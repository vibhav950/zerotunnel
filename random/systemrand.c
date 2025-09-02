#include "systemrand.h"
#include "common/defines.h"
#include "common/x86_cpuid.h"
#include "rdrand.h"

// clang-format off
#if defined(HAVE_GETENTROPY)
#include <sys/random.h>
#endif
#if defined(HAVE_GETRANDOM)
#if __GLIBC_PREREQ(2, 25)
/* getentropy was added in glibc 2.25
 * See https://sourceware.org/legacy-ml/libc-alpha/2017-02/msg00079.html */
#include <sys/random.h>
#else /* older glibc */
#undef HAVE_GETRANDOM
#include <linux/random.h>
#include <sys/syscall.h>
#endif
#endif

#if defined(_WIN32)
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#elif defined(__linux__)
/* Linux */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#define HAVE_DEV_URANDOM
#define URANDOM_DEVICE "/dev/urandom"
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/* FreeBSD, NetBSD, OpenBSD */
#include <stdlib.h>
#define HAVE_ARC4RANDOM
#elif defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1
/* macOS */
#include <stdlib.h>
#define HAVE_ARC4RANDOM
#endif
#else
#error "unknown platform"
#endif
// clang-format on

#define U64_FROM_2_U32(hi, lo) (((uint64_t)(hi) << 32) + (lo))

#if defined(_WIN32)
static inline int _win32_sys_rand(uint8_t *buf, size_t bytes) {
  return (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)bytes,
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS);
}
#endif /* _WIN32 */

#if defined(HAVE_DEV_URANDOM)
static inline int _dev_urandom_rand(uint8_t *buf, size_t bytes) {
  int fd = -1, rc = 0;
#if defined(O_CLOEXEC)
  fd = open(URANDOM_DEVICE, O_RDONLY | O_CLOEXEC);
#else
  fd = open(URANDOM_DEVICE, O_RDONLY);
#if defined(FD_CLOEXEC)
  if (unlikely(fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)) {
    close(fd);
    fd = -1;
  }
#endif
#endif
  if (likely(fd > 0)) {
    rc = read(fd, buf, bytes);
    close(fd);
  }
  return rc == bytes;
}
#endif /* HAVE_DEV_URANDOM */

#if defined(HAVE_GETENTROPY)
static inline int _getentropy_rand(uint8_t *buf, size_t bytes) {
  while (bytes > 256) {
    if (likely(getentropy(buf, 256) != -1)) {
      buf += 256;
      bytes -= 256;
    } else
      return 0;
  }
  return getentropy(buf, bytes) != -1;
}
#endif /* HAVE_GETENTROPY */

#if defined(HAVE_GETRANDOM) || defined(SYS_getrandom)
/* Ref: lighttpd1.4/src/rand.c */
static inline int _getrandom_rand(uint8_t *buf, size_t bytes) {
  int num;

#if defined(HAVE_GETRANDOM)
  num = getrandom(buf, bytes, 0);
#else
  /* https://lwn.net/Articles/605828/ */
  /* https://bbs.archlinux.org/viewtopic.php?id=200039 */
  num = (int)syscall(SYS_getrandom, buf, bytes, 0);
#endif
  return num == (int)bytes;
}
#endif /* HAVE_GETRANDOM || SYS_getrandom */

/**
 * Get \p bytes random bytes into \p buf using the platform-dependent
 * random number generator which is chosen at compile-time.
 */
void zt_systemrand_bytes(uint8_t *buf, size_t bytes) {
  int rv = 1;

  if (unlikely(!bytes))
    return;

#if defined(_WIN32)
  rv = _win32_sys_rand(buf, bytes);
#elif defined(HAVE_ARC4RANDOM)
  arc4random_buf(buf, bytes);
#else
  /* On Linux, try to use the getrandom(2) system call and fallback to
   * directly reading from the urandom device if the former is missing */
  int errno_save;
  errno_save = errno;
  errno = 0;
#if defined(HAVE_GETENTROPY)
  if (!(rv = _getentropy_rand(buf, bytes)) && errno == ENOSYS)
#elif defined(HAVE_GETRANDOM) || defined(SYS_getrandom)
  if (!(rv = _getrandom_rand(buf, bytes)) && errno == ENOSYS)
#else
  if (1) /* read from the urandom device as the last resort */
#endif
    rv = _dev_urandom_rand(buf, bytes);
  errno = errno_save;
#endif

  if (!rv)
    log_fatal("Failed to fetch random bytes"); /* error and exit */
}

/**
 * For a request where the size is a multiple of 4 bytes, it is advised to use
 * this function over `zt_systemrand_bytes()` if the underlying architecture is
 * x86. This function uses a runtime check performed by `DetectX86CPUFeatures()`
 * at program startup as a prerequisite to determine if the RDRAND instruction
 * is available; if this check fails, we naturally fall back to
 * `zt_systemrand_bytes()`.
 */
void zt_systemrand_4bytes(uint32_t *buf, size_t bytes4) {
  if (unlikely(!bytes4))
    return;

  if (HasRDRAND()) {
    for (size_t i = 0; i < bytes4; i++)
      if (!rdrand32_step(&buf[i]))
        goto fallback;
    return;
  }
fallback:
  zt_systemrand_bytes(PTR8(buf), bytes4 * 4);
}

/**
 * For a request where the size is a multiple of 8 bytes, it is advised
 * to use this function over `zt_systemrand_bytes()` on an x86 machine.
 */
void zt_systemrand_8bytes(uint64_t *buf, size_t bytes8) {
  if (unlikely(!bytes8))
    return;

  if (HasRDRAND()) {
    for (size_t i = 0; i < bytes8; i++)
      if (!rdrand64_step(&buf[i]))
        goto fallback;
    return;
  }
fallback:
  zt_systemrand_bytes(PTR8(buf), bytes8 * 8);
}

inline uint8_t zt_rand_u8(void) {
  uint8_t rand;

  zt_systemrand_bytes(&rand, 1);
  return rand;
}

inline uint16_t zt_rand_u16(void) {
  uint16_t rand;

  zt_systemrand_bytes(PTR8(&rand), 2);
  return rand;
}

inline uint32_t zt_rand_u32(void) {
  uint32_t rand;

#if defined(HAVE_ARC4RANDOM)
  rand = arc4random();
#else
  zt_systemrand_4bytes(&rand, 1);
#endif
  return rand;
}

inline uint64_t zt_rand_u64(void) {
  uint64_t rand;

#if defined(HAVE_ARC4RANDOM)
  uint32_t hi, lo;
  hi = arc4random();
  lo = arc4random();
  rand = U64_FROM_2_U32(hi, lo);
#else
  zt_systemrand_8bytes(&rand, 1);
#endif
  return rand;
}

#if defined(_MSC_VER)
#include <intrin.h> // _BitScanReverse64
#pragma intrinsic(_BitScanReverse64)
#else
#include <limits.h> // UINT64_MAX, LONG_MAX, LONGLONG_MAX
#endif

/** Number of bits in x */
static inline int nbits(uint64_t x) {
  ASSERT(x > 0);
#if defined(_MSC_VER)
  int lz;
  _BitScanReverse64(&lz, x);
  return lz + 1;
#elif ULONG_MAX == UINT64_MAX && defined(__has_builtin) && __has_builtin(__builtin_clzl)
  return 64 - __builtin_clzl(x);
#elif ULONGLONG_MAX == UINT64_MAX && defined(__has_builtin) &&                           \
    __has_builtin(__builtin_clzll)
  return 64 - __builtin_clzll(x);
#else
  int n = 0;
  for (; x; x >>= 1, n++)
    ;
  return n;
#endif
}

inline int64_t zt_rand_ranged(int64_t max) {
  uint64_t r;
  int nbitsv;

  if (unlikely(max <= 0))
    return -1;

  nbitsv = nbits(max);
  do {
    r = zt_rand_u64();
    r &= (1 << nbitsv) - 1;
  } while (r > max);
  return r;
}

int zt_rand_charset(char *rstr, size_t rstr_len, const char *charset,
                    size_t charset_len) {
  const char *p;

  if (unlikely(!rstr || rstr_len < 2))
    return -1;

  if (!charset_len) {
    p = RAND_DEFAULT_CHARSET;
    charset_len = sizeof(RAND_DEFAULT_CHARSET) - 2;
  } else {
    p = charset;
    charset_len -= 1;
  }

  for (size_t i = 0; i < rstr_len - 1; i++)
    rstr[i] = p[zt_rand_ranged(charset_len)];
  rstr[rstr_len - 1] = 0;

  return 0;
}
