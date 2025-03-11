#include "systemrand.h"
#include "common/defines.h"
#include "common/x86_cpuid.h"
#include "rdrand.h"

#include <assert.h>

#if defined(_WIN32)
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#include <bcrypt.h>
#include <ntstatus.h>
#include <windows.h>
#elif defined(__linux__)
/* Linux */
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#define HAVE_DEV_URANDOM 1
#elif defined(__OpenBSD__) && defined(__FreeBSD__)
/* OpenBSD, FreeBSD */
#include <stdlib.h>
#define HAVE_ARC4RANDOM 1
#elif defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1
/* OSX */
#include <fnctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#define HAVE_DEV_URANDOM 1
#endif
#endif

#if defined(_WIN32)
static int _win32_sys_rand(uint8_t *buf, size_t bytes) {
  NTSTATUS status;

  status = BCryptGenRandom(NULL, (BYTE *)buf, (DWORD)bytes,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  return NT_SUCCESS(status) ? 0 : -1;
}
#endif // _WIN32

/**
 * Get \p bytes random bytes into \p buf using the platform-dependent
 * random number generator which is chosen at compile-time.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_systemrand_bytes(uint8_t *buf, size_t bytes) {
  int rv = 0;
#ifndef _WIN32
  int fd;
#endif

  if (!buf || !bytes)
    return -1;

#ifdef _WIN32
  rv = _win32_sys_rand(buf, bytes);
#elif defined(HAVE_DEV_URANDOM)
  if ((fd = open("/dev/random", O_RDONLY)) < 0)
    return -1;

  if (read(fd, buf, bytes) != (ssize_t)bytes)
    rv = -1;

  close(fd);
#elif defined(HAVE_ARC4RANDOM)
  arc4random_buf(buf, bytes);
#endif
  return rv;
}

/**
 * For a request where the size is a multiple of 4 bytes, it is advised to use
 * this function over zt_systemrand_bytes() if the underlying architecture is
 * x86. This function uses a runtime check performed by DetectX86CPUFeatures()
 * at program startup as a prerequisite to determine if the RDRAND instruction
 * is available; if this check fails, we naturally fall back to
 * zt_systemrand_bytes().
 *
 * Note: DetectX86CPUFeatures() must be called before.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_systemrand_4bytes(uint32_t *buf, size_t bytes4) {
  if (!buf || !bytes4)
    return -1;

  if (HasRDRAND()) {
    for (size_t i = 0; i < bytes4; i++)
      if (!rdrand32_step(&buf[i]))
        goto fallback;
    return 0;
  }
fallback:
  return zt_systemrand_bytes((uint8_t *)buf, bytes4 * 4);
}

/**
 * For a request where the size is a multiple of 8 bytes, it is advised
 * to use this function over zt_systemrand_bytes() on an x86 machine.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_systemrand_8bytes(uint64_t *buf, size_t bytes8) {
  if (!buf || !bytes8)
    return -1;

  if (HasRDRAND()) {
    for (size_t i = 0; i < bytes8; i++)
      if (!rdrand64_step(&buf[i]))
        goto fallback;
    return 0;
  }
fallback:
  return zt_systemrand_bytes((uint8_t *)buf, bytes8 * 8);
}

inline uint8_t zt_rand_u8(void) {
  uint8_t rand;
#if defined(HAVE_ARC4RANDOM)
  rand = arc4random_uniform(UINT8_MAX + 1);
#else
  if (zt_systemrand_bytes(&rand, 1) != 0) {
    PRINTERROR("System RNG failure");
    __FKILL();
  }
#endif
  return rand;
}

inline uint16_t zt_rand_u16(void) {
  uint16_t rand;
#if defined(HAVE_ARC4RANDOM)
  rand = arc4random_uniform(UINT16_MAX + 1);
#else
  if (zt_systemrand_bytes((uint8_t *)&rand, 2) != 0) {
    PRINTERROR("System RNG failure");
    __FKILL();
  }
#endif
  return rand;
}

inline uint32_t zt_rand_u32(void) {
  uint32_t rand;
#if defined(HAVE_ARC4RANDOM)
  rand = arc4random();
#else
  if (zt_systemrand_4bytes(&rand, 1) != 0) {
    PRINTERROR("System RNG failure");
    __FKILL();
  }
#endif
  return rand;
}

inline uint64_t zt_rand_u64(void) {
  uint64_t rand;
  if (zt_systemrand_8bytes(&rand, 1) != 0) {
    PRINTERROR("System RNG failure");
    __FKILL();
  }
  return rand;
}

#if defined(_MSC_VER)
#include <intrin.h> // _BitScanReverse64
#endif

/* number of bits in x */
static inline int nbits(uint64_t x) {
  assert(x > 0);
#if defined(_MSC_VER)
  int lz;
  _BitScanReverse64(&lz, x);
  return lz + 1;
#elif defined(__has_builtin) && __has_builtin(__builtin_clzll)
  return 64U - __builtin_clzll(x);
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

  assert(max > 0);

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

  if (!charset && (charset_len > 1))
    return -1;

  if (rstr_len < 2)
    return -1;

  if (!charset || (charset_len == 1)) {
    p = RAND_DEFAULT_CHARSET;
    charset_len = sizeof(RAND_DEFAULT_CHARSET) - 2;
  } else {
    p = charset;
    charset_len -= 1;
  }

  for (size_t i = 0; i < rstr_len - 1; i++) {
    rstr[i] = p[zt_rand_ranged(charset_len)];
  }
  rstr[rstr_len - 1] = 0;

  return 0;
}
