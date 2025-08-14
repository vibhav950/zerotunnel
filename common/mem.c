/**
 * @file mem.c
 * Wrapper for LIBC memory functions.
 */

#include "common/log.h"
#include "defines.h"

#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __ZTLIB_ENVIRON_MLOCK_LARGE_ALLOC
#define __LARGE_ALLOC_SIZE (1UL << 14)                  /* ~4 pages */
#define __LARGE_ALLOC_ALIGN_SIZE sysconf(_SC_PAGE_SIZE) /* 4 KiB */
#endif

void *zt_mem_malloc(size_t size) {
  void *ptr;

  ASSERT(size > 0);

#ifdef __ZTLIB_ENVIRON_MLOCK_LARGE_ALLOC
  if (size >= __LARGE_ALLOC_SIZE) {
    size = (size & ~(__LARGE_ALLOC_ALIGN_SIZE - 1)) + __LARGE_ALLOC_ALIGN_SIZE;
    if (!(ptr = aligned_alloc(__LARGE_ALLOC_ALIGN_SIZE, size))) {
      log_error(NULL, "aligned_alloc() failed (%s)", strerror(errno));
      return NULL;
    }
    if (mlock(ptr, malloc_usable_size(ptr))) {
      log_error(NULL, "mlock() failed (%s)", strerror(errno));
      return NULL;
    }
#else
  if (0) {
#endif
  } else {
    if (unlikely(!(ptr = malloc(size))))
      log_error(NULL, "malloc(%zu) failed (%s)", size, strerror(errno));
  }
  return ptr;
}

void *zt_mem_calloc(size_t nmemb, size_t size) {
  void *ptr;

  ASSERT(nmemb > 0);
  ASSERT(size > 0);

#ifdef __ZTLIB_ENVIRON_MLOCK_LARGE_ALLOC
  /* check for an overflow */
  if (size * nmemb < size && size && nmemb) {
    log_error(NULL, "not enough memory");
    return NULL;
  }
  if (size * nmemb >= __LARGE_ALLOC_SIZE) {
    ptr = zt_malloc(size * nmemb);
    if (ptr)
      memzero(ptr, malloc_usable_size(ptr));
#else
  if (0) {
#endif
  } else if (unlikely(!(ptr = calloc(nmemb, size)))) {
    log_error(NULL, "calloc(%zu, %zu) failed (%s)", nmemb, size,
              strerror(errno));
  }
  return ptr;
}

void zt_mem_free(void *ptr) {
  if (unlikely(!ptr))
    return;

  ASSERT(malloc_usable_size(ptr) > 0);

#ifdef __ZTLIB_ENVIRON_MLOCK_LARGE_ALLOC
  size_t size = malloc_usable_size(ptr);
  if (malloc_usable_size(ptr) >= __LARGE_ALLOC_SIZE) {
    if (munlock(ptr, size)) {
      /**
       * NOTE: This failure will only occur if pages corresponding to ptr[.size]
       * have not been successfully locked with mlock(). Forcing an exit here
       * means we are exiting without first sweeping process memory with secrets
       * in it. Even more the reason to only call zt_free() with valid
       * arguments!
       * Forcing an exit here is like blowing up the entire car with a Bazooka
       * because someone put water in the fuel tank, but I don't know what the
       * fuck else to do :-)
       */
      log_error(NULL, "munlock(ptr, %zu) failed (%s)", size, strerror(errno));
      memzero(ptr, size);
      __FKILL();
    }
  }
#endif
  free(ptr);
}

void *zt_mem_realloc(void *ptr, size_t size) {
  ASSERT(size > 0);

  memzero(ptr, size);
#ifdef __ZTLIB_ENVIRON_MLOCK_LARGE_ALLOC
  zt_free(ptr);
  ptr = zt_malloc(size);
#else
  if (unlikely(!(ptr = realloc(ptr, size)))) {
    log_error(NULL, "realloc(ptr, %zu) failed (%s)", size, strerror(errno));
#endif
  return ptr;
}

void *zt_mem_memset(void *mem, int ch, size_t len) {
#if defined(__ZTLIB_ENVIRON_SAFE_MEM) && (__ZTLIB_ENVIRON_SAFE_MEM)
  volatile char *p;

  for (p = (volatile char *)mem; len; p[--len] = ch)
    ;
  return mem;
#else
    return memset(mem, ch, len);
#endif
}

void *zt_mem_memzero(void *mem, size_t len) {
#if defined(__ZTLIB_ENVIRON_SAFE_MEM) && (__ZTLIB_ENVIRON_SAFE_MEM)
  volatile char *p;

  for (p = (volatile char *)mem; len; p[--len] = 0x00)
    ;
  return mem;
#else
    return memset(mem, 0x00, len);
#endif
}

void *zt_mem_memcpy(void *dst, void *src, size_t len) {
#if defined(__ZTLIB_ENVIRON_SAFE_MEM) && (__ZTLIB_ENVIRON_SAFE_MEM)
  volatile char *cdst, *csrc;

  cdst = (volatile char *)dst;
  csrc = (volatile char *)src;
  while (len--)
    cdst[len] = csrc[len];
  return dst;
#else
    return memcpy(dst, src, len);
#endif
}

void *zt_mem_memmove(void *dst, void *src, size_t len) {
#if defined(__ZTLIB_ENVIRON_SAFE_MEM) && (__ZTLIB_ENVIRON_SAFE_MEM)
  size_t i;
  volatile char *cdst, *csrc;

  cdst = (volatile char *)dst;
  csrc = (volatile char *)src;
  if (csrc > cdst && csrc < cdst + len)
    for (i = 0; i < len; i++)
      cdst[i] = csrc[i];
  else
    while (len--)
      cdst[len] = csrc[len];
  return dst;
#else
    return memmove(dst, src, len);
#endif
}

/* Returns zero if a[0:len-1] == b[0:len-1], otherwise non-zero. */
unsigned int zt_mem_memcmp(const void *a, const void *b, size_t len) {
#if defined(__ZTLIB_ENVIRON_SAFE_MEM) && (__ZTLIB_ENVIRON_SAFE_MEM)
  unsigned int res = 0;
  const char *pa, *pb;

  pa = (const char *)a;
  pb = (const char *)b;
  for (; len; --len, res |= pa[len] ^ pb[len])
    ;
  return res;
#else
    return memcmp(a, b, len);
#endif
}

/**
 * Returns zero if the strings are equal, otherwise non-zero.
 *
 * This function behaves slightly differently than strcmp() in that it only
 * checks the strings for equality and doesn't compare them lexicographically.
 *
 * We are better off always using a constant time string compare function since
 * this can be useful for non-cryptographic modules too and this way we aren't
 * forced to use the 'safe' versions of the other memory functions.
 *
 * Note: To avoid leaking the length of a secret string, use x
 * as the private string and str as the provided string.
 *
 * Thanks to John's blog:
 * https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
 */
unsigned int zt_strcmp(const char *str, const char *x) {
  unsigned int res = 0;
  volatile size_t i, j, k;

  if (unlikely(!str || !x))
    return 1;

  i = j = k = 0;
  for (;;) {
    res |= str[i] ^ x[j];
    if (str[i] == '\0')
      break;
    i++;
    if (x[j] != '\0')
      j++;
    if (x[j] == '\0')
      k++;
  }
  return res;
}

void *zt_memdup(const void *m, size_t n) {
  if (unlikely(!m || !n))
    return NULL;

  void *p = zt_malloc(n);
  if (unlikely(!p))
    return NULL;
  return (void *)zt_memcpy(p, (void *)m, n);
}

char *zt_strdup(const char *s) {
  return s ? zt_memdup(s, strlen(s) + 1) : NULL;
}

char *zt_vstrdup(const char *fmt, ...) {
  va_list args;
  char *buf;
  size_t len;

  if (unlikely(!fmt))
    return NULL;

  va_start(args, fmt);
  len = vsnprintf(NULL, 0, fmt, args);
  va_end(args);

  if (unlikely(len < 0))
    return NULL;

  buf = zt_malloc(len + 1);
  if (unlikely(!buf))
    return NULL;

  va_start(args, fmt);
  vsnprintf(buf, len + 1, fmt, args);
  va_end(args);
  return buf;
}

char *zt_strmemdup(const void *m, size_t n) {
  if (unlikely(!m || !n))
    return NULL;

  void *p1 = zt_malloc(n + 1);
  if (unlikely(!p1))
    return NULL;
  char *p2 = (char *)zt_memcpy(p1, (void *)m, n);
  p2[n] = 0;
  return p2;
}
