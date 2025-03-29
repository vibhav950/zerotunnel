/**
 * @file mem.c
 * Wrapper for LIBC memory functions.
 */

#include "defines.h"

#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// As of the development phase, this has not yet been tested is strictly
// experimental. Define this macro at your own risk.
#undef __ZTLIB_ENVIRON_SECURE_LARGE_ALLOC
#undef __LARGE_ALLOC_SIZE
#undef __LARGE_ALLOC_ALIGN_SIZE

void *zt_mem_malloc(size_t size) {
  void *ptr;

  ASSERT(size > 0);

#ifdef __ZTLIB_ENVIRON_SECURE_LARGE_ALLOC
  if (size >= __LARGE_ALLOC_SIZE) {
    size = (size & ~(__LARGE_ALLOC_ALIGN_SIZE - 1)) + __LARGE_ALLOC_ALIGN_SIZE;
    if (!(ptr = aligned_alloc(__LARGE_ALLOC_ALIGN_SIZE, size))) {
      PRINTDEBUG("aligned_alloc(%zu, %zu) failed\n", __LARGE_ALLOC_SIZE, size);
      return NULL;
    }
    if (mlock(ptr, malloc_usable_size(ptr))) {
      PRINTDEBUG("mlock(%zu) failed\n", size);
      return NULL;
    }
#else
  if (0) {
#endif
  } else {
    if (!(ptr = malloc(size)))
      PRINTDEBUG("malloc(%zu) failed %s\n", size, strerror(errno));
  }
  return ptr;
}

void *zt_mem_calloc(size_t nmemb, size_t size) {
  void *ptr;

  ASSERT(nmemb > 0);
  ASSERT(size > 0);

#ifdef __ZTLIB_ENVIRON_SECURE_LARGE_ALLOC
  if (size * nmemb >= __LARGE_ALLOC_SIZE) {
    ptr = zt_malloc(size * nmemb);
    if (ptr)
      memzero(ptr, malloc_usable_size(ptr));
#else
  if (0) {
#endif
  } else {
    if (!(ptr = calloc(nmemb, size)))
      PRINTDEBUG("calloc(%zu, %zu) failed %s\n", nmemb, size, strerror(errno));
  }
  return ptr;
}

void zt_mem_free(void *ptr) {
  if (!ptr)
    return;

  ASSERT(malloc_usable_size(ptr) > 0);

#ifdef __ZTLIB_ENVIRON_SECURE_LARGE_ALLOC
  size_t size = malloc_usable_size(ptr);
  if (malloc_usable_size(ptr) >= __LARGE_ALLOC_SIZE) {
    if (munlock(ptr, size)) {
      /**
       * NOTE: This failure will only occur if pages corresponding to ptr[.size]
       * have not been successfully locked with mlock(). Forcing an exit here
       * means we are exiting without first sweeping process memory with secrets
       * in it. Even more the reason to only call zt_free() with valid arguments!
       */
      PRINTDEBUG("munlock(%zu) failed (%s)\n", size, strerror(errno));
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
#ifdef __ZTLIB_ENVIRON_SECURE_LARGE_ALLOC
  zt_free(ptr);
  ptr = zt_malloc(size);
#else
  ptr = realloc(ptr, size);
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
 * Note: To avoid leaking the length of a secret string, use x
 * as the private string and str as the provided string.
 *
 * Thanks to John's blog:
 * https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
 */
unsigned int zt_strcmp(const char *str, const char *x) {
  unsigned int res = 0;
  volatile size_t i, j, k;

  if (!str || !x)
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
  if (!m || !n)
    return NULL;

  void *p = zt_malloc(n);
  if (!p)
    return NULL;
  return (void *)zt_memcpy(p, (void *)m, n);
}

char *zt_strdup(const char *s) { return s ? zt_memdup(s, strlen(s) + 1) : NULL; }

char *zt_strmemdup(const void *m, size_t n) {
  if (!m || !n)
    return NULL;

  void *p1 = zt_malloc(n + 1);
  if (!p1)
    return NULL;
  char *p2 = (char *)zt_memcpy(p1, (void *)m, n);
  p2[n] = 0;
  return p2;
}
