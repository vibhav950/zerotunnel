/**
 * @file mem.c
 * Wrapper for LIBC memory functions.
 */

#include "defs.h"
#include "memzero.h"

#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// As of the development phase, this has not yet been tested is strictly
// experimental. Define this macro at your own risk.
#undef __SECURE_LARGE_ALLOC
#undef __LARGE_ALLOC_SIZE
#undef __LARGE_ALLOC_ALIGN_SIZE

void *xmalloc(size_t size) {
  void *ptr;

  assert(size > 0);

#ifdef __SECURE_LARGE_ALLOC
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

void *xcalloc(size_t nmemb, size_t size) {
  void *ptr;

  assert(nmemb > 0);
  assert(size > 0);

#ifdef __SECURE_LARGE_ALLOC
  if (size * nmemb >= __LARGE_ALLOC_SIZE) {
    ptr = xmalloc(size * nmemb);
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

void xfree(void *ptr) {
  size_t size;

  if (!ptr)
    return;

  assert(malloc_usable_size(ptr) > 0);

#ifdef __SECURE_LARGE_ALLOC
  size = malloc_usable_size(ptr);
  if (malloc_usable_size(ptr) >= __LARGE_ALLOC_SIZE) {
    if (munlock(ptr, size)) {
      /**
       * NOTE: This failure will only occur if pages corresponding to ptr[.size]
       * have not been successfully locked with mlock(). Forcing an exit here
       * means we are exiting without first sweeping process memory with secrets
       * in it. Even more the reason to only call xfree() with valid arguments!
       */
      PRINTDEBUG("munlock(%zu) failed (%s)\n", size, strerror(errno));
      memzero(ptr, size);
      __FKILL();
    }
  }
#endif
  free(ptr);
}

void *xrealloc(void *ptr, size_t size) {
  void *new_ptr;

  assert(size > 0);

  memzero(ptr, size);
#ifdef __SECURE_LARGE_ALLOC
  xfree(ptr);
  ptr = xmalloc(size);
#else
  ptr = realloc(ptr, size);
#endif
  return ptr;
}

volatile void *xmemset(volatile void *mem, int ch, size_t len) {
  volatile char *p;

  for (p = (volatile char *)mem; len; p[--len] = ch)
    ;
  return mem;
}

volatile void *xmemzero(volatile void *mem, size_t len) {
  volatile char *p;

  for (p = (volatile char *)mem; len; p[--len] = 0x00)
    ;
  return mem;
}

volatile void *xmemcpy(volatile void *dst, volatile void *src, size_t len) {
  volatile char *cdst, *csrc;

  cdst = (volatile char *)dst;
  csrc = (volatile char *)src;
  while (len--)
    cdst[len] = csrc[len];
  return dst;
}

volatile void *xmemmove(volatile void *dst, volatile void *src, size_t len) {
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
}

/* Returns zero if a[0:len-1] == b[0:len-1], otherwise non-zero. */
unsigned int xmemcmp(const void *a, const void *b, size_t len) {
  unsigned int res = 0;
  const char *pa, *pb;

  pa = (const char *)a;
  pb = (const char *)b;
  for (; len; res |= pa[len] ^ pb[len], len--)
    ;
  return res;
}

/* Returns zero if the strings are equal, otherwise non-zero.

  Note: To avoid leaking the length of a secret string, use x
  as the private string and str as the provided string.

  Thanks to John's blog:
  https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
*/
unsigned int xstrcmp(const char *str, const char *x) {
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

void *xmemdup(const void *m, size_t n) {
  if (!m || !n)
    return NULL;

  void *p = xmalloc(n);
  if (!p)
    return NULL;
  return (void *)xmemcpy(p, m, n);
}

void *xstrdup(const char *s) { return s ? xmemdup(s, strlen(s) + 1) : NULL; }

char *xstrmemdup(const void *m, size_t n) {
  if (!m || !n)
    return NULL;

  void *p1 = xmalloc(n + 1);
  if (!p1)
    return NULL;
  char *p2 = (char *)xmemcpy(p1, m, n);
  p2[n] = 0;
  return p2;
}
