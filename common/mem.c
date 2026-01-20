/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * mem.c - Memory interface
 */

#include "defines.h"
#include "log.h"

#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

/* Forward declarations */
static void *zt_mem_malloc(size_t);
static void *zt_mem_calloc(size_t, size_t);
static void *zt_mem_aligned_alloc(size_t, size_t);
static void zt_mem_free(void *);
static void *zt_mem_realloc(void *, size_t);

static malloc_func_t *zt_malloc_func = zt_mem_malloc;
static calloc_func_t *zt_calloc_func = zt_mem_calloc;
static realloc_func_t *zt_realloc_func = zt_mem_realloc;
static aligned_alloc_func_t *zt_aligned_alloc_func = zt_mem_aligned_alloc;
static free_func_t *zt_free_func = zt_mem_free;

static inline ATTRIBUTE_ALWAYS_INLINE void out_of_memory(void) {
  log_error(NULL, "could not allocate enough memory: %s", strerror(errno));
#ifdef DEBUG
  __FKILL(); // can dump core here
#endif
}

/**************************************************************
 *                  Standard memory functions                 *
 **************************************************************/

static void *zt_mem_malloc(size_t n) {
  void *p;

  ASSERT(n > 0);

  if (unlikely(!(p = malloc(n))))
    out_of_memory();
  return p;
}

static void *zt_mem_calloc(size_t n, size_t m) {
  size_t bytes;
  void *p;

  ASSERT(n > 0);
  ASSERT(m > 0);

  bytes = n * m;
  if (m && bytes / m != n)
    return NULL;

  if (unlikely(!(p = calloc(1, bytes))))
    out_of_memory();
  return p;
}

/** `size` rounded-up to `align` */
#define _ALIGNED_SIZE(size, align) ((((size) - 1) | ((align) - 1)) + 1)

static void *zt_mem_aligned_alloc(size_t align, size_t size) {
  void *p;
  size_t asz = _ALIGNED_SIZE(size, align);

  ASSERT(align >= sizeof(void *));
  ASSERT((align & (align - 1)) == 0); // power of two
  ASSERT(asz >= size);

  if (posix_memalign(&p, align, asz) != 0) {
    out_of_memory();
    return NULL;
  }
  return p;
}

static void zt_mem_free(void *p) {
  if (likely(p))
    free(p);
}

static void *zt_mem_realloc(void *p, size_t n) {
  ASSERT(n > 0);

  if (unlikely(!(p = realloc(p, n))))
    out_of_memory();
  return p;
}

void zt_mem_set_functions(malloc_func_t *malloc_fn, calloc_func_t *calloc_fn,
                          realloc_func_t *realloc_fn, free_func_t *free_fn) {
  zt_malloc_func = malloc_fn ? malloc_fn : zt_mem_malloc;
  zt_calloc_func = calloc_fn ? calloc_fn : zt_mem_calloc;
  zt_realloc_func = realloc_fn ? realloc_fn : zt_mem_realloc;
  zt_free_func = free_fn ? free_fn : zt_mem_free;
}

void *zt_malloc(size_t n) { return zt_malloc_func(n); }

void *zt_calloc(size_t n, size_t m) { return zt_calloc_func(n, m); }

void zt_free(void *p) { zt_free_func(p); }

void *zt_realloc(void *p, size_t n) { return zt_realloc_func(p, n); }

void *zt_aligned_alloc(size_t align, size_t size) {
  return zt_aligned_alloc_func(align, size);
}

void zt_clr_free(void *p, size_t n) {
  memzero(p, n);
  zt_free(p);
}

/**************************************************************
 *                   Secure heap allocation                   *
 **************************************************************/

#define SECURE_MEMORY_MIN_SIZE 16384

/**
 * Initialize a secure memory pool at least of size @p n bytes. This memory
 * region is protected from being swapped out to disk and zeroed out after use.
 * Since this memory is scarce, it should only be used to store protected data
 * like encryption keys and passwords.
 *
 * On Linux, this function uses Libgcrypt's secure memory functions.
 *
 * FIXME: what should we do when Libgcrypt is not available or fails to provide
 * secure memory? Fallback to some sort of malloc + mlock approach? Also it may
 * be helpful to explore other API's like OpenSSL's secure_malloc().
 */
err_t zt_secure_mem_init(size_t n) {
#ifdef HAVE_LIBGCRYPT
  gcry_error_t e;

  if (!gcry_check_version(GCRYPT_VERSION))
    goto err;

  /* libgcrypt can't do smaller than this size */
  n = n < SECURE_MEMORY_MIN_SIZE ? SECURE_MEMORY_MIN_SIZE : n;

  if ((e = gcry_control(GCRYCTL_INIT_SECMEM, n, 0)))
    goto err;

  if ((e = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0)))
    goto err;

  return ERR_SUCCESS;

err:
  log_error(NULL, "could not init secure memory: %s", gcry_strerror(e));
  return ERR_INTERNAL;
#endif /* HAVE_LIBGCRYPT */

  /* Let the caller handle this */
  log_error(NULL, "no secure memory provider");
  return ERR_NOT_SUPPORTED;
}

void *zt_secure_mem_alloc(size_t n) {
#ifdef HAVE_LIBGCRYPT
  void *p;

  if (unlikely(!(p = gcry_xcalloc_secure(1, n))))
    out_of_memory();
  return p;
#endif /* HAVE_LIBGCRYPT */
  log_fatal("no secure memory provider");
  return NULL; /* make the compiler happy, the log_fatal will exit out */
}

void zt_secure_mem_free(void *p) {
#ifdef HAVE_LIBGCRYPT
  if (likely(p))
    gcry_free(p);
#endif /* HAVE_LIBGCRYPT */
  log_fatal("no secure memory provider");
}

/**
 * Cleanup the secure memory.
 * May be called from atexit() hooks and/or signal handlers.
 */
void zt_secure_mem_cleanup(void) {
#ifdef HAVE_LIBGCRYPT
  gcry_control(GCRYCTL_TERM_SECMEM, 0, 0);
#endif /* HAVE_LIBGCRYPT */
}

/**************************************************************
 *              Miscellaneous string functions                *
 **************************************************************/

typedef void *(*memset_t)(void *, int, size_t);

/* Make this pointer to memset volatile so that the compiler must always
 * dereference it and can't optimize away the call to memset, in case it is
 * being used to wipe secrets */
static volatile memset_t memset_func = memset;

void zt_memset(void *mem, int ch, size_t len) { memset_func(mem, ch, len); }

/* Returns zero if a[0:len-1] == b[0:len-1], otherwise non-zero. */
int zt_memcmp(const void *a, const void *b, size_t len) {
  unsigned char res = 0;
  const volatile unsigned char *ca = (const volatile unsigned char *)a;
  const volatile unsigned char *cb = (const volatile unsigned char *)b;

  for (; len; --len, res |= ca[len] ^ cb[len])
    ;
  return res;
}

/**
 * Returns zero if the strings are equal, otherwise non-zero.
 *
 * This function behaves slightly differently than strcmp() in that it only
 * checks the strings for equality and doesn't compare them lexicographically.
 *
 * Note: To avoid leaking the length of a secret string, use x
 * as the private string and str as the provided string.
 *
 * Thanks to John's blog:
 * https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
 */
int zt_strcmp(const char *str, const char *x) {
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
  return memcpy(p, m, n);
}

char *zt_strdup(const char *s) { return s ? zt_memdup(s, strlen(s) + 1) : NULL; }

char *zt_strndup(const char *s, size_t n) {
  if (unlikely(!s))
    return NULL;

  size_t slen = strnlen(s, n);
  char *p = zt_malloc(slen + 1);
  if (unlikely(!p))
    return NULL;
  memcpy(p, (const void *)s, slen);
  p[slen] = '\0';
  return p;
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
  char *p2 = (char *)memcpy(p1, m, n);
  p2[n] = 0;
  return p2;
}
