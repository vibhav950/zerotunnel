/**
 * @file defines.h
 * @brief Common macros and definitions.
 */

#ifndef __DEFINES_H__
#define __DEFINES_H__

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define GCC_VERSION_AT_LEAST(major, minor)                                               \
  ((__GNUC__ > (major)) || ((__GNUC__ == (major)) && (__GNUC_MINOR__ >= (minor))))
#else
#define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if defined(__GNUC__) && !defined(__clang__)

#if GCC_VERSION_AT_LEAST(3, 1)
#define ATTRIBUTE_ALWAYS_INLINE __attribute__((always_inline))
#else
#define ATTRIBUTE_ALWAYS_INLINE
#endif

#if GCC_VERSION_AT_LEAST(2, 5)
#define ATTRIBUTE_NORETURN __attribute__((noreturn))
#else
#define ATTRIBUTE_NORETURN
#endif

#if GCC_VERSION_AT_LEAST(2, 7)
#define ATTRIBUTE_UNUSED __attribute__((unused))
#else
#define ATTRIBUTE_UNUSED
#endif

#if GCC_VERSION_AT_LEAST(7, 1)
#define ATTRIBUTE_FALLTHROUGH __attribute__((fallthrough))
#else
#define ATTRIBUTE_FALLTHROUGH
#endif

#if GCC_VERSION_AT_LEAST(3, 0)
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#define likely(expr) __builtin_expect(!!(expr), 1)
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#if GCC_VERSION_AT_LEAST(2, 7)
#define ALIGN(n) __attribute__((aligned(n)))
#else
#define ALIGN(n)
#endif

#if GCC_VERSION_AT_LEAST(3, 3)
#define ATTRIBUTE_NOTHROW __attribute__((nothrow))
#else
#define ATTRIBUTE_NOTHROW
#endif

#if GCC_VERSION_AT_LEAST(2, 5)
#define ATTRIBUTE_FORMAT_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
#define ATTRIBUTE_FORMAT_PRINTF(fmt, args)
#endif

#if GCC_VERSION_AT_LEAST(3, 3)
#define ATTRIBUTE_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define ATTRIBUTE_NONNULL(...)
#endif

#if GCC_VERSION_AT_LEAST(2, 96)
#define ATTRIBUTE_PURE __attribute__((pure))
#else
#define ATTRIBUTE_PURE
#endif

#else /* defined(__GNUC__) && !defined(__clang__) */

#define ATTRIBUTE_ALWAYS_INLINE
#define ATTRIBUTE_NORETURN
#define ATTRIBUTE_UNUSED
#define ATTRIBUTE_FALLTHROUGH
#define ALIGN(n)
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#define ATTRIBUTE_NOTHROW
#define ATTRIBUTE_FORMAT_PRINTF(fmt, args)
#define ATTRIBUTE_NONNULL(...)
#define ATTRIBUTE_PURE

#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "endianness.h"

#define BSWAP16(x) bswap16(x)
#define BSWAP32(x) bswap32(x)
#define BSWAP64(x) bswap64(x)

#if defined(_WIN32)
#include <intrin.h>
#pragma intrinsic(_rotl8, _rotl16, _rotr8, _rotr16)
#else
static inline ATTRIBUTE_ALWAYS_INLINE uint8_t _rotl8(uint8_t x, int s) {
  return (x << s) | (x >> (8 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint16_t _rotl16(uint16_t x, int s) {
  return (x << s) | (x >> (16 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint32_t _rotl(uint32_t x, int s) {
  return (x << s) | (x >> (32 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint64_t _rotl64(uint64_t x, int s) {
  return (x << s) | (x >> (64 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint8_t _rotr8(uint8_t x, int s) {
  return (x >> s) | (x << (8 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint16_t _rotr16(uint16_t x, int s) {
  return (x >> s) | (x << (16 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint32_t _rotr(uint32_t x, int s) {
  return (x >> s) | (x << (32 - s));
}

static inline ATTRIBUTE_ALWAYS_INLINE uint64_t _rotr64(uint64_t x, int s) {
  return (x >> s) | (x << (64 - s));
}
#endif /* !defined _WIN32 */

#define ROTL8(x, s) _rotl8((x), (s))
#define ROTL16(x, s) _rotl16((x), (s))
#define ROTL32(x, s) _rotl((x), (s))
#define ROTL64(x, s) _rotl64((x), (s))

#define ROTR8(x, s) _rotr8((x), (s))
#define ROTR16(x, s) _rotr16((x), (s))
#define ROTR32(x, s) _rotr((x), (s))
#define ROTR64(x, s) _rotr64((x), (s))

#define PTRV(ptr) ((void *)(ptr))
#define PTR8(ptr) ((uint8_t *)(ptr))
#define PTR16(ptr) ((uint16_t *)(ptr))
#define PTR32(ptr) ((uint32_t *)(ptr))
#define PTR64(ptr) ((uint64_t *)(ptr))

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define COUNTOF(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef enum {
  ERR_SUCCESS,                 /* OK */
  ERR_NOT_ALLOC,               /* memory/interface not allocated */
  ERR_NOT_INIT,                /* not initialized */
  ERR_NULL_PTR,                /* null pointer argument(s) */
  ERR_BAD_ARGS,                /* invalid argument(s) */
  ERR_MEM_FAIL,                /* out of memory */
  ERR_BUFFER_TOO_SMALL,        /* buffer too small */
  ERR_REQUEST_TOO_LARGE,       /* request exceeded allowed maximum size */
  ERR_NOT_SUPPORTED,           /* operation not supported */
  ERR_INTERNAL,                /* internal library error */
  ERR_INVALID,                 /* invalid operation (sequence) */
  ERR_OPERATION_LIMIT_REACHED, /* operation limit reached */
  ERR_BAD_CONTROL_FLOW,        /* protocol deviation */
  ERR_INVALID_DATUM,           /* invalid data */
  ERR_HSHAKE_ABORTED,          /* handshake aborted */
  ERR_AUTH_FAIL,               /* authentication failed */
  ERR_AGAIN,                   /* try again */
  ERR_TIMEOUT,                 /* operation timed out */
  ERR_NORESOLVE,               /* could not resolve host */
  ERR_TCP_ACCEPT,              /* failed to accept TCP connection */
  ERR_TCP_CONNECT,             /* TCP connection failed */
  ERR_TCP_SEND,                /* TCP send failed */
  ERR_TCP_RECV,                /* TCP receive failed */
  ERR_ALREADY,                 /* already in progress */
  ERR_FIO_READ,                /* fio read failed */
  ERR_FIO_WRITE,               /* fio write failed */
  ERR_EOF,                     /* end of file reached */
} err_t;

/**
 * Log an error message using the global logger and exit with failure.
 *
 * Although technically part of the logging module, this function is
 * not associated with any log handler (logger). No hooks are invoked.
 */
extern void zt_log_fatal(const char *fmt, ...)
    ATTRIBUTE_FORMAT_PRINTF(1, 2) ATTRIBUTE_NORETURN;

#define log_fatal(fmt, ...) zt_log_fatal((fmt), ##__VA_ARGS__)

#ifdef ASSERT
#undef ASSERT
#endif
#if defined(DEBUG)
#define ASSERT(cond)                                                                     \
  do {                                                                                   \
    ((cond) ? (void)0                                                                    \
            : zt_log_fatal("%s:%d: assertion failed `" #cond "`", __FILE__, __LINE__));  \
  } while (0)
#else
#define ASSERT(cond) (cond)
#endif

#if defined(_MSC_VER)
#include <intrin.h> /* __fastfail */
#pragma intrinsic(__fastfail)
#endif

ATTRIBUTE_NORETURN static inline void __FKILL(void) {
#if defined(__has_builtin)
#if defined(__GNUC__) && __has_builtin(__builtin_trap)
  /* GCC / LLVM (Clang) */
  __builtin_trap();
#elif _MSC_VER >= 1610
  /* Visual Studio */
  __fastfail(0);
#else
  exit(EXIT_FAILURE);
#endif
#if __has_builtin(__builtin_unreachable)
  __builtin_unreachable();
#endif
#else /* __has_builtin */
  exit(EXIT_FAILURE)
#endif
}

/**************************************************************
 *                      Secure zero functions                 *
 **************************************************************/

extern void memzero(void *ptr, size_t len);

extern void fzero(int fd);

/**************************************************************
 *                    System information helpers              *
 **************************************************************/

/* Get the number of logical processors available to the current process */
unsigned int zt_cpu_get_processor_count(void);

/**************************************************************
 *                     Memory/string routines                 *
 **************************************************************/

#include <string.h>

typedef void *(malloc_func)(size_t);
typedef void *(calloc_func)(size_t, size_t);
typedef void *(realloc_func)(void *, size_t);
typedef void(free_func)(void *);

void *zt_malloc(size_t size);
void *zt_calloc(size_t nmemb, size_t size);
void zt_free(void *ptr);
void *zt_realloc(void *ptr, size_t size);

err_t zt_secure_mem_init(size_t n);
void *zt_secure_mem_alloc(size_t n);
void zt_secure_mem_free(void *p);

/**
 * Initialize global memory function pointers. These pointers can be set
 * to custom functions, or to NULL to use the default memory functions.
 *
 * @example zt_mem_init(NULL, NULL, NULL, NULL)
 *
 * This initializer must be called at the program startup before any of the zt_*
 * memory/string functions can be used.
 */
void zt_mem_init(malloc_func *malloc_fn, calloc_func *calloc_fn, realloc_func *realloc_fn,
                 free_func *free_fn);

/**
 * Sets the first len bytes of the memory area pointed to by mem to the
 * specified value (interpreted as an unsigned char).
 *
 * @param mem Pointer to the memory area to be set.
 * @param ch The value to set.
 * @param len The number of bytes to set.
 * @return Void.
 */
void zt_memset(void *mem, int ch, size_t len);

/**
 * Compares the first len bytes of the memory areas a and b.
 *
 * @param a A pointer to the first memory area.
 * @param b A pointer to the second memory area.
 * @param len The number of bytes to compare.
 * @return Zero if the memory areas are equal, non-zero otherwise.
 */
int zt_memcmp(const void *a, const void *b, size_t len);

/**
 * Compares two strings without leaking timing info about the private string.
 *
 * @param str The first (known) string.
 * @param x The second (secret/private) string.
 * @return Zero if the strings are equal, non-zero otherwise.
 */
int zt_strcmp(const char *str, const char *x);

/**
 * Duplicates a memory block.
 *
 * @param m A pointer to the memory block.
 * @param n The size of the memory block.
 * @return A pointer to the duplicated memory block, or NULL if the duplication
 * fails.
 *
 * @note The returned pointer must be zt_free()'d when no longer needed.
 */
void *zt_memdup(const void *m, size_t n);

/**
 * Duplicates a string.
 *
 * @param s The string to duplicate.
 * @return A pointer to the duplicated string, or NULL if the duplication fails.
 *
 * @note The returned pointer must be zt_free()'d when no longer needed.
 */
char *zt_strdup(const char *s);

/**
 * Duplicates a formatted string.
 *
 * @param fmt The format string.
 * @param ... The values to format.
 * @return A pointer to the nul-terminated duplicated string, or NULL if the
 * duplication fails.
 *
 * @note The returned pointer must be zt_free()'d when no longer needed.
 */
char *zt_vstrdup(const char *fmt, ...);

/**
 * Duplicates a memory block and converts it to a null-terminated string.
 *
 * @param m A pointer to the memory block.
 * @param n The size of the memory block.
 * @return A pointer to the duplicated string, or NULL if the duplication fails.
 *
 * @note The returned pointer must be zt_free()'d when no longer needed.
 */
char *zt_strmemdup(const void *m, size_t n);

/**************************************************************
 *                        Miscellaneous                       *
 **************************************************************/

/** Unsigned long to unsigned short */
unsigned short zt_ultous(unsigned long val);

/** Unsigned long to unsigned char */
unsigned char zt_ultouc(unsigned long val);

/** Unsigned long long to unsigned long */
unsigned long zt_ulltoul(unsigned long long val);

/** Unsigned long long to unsigned int */
unsigned int zt_ulltoui(unsigned long long val);

/** Unsigned long long to unsigned short */
unsigned short zt_ulltous(unsigned long long val);

/** Unsigned size_t to unsigned long */
unsigned long zt_ustoul(size_t val);

/** Unsigned size_t to unsigned int */
unsigned int zt_ustoui(size_t val);

/** Unsigned size_t to unsigned short */
unsigned short zt_ustous(size_t val);

/** Signed long to signed int */
int zt_sltoi(long val);

/** Signed long to unsigned int */
unsigned int zt_sltoui(long val);

/** Signed long to signed short */
short zt_sltos(long val);

/** Signed long to unsigned short */
unsigned short zt_sltous(long val);

/** Unsigned long long to signed long long */
long long zt_ulltoll(unsigned long long val);

/** Unsigned long long to signed long */
long zt_ulltol(unsigned long long val);

/** Unsigned long long to signed int */
int zt_ulltoi(unsigned long long val);

/** Signed long long to signed long */
long zt_slltol(long long val);

/** Signed long long to signed int */
int zt_slltoi(long long val);

/** Signed long long to signed short */
short zt_slltos(long long val);

/** size_t to ssize_t */
ssize_t zt_ssztosz(size_t val);

/** size_t to int */
int zt_sztoi(size_t val);

/** size_t to short */
short zt_sztos(size_t val);

/** ssize_t to unsigned int */
unsigned int zt_ssztoui(ssize_t val);

/** ssize_t to unsigned short */
unsigned short zt_ssztous(ssize_t val);

#define SIZE_KB ((off_t)1024)    /* 1 KB */
#define SIZE_MB (1024 * SIZE_KB) /* 1 MB */
#define SIZE_GB (1024 * SIZE_MB) /* 1 GB */
#define SIZE_TB (1024 * SIZE_GB) /* 1 TB */

/**
 * Convert file size to size in an appropriate unit.
 * Use `zt_filesize_unit_str()` to get the unit string.
 */
uint64_t zt_filesize_unit_conv(uint64_t size);

/**
 * Convert file size to appropriate unit.
 * Use `zt_filesize_unit_conv()` to get the size in the same unit.
 */
const char *zt_filesize_unit_str(uint64_t size);

#endif /* __DEFINES_H__ */
