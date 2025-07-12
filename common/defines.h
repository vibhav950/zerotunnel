/**
 *
 */

#ifndef __DEFINES_H__
#define __DEFINES_H__

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define GCC_VERSION_AT_LEAST(major, minor)                                     \
  ((__GNUC__ > (major)) ||                                                     \
   ((__GNUC__ == (major)) && (__GNUC_MINOR__ >= (minor))))
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

#else /* defined(__GNUC__) && !defined(__clang__) */

#define ATTRIBUTE_ALWAYS_INLINE
#define ATTRIBUTE_NORETURN
#define ATTRIBUTE_UNUSED
#define ATTRIBUTE_FALLTHROUGH
#define ALIGN(n)
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#define ATTRIBUTE_NOTHROW

#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

// #include <errno.h>

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
  ERR_SUCCESS,                    /* OK */
  ERR_NOT_ALLOC,                  /* memory/interface not allocated */
  ERR_NOT_INIT,                   /* not initialized */
  ERR_NULL_PTR,                   /* null pointer argument(s) */
  ERR_BAD_ARGS,                   /* invalid argument(s) */
  ERR_MEM_FAIL,                   /* out of memory */
  ERR_BUFFER_TOO_SMALL,           /* buffer too small */
  ERR_REQUEST_TOO_LARGE,          /* request exceeded allowed maximum size */
  ERR_NOT_SUPPORTED,              /* operation not supported */
  ERR_INTERNAL,                   /* internal library error */
  ERR_INVALID,                    /* invalid operation (sequence) */
  ERR_OPERATION_LIMIT_REACHED,    /* operation limit reached */
  ERR_INVALID_DATUM,              /* invalid data */
  ERR_HSHAKE_ABORTED,             /* handshake aborted */
  ERR_AUTH_FAIL,                  /* authentication failed */
  ERR_AGAIN,                      /* try again */
  ERR_TIMEOUT,                    /* operation timed out */
  ERR_NORESOLVE,                  /* could not resolve host */
  ERR_TCP_ACCEPT,                 /* failed to accept TCP connection */
  ERR_TCP_CONNECT,                /* TCP connection failed */
  ERR_TCP_SEND,                   /* TCP send failed */
  ERR_TCP_RECV,                   /* TCP receive failed */
  ERR_ALREADY,                    /* already in progress */
  ERR_FIO_READ,                   /* fio read failed */
  ERR_FIO_WRITE,                  /* fio write failed */
  ERR_EOF,                        /* end of file reached */
} err_t;

const char *zt_error_str(err_t err);

/**
 * Logging routines
 */

#if GCC_VERSION_AT_LEAST(2, 5)
extern void zt_debug_vprintf(const char *func, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

extern void zt_error_vprintf(const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

extern void zt_info_vprintf(const char *file, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

extern void zt_error_vprintf_exit(const char *f, int ln, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 3, 4)));

extern void zt_warn_vprintf(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
#else
extern void zt_debug_vprintf(const char *func, const char *fmt, ...);
extern void zt_error_vprintf(const char *file, int line, const char *fmt, ...);
extern void zt_info_vprintf(const char *file, const char *fmt, ...);
extern void zt_error_vprintf_exit(const char *f, int ln, const char *fmt, ...);
extern void zt_warn_vprintf(const char *fmt, ...);
#endif

#ifdef ASSERT
#undef ASSERT
#endif

#if defined(DEBUG)

#define PRINTDEBUG(fmt, ...) zt_debug_vprintf(__func__, fmt, ##__VA_ARGS__)

#define ASSERT(cond)                                                           \
  do {                                                                         \
    ((cond) ? (void)0                                                          \
            : zt_error_vprintf_exit(__FILE__, __LINE__,                        \
                                    "Assertion failed `" #cond "`"));          \
  } while (0)

#else /* !defined(DEBUG) */

#define PRINTDEBUG(fmt, ...)

#define ASSERT(cond) (cond)

#endif

#define PRINTERROR(fmt, ...)                                                   \
  zt_error_vprintf(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define PRINTFATAL(fmt, ...)                                                   \
  zt_error_vprintf_exit(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define PRINTINFO(fmt, ...) zt_info_vprintf(__func__, fmt, ##__VA_ARGS__)

#define PRINTWARN(fmt, ...) zt_warn_vprintf(fmt, ##__VA_ARGS__)

#if defined(_MSC_VER)
#include <intrin.h> // __fastfail
#pragma intrinsic(__fastfail)
#endif

ATTRIBUTE_NORETURN static inline void __FKILL(void) {
#if defined(__has_builtin)
#if defined(__GNUC__) && __has_builtin(__builtin_trap)
  // GCC / LLVM (Clang)
  __builtin_trap();
#elif _MSC_VER >= 1610
  // Visual Studio
  __fastfail(0);
#else
  exit(EXIT_FAILURE);
#endif
#if __has_builtin(__builtin_unreachable)
  __builtin_unreachable();
#endif
#else // __has_builtin
  exit(EXIT_FAILURE)
#endif
}

/**
 * Secure zero functions
 */

void memzero(void *ptr, size_t len);

void fzero(int fd);

/**
 * System information helpers
 */

/**
 * Get the number of logical processors available to the current process
 */
unsigned int zt_cpu_get_processor_count(void);

/**
 * Memory/string routines
 */

/**
 * Allocates a block of memory of the given size.
 *
 * @param size The size of the memory block to allocate.
 * @return A pointer to the allocated memory block, or NULL if the allocation
 * fails.
 */
void *zt_mem_malloc(size_t size);

/**
 * Allocates a block of memory for an array of elements, each of the given size.
 * The memory is initialized to zero.
 *
 * @param nmemb The number of elements in the array.
 * @param size The size of each element.
 * @return A pointer to the allocated memory block, or NULL if the allocation
 * fails.
 */
void *zt_mem_calloc(size_t nmemb, size_t size);

/**
 * Frees a previously allocated block of memory.
 *
 * @param ptr A pointer to the memory block to free.
 */
void zt_mem_free(void *ptr);

/**
 * Changes the size of the memory block pointed to by ptr to the given size.
 *
 * @param ptr A pointer to the memory block to reallocate.
 * @param size The new size of the memory block.
 * @return A pointer to the reallocated memory block, or NULL if the
 * reallocation fails.
 */
void *zt_mem_realloc(void *ptr, size_t size);

/**
 * Sets the first len bytes of the memory area pointed to by mem to the
 * specified value.
 *
 * @param mem A pointer to the memory area.
 * @param ch The value to set.
 * @param len The number of bytes to set.
 * @return A pointer to the memory area.
 */
void *zt_mem_memset(void *mem, int ch, size_t len);

/**
 * Sets the first len bytes of the memory area pointed to by mem to zero.
 *
 * @param mem A pointer to the memory area.
 * @param len The number of bytes to set.
 * @return A pointer to the memory area.
 */
void *zt_mem_memzero(void *mem, size_t len);

/**
 * Copies len bytes from the memory area src to the memory area dst.
 *
 * @param dst A pointer to the destination memory area.
 * @param src A pointer to the source memory area.
 * @param len The number of bytes to copy.
 * @return A pointer to the destination memory area.
 */
void *zt_mem_memcpy(void *dst, void *src, size_t len);

/**
 * Copies len bytes from the memory area src to the memory area dst, even if the
 * memory areas overlap.
 *
 * @param dst A pointer to the destination memory area.
 * @param src A pointer to the source memory area.
 * @param len The number of bytes to copy.
 * @return A pointer to the destination memory area.
 */
void *zt_mem_memmove(void *dst, void *src, size_t len);

/**
 * Compares the first len bytes of the memory areas a and b.
 *
 * @param a A pointer to the first memory area.
 * @param b A pointer to the second memory area.
 * @param len The number of bytes to compare.
 * @return Zero if the memory areas are equal, non-zero otherwise.
 */
unsigned int zt_mem_memcmp(const void *a, const void *b, size_t len);

/**
 * Compares two strings without leaking timing info about the private string.
 *
 * @param str The first (known) string.
 * @param x The second (secret/private) string.
 * @return Zero if the strings are equal, non-zero otherwise.
 */
unsigned int zt_strcmp(const char *str, const char *x);

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

#include <stdlib.h>
#include <string.h>

#if defined(USE_SAFE_MEM)
#define zt_malloc(size) zt_mem_malloc(size)
#define zt_calloc(nmemb, size) zt_mem_calloc(nmemb, size)
#define zt_realloc(ptr, size) zt_mem_realloc(ptr, size)
#define zt_free(ptr) zt_mem_free(ptr)
#define zt_memset(mem, ch, len) zt_mem_memset(mem, ch, len)
#define zt_memzero(mem, len) zt_mem_memzero(mem, len)
#define zt_memcpy(dst, src, len) zt_mem_memcpy(dst, src, len)
#define zt_memmove(dst, src, len) zt_mem_memmove(dst, src, len)
#define zt_memcmp(a, b, len) zt_mem_memcmp(a, b, len)
#else /* defined(USE_SAFE_MEM) */
#define zt_malloc(size) malloc(size)
#define zt_calloc(nmemb, size) calloc(nmemb, size)
#define zt_realloc(ptr, size) realloc(ptr, size)
#define zt_free(ptr) free(ptr)
#define zt_memset(mem, ch, len) memset(mem, ch, len)
#define zt_memzero(mem, len) memset(mem, 0, len)
#define zt_memcpy(dst, src, len) memcpy(dst, src, len)
#define zt_memmove(dst, src, len) memmove(dst, src, len)
#define zt_memcmp(a, b, len) memcmp(a, b, len)
#endif /* !defined(USE_SAFE_MEM) */

#include "timeout.h" // transitive #include "time_utils.h"

/**
 * Type conversions
 */

unsigned short zt_ultous(unsigned long val);
unsigned char zt_ultouc(unsigned long val);
unsigned long zt_ulltoul(unsigned long long val);
unsigned int zt_ulltoui(unsigned long long val);
unsigned short zt_ulltous(unsigned long long val);
unsigned long zt_ustoul(size_t val);
unsigned int zt_ustoui(size_t val);
unsigned short zt_ustous(size_t val);
int zt_sltoi(long val);
unsigned int zt_sltoui(long val);
short zt_sltos(long val);
unsigned short zt_sltous(long val);
long long zt_ulltoll(unsigned long long val);
long zt_ulltol(unsigned long long val);
int zt_ulltoi(unsigned long long val);
long zt_slltol(long long val);
int zt_slltoi(long long val);
short zt_slltos(long long val);
ssize_t zt_ssztosz(size_t val);
int zt_sztoi(size_t val);
short zt_sztos(size_t val);
unsigned int zt_ssztoui(ssize_t val);
unsigned short zt_ssztous(ssize_t val);

#endif /* __DEFINES_H__ */
