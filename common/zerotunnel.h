/**
 *
 */

#ifndef __ZEROTUNNEL_H__
#define __ZEROTUNNEL_H__

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define GCC_VERSION_AT_LEAST(major, minor)                                     \
  ((__GNUC__ > (major)) ||                                                     \
   ((__GNUC__ == (major)) && (__GNUC_MINOR__ >= (minor))))
#else
#define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if defined(__clang__) && defined(__clang_minor__)
#define CLANG_VERSION_AT_LEAST(major, minor)                                   \
  ((__clang__ > (major)) ||                                                    \
   ((__clang__ == (major)) && (__clang_minor__ >= (minor))))
#else
#define CLANG_VERSION_AT_LEAST(major, minor) 0
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

#elif defined(__clang__) /* __GNUC__ && !__clang__ */

#define ATTRIBUTE_ALWAYS_INLINE
#define ATTRIBUTE_NORETURN
#define ATTRIBUTE_UNUSED

#endif

#include <stdbool.h>
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

#ifdef MAX
#undef MAX
#endif
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#ifdef MIN
#undef MIN
#endif
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#ifdef COUNTF
#undef COUNTF
#endif
#define COUNTOF(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef enum {
  ERR_SUCCESS,
  ERR_NOT_ALLOC,
  ERR_NOT_INIT,
  ERR_NULL_PTR,
  ERR_BAD_ARGS,
  ERR_MEM_FAIL,
  ERR_AUTH_FAIL,
  ERR_BUFFER_TOO_SMALL,
  ERR_AGAIN,
  ERR_NOT_SUPPORTED,
  ERR_INTERNAL,
  ERR_TIMEOUT,
  ERR_INVALID,
  ERR_NORESOLVE,
  ERR_CONNECT,
  ERR_ALREADY,
} error_t;

/**
 * Logging routines
 */

void zt_debug_vprintf(const char *func, const char *fmt, ...);

void zt_error_vprintf(const char *file, int line, const char *fmt, ...);

void zt_info_vprintf(const char *fmt, ...);

#if defined(DEBUG)
#define PRINTDEBUG(fmt, ...) zt_debug_vprintf(__func__, fmt, ##__VA_ARGS__)
#else
#define PRINTDEBUG(fmt, ...)
#endif
#define PRINTERROR(fmt, ...)                                                   \
  zt_error_vprintf(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define PRINTINFO(fmt, ...) zt_info_vprintf(fmt, ##__VA_ARGS__)

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
  // Hacky way to trigger a segfault
  *(char *)0 = 0;
#endif
#if __has_builtin(__builtin_unreachable)
  __builtin_unreachable();
#endif
#else // __has_builtin
  *(char *)0 = 0;
#endif
}

/**
 * System information helpers
 */

/** Get the number of CPU cores. */
int zt_cpu_get_processor_count(void);

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
void *zt_malloc(size_t size);

/**
 * Allocates a block of memory for an array of elements, each of the given size.
 * The memory is initialized to zero.
 *
 * @param nmemb The number of elements in the array.
 * @param size The size of each element.
 * @return A pointer to the allocated memory block, or NULL if the allocation
 * fails.
 */
void *zt_calloc(size_t nmemb, size_t size);

/**
 * Frees a previously allocated block of memory.
 *
 * @param ptr A pointer to the memory block to free.
 */
void zt_free(void *ptr);

/**
 * Changes the size of the memory block pointed to by ptr to the given size.
 *
 * @param ptr A pointer to the memory block to reallocate.
 * @param size The new size of the memory block.
 * @return A pointer to the reallocated memory block, or NULL if the
 * reallocation fails.
 */
void *zt_realloc(void *ptr, size_t size);

/**
 * Sets the first len bytes of the memory area pointed to by mem to the
 * specified value.
 *
 * @param mem A pointer to the memory area.
 * @param ch The value to set.
 * @param len The number of bytes to set.
 * @return A pointer to the memory area.
 */
volatile void *zt_memset(volatile void *mem, int ch, size_t len);

/**
 * Sets the first len bytes of the memory area pointed to by mem to zero.
 *
 * @param mem A pointer to the memory area.
 * @param len The number of bytes to set.
 * @return A pointer to the memory area.
 */
volatile void *zt_memzero(volatile void *mem, size_t len);

/**
 * Copies len bytes from the memory area src to the memory area dst.
 *
 * @param dst A pointer to the destination memory area.
 * @param src A pointer to the source memory area.
 * @param len The number of bytes to copy.
 * @return A pointer to the destination memory area.
 */
volatile void *zt_memcpy(volatile void *dst, volatile void *src, size_t len);

/**
 * Copies len bytes from the memory area src to the memory area dst, even if the
 * memory areas overlap.
 *
 * @param dst A pointer to the destination memory area.
 * @param src A pointer to the source memory area.
 * @param len The number of bytes to copy.
 * @return A pointer to the destination memory area.
 */
volatile void *zt_memmove(volatile void *dst, volatile void *src, size_t len);

/**
 * Compares the first len bytes of the memory areas a and b.
 *
 * @param a A pointer to the first memory area.
 * @param b A pointer to the second memory area.
 * @param len The number of bytes to compare.
 * @return Zero if the memory areas are equal, non-zero otherwise.
 */
unsigned int zt_memcmp(const void *a, const void *b, size_t len);

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
 * Duplicates a memory block and converts it to a null-terminated string.
 *
 * @param m A pointer to the memory block.
 * @param n The size of the memory block.
 * @return A pointer to the duplicated string, or NULL if the duplication fails.
 *
 * @note The returned pointer must be zt_free()'d when no longer needed.
 */
char *zt_strmemdup(const void *m, size_t n);

/**
 * Timeout routines
 */

#include "time_utils.h"

typedef void (*timeout_cb)(void *args);

typedef struct _zt_timeout_st {
  zt_timeval_t begin;
  timediff_t expire_in_usec;
  timeout_cb handler;
} zt_timeout_t;

/**
 * Set a timeout now
 */
void zt_timeout_begin(zt_timeout_t *timeout, timediff_t usec,
                      timeout_cb handler);

/**
 * Reset the timeout
 *
 * This function should only be called after a timeout has already been set
 * using zt_timeout_begin()
 */
void zt_timeout_reset(zt_timeout_t *timeout);

/**
 * Check if the timeout has expired
 *
 * This function should only be called after a timeout has already been set
 * using zt_timeout_begin()
 *
 * Returns 1 if the timeout has expired, 0 otherwise
 */
int zt_timeout_expired(zt_timeout_t *timeout, void *args);

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

#endif /* __ZEROTUNNEL_H__ */
