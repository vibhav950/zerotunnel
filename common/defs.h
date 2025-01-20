/**
 *
 */

#ifndef __DEFS_H__
#define __DEFS_H__

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

#include "endianness.h"

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

typedef enum {
  ERR_SUCCESS,
  ERR_NOT_ALLOC,
  ERR_NOT_INIT,
  ERR_NULL_PTR,
  ERR_BAD_ARGS,
  ERR_MEM_FAIL,
  ERR_AUTH_FAIL,
  ERR_BUFFER_TOO_SMALL,
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

void debug_vprintf(const char *func, const char *fmt, ...);

void error_vprintf(const char *file, int line, const char *fmt, ...);

void info_vprintf(const char *fmt, ...);

#if defined(DEBUG)
#define PRINTDEBUG(fmt, ...) debug_vprintf(__func__, fmt, ##__VA_ARGS__)
#else
#define PRINTDEBUG(fmt, ...)
#endif
#define PRINTERROR(fmt, ...)                                                   \
  error_vprintf(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define PRINTINFO(fmt, ...) info_vprintf(fmt, ##__VA_ARGS__)

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
 * Memory/string routines
 */

/**
 * Allocates a block of memory of the given size.
 *
 * @param size The size of the memory block to allocate.
 * @return A pointer to the allocated memory block, or NULL if the allocation
 * fails.
 */
void *xmalloc(size_t size);

/**
 * Allocates a block of memory for an array of elements, each of the given size.
 * The memory is initialized to zero.
 *
 * @param nmemb The number of elements in the array.
 * @param size The size of each element.
 * @return A pointer to the allocated memory block, or NULL if the allocation fails.
 */
void *xcalloc(size_t nmemb, size_t size);

/**
 * Frees a previously allocated block of memory.
 *
 * @param ptr A pointer to the memory block to free.
 */
void xfree(void *ptr);

/**
 * Changes the size of the memory block pointed to by ptr to the given size.
 *
 * @param ptr A pointer to the memory block to reallocate.
 * @param size The new size of the memory block.
 * @return A pointer to the reallocated memory block, or NULL if the reallocation fails.
 */
void *xrealloc(void *ptr, size_t size);

/**
 * Sets the first len bytes of the memory area pointed to by mem to the specified value.
 *
 * @param mem A pointer to the memory area.
 * @param ch The value to set.
 * @param len The number of bytes to set.
 * @return A pointer to the memory area.
 */
volatile void *xmemset(volatile void *mem, int ch, size_t len);

/**
 * Sets the first len bytes of the memory area pointed to by mem to zero.
 *
 * @param mem A pointer to the memory area.
 * @param len The number of bytes to set.
 * @return A pointer to the memory area.
 */
volatile void *xmemzero(volatile void *mem, size_t len);

/**
 * Copies len bytes from the memory area src to the memory area dst.
 *
 * @param dst A pointer to the destination memory area.
 * @param src A pointer to the source memory area.
 * @param len The number of bytes to copy.
 * @return A pointer to the destination memory area.
 */
volatile void *xmemcpy(volatile void *dst, volatile void *src, size_t len);

/**
 * Copies len bytes from the memory area src to the memory area dst, even if the memory areas overlap.
 *
 * @param dst A pointer to the destination memory area.
 * @param src A pointer to the source memory area.
 * @param len The number of bytes to copy.
 * @return A pointer to the destination memory area.
 */
volatile void *xmemmove(volatile void *dst, volatile void *src, size_t len);

/**
 * Compares the first len bytes of the memory areas a and b.
 *
 * @param a A pointer to the first memory area.
 * @param b A pointer to the second memory area.
 * @param len The number of bytes to compare.
 * @return Zero if the memory areas are equal, non-zero otherwise.
 */
unsigned int xmemcmp(const void *a, const void *b, size_t len);

/**
 * Compares two strings without leaking timing info about the private string.
 *
 * @param str The first (known) string.
 * @param x The second (secret/private) string.
 * @return Zero if the strings are equal, non-zero otherwise.
 */
unsigned int xstrcmp(const char *str, const char *x);

/**
 * Duplicates a memory block.
 *
 * @param m A pointer to the memory block.
 * @param n The size of the memory block.
 * @return A pointer to the duplicated memory block, or NULL if the duplication fails.
 *
 * @note The returned pointer must be xfree()'d when no longer needed.
 */
void *xmemdup(const void *m, size_t n);

/**
 * Duplicates a string.
 *
 * @param s The string to duplicate.
 * @return A pointer to the duplicated string, or NULL if the duplication fails.
 *
 * @note The returned pointer must be xfree()'d when no longer needed.
 */
char *xstrdup(const char *s);

/**
 * Duplicates a memory block and converts it to a null-terminated string.
 *
 * @param m A pointer to the memory block.
 * @param n The size of the memory block.
 * @return A pointer to the duplicated string, or NULL if the duplication fails.
 *
 * @note The returned pointer must be xfree()'d when no longer needed.
 */
char *xstrmemdup(const void *m, size_t n);

/**
 * Timeout routines
 */

#include "time_utils.h"

typedef void (*timeout_cb)(void *args);

typedef struct _timeout_st {
  timeval_t begin;
  timediff_t expire_in_usec;
  timeout_cb handler;
} timeout_t;

/**
 * Set a timeout now
 */
void timeout_begin(timeout_t *timeout, timediff_t usec, timeout_cb handler);

/**
 * Reset the timeout
 *
 * This function should only be called after a timeout has already been set
 * using timeout_begin()
 */
void timeout_reset(timeout_t *timeout);

/**
 * Check if the timeout has expired
 *
 * This function should only be called after a timeout has already been set
 * using timeout_begin()
 *
 * Returns 1 if the timeout has expired, 0 otherwise
 */
int timeout_expired(timeout_t *timeout, void *args);

/**
 * Type conversions
 */

unsigned short ultous(unsigned long val);
unsigned char ultouc(unsigned long val);
unsigned long ulltoul(unsigned long long val);
unsigned int ulltoui(unsigned long long val);
unsigned short ulltous(unsigned long long val);
unsigned long ustoul(size_t val);
unsigned int ustoui(size_t val);
unsigned short ustous(size_t val);
int sltoi(long val);
unsigned int sltoui(long val);
short sltos(long val);
unsigned short sltous(long val);
long long ulltoll(unsigned long long val);
long ulltol(unsigned long long val);
int ulltoi(unsigned long long val);
long slltol(long long val);
int slltoi(long long val);
short slltos(long long val);
ssize_t ssztosz(size_t val);
int sztoi(size_t val);
short sztos(size_t val);
unsigned int ssztoui(ssize_t val);
unsigned short ssztous(ssize_t val);

#endif /* __DEFS_H__ */
