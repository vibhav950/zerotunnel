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

#endif /* __GNUC__ && !__clang__ */

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

/** Reset the timeout
 *
 * This function should only be called after a timeout has already been set
 * using timeout_begin()
 */
void timeout_reset(timeout_t *timeout);

/** Check if the timeout has expired
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
