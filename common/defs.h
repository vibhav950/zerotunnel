/**
 *
 */

#ifndef __DEFS_H__
#define __DEFS_H__

#if defined(__GNUC__) &&                                                       \
    ((__GNUC__ > 2) || (__GNUC__ == 2) && (__GNUC_MINOR__ >= 95))
#define ATTRIBUTE_UNUSED __attribute__((unused))
#else
#define ATTRIBUTE_UNUSED
#endif

#if defined(__GNUC__) &&                                                       \
    ((__GNUC__ > 2) || (__GNUC__ == 2) && (__GNUC_MINOR__ >= 8))
#define ATTRIBUTE_NORETURN __attribute__((noreturn))
#else
#define ATTRIBUTE_NORETURN
#endif

#include "endianness.h"

#include <stdint.h>
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
} error_t;

/**
 * Logging routines
 */
void debug_printf(const char *func, const char *fmt, ...);
void error_printf(const char *file, int line, const char *msg);
void info_vprintf(const char *fmt, ...);

#if defined(DEBUG)
#define PRINTDEBUG(fmt, ...) debug_printf(__func__, fmt, ##__VA_ARGS__)
#else
#define PRINTDEBUG(fmt, ...)
#endif
#define PRINTERROR(msg) error_printf(__FILE__, __LINE__, msg)
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
 *  Set a timeout now
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

#endif /* __DEFS_H__ */
