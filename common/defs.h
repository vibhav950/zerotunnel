/**
 *
 */

#ifndef __DEFS_H__
#define __DEFS_H__

#include "endianness.h"

#include <stdint.h>

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

#endif /* __DEFS_H__ */
