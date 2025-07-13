#include "defines.h"

#include <stdarg.h>
#include <stdio.h>

#ifndef LOG_FP_DEBUG
#define LOG_FP_DEBUG stderr
#endif

#ifndef LOG_FP_ERROR
#define LOG_FP_ERROR stderr
#endif

#ifndef LOG_FP_INFO
#define LOG_FP_INFO stdout
#endif

#ifndef LOG_FP_WARN
#define LOG_FP_WARN stderr
#endif

#define FG_BLUE     "\x1B[94m"
#define FG_MAGENTA  "\x1B[95m"
#define FG_RED      "\x1B[91m"
#define FG_GREEN    "\x1B[92m"
#define FG_YELLOW   "\x1B[33m"
#define FG_CLEAR    "\x1B[0m"

#define FG_BOLD "\x1B[1m"

const char *zt_error_str(err_t err) {
  switch (err) {
  case ERR_SUCCESS:
    return "success";
  case ERR_NOT_ALLOC:
    return "memory/interface not allocated";
  case ERR_NOT_INIT:
    return "not initialized";
  case ERR_NULL_PTR:
    return "null pointer argument(s)";
  case ERR_BAD_ARGS:
    return "invalid argument(s)";
  case ERR_MEM_FAIL:
    return "out of memory";
  case ERR_BUFFER_TOO_SMALL:
    return "buffer too small";
  case ERR_REQUEST_TOO_LARGE:
    return "request exceeded maximum allowed size";
  case ERR_NOT_SUPPORTED:
    return "operation not supported";
  case ERR_INTERNAL:
    return "internal library failure";
  case ERR_INVALID:
    return "invalid operation sequence";
  case ERR_OPERATION_LIMIT_REACHED:
    return "operation limit reached";
  case ERR_BAD_CONTROL_FLOW:
    return "deviated from expected control flow";
  case ERR_INVALID_DATUM:
    return "mismatch from expected data";
  case ERR_HSHAKE_ABORTED:
    return "handshake aborted due to failure";
  case ERR_AUTH_FAIL:
    return "authentication failure";
  case ERR_AGAIN:
    return "try again";
  case ERR_TIMEOUT:
    return "operation timed out";
  case ERR_NORESOLVE:
    return "could not resolve host";
  case ERR_TCP_ACCEPT:
    return "failed to accept TCP connection";
  case ERR_TCP_CONNECT:
    return "TCP connection failed";
  case ERR_TCP_SEND:
    return "TCP send failed";
  case ERR_TCP_RECV:
    return "TCP receive failed";
  case ERR_ALREADY:
    return "already in progress";
  case ERR_FIO_READ:
    return "failed to read file";
  case ERR_FIO_WRITE:
    return "failed to write file";
  case ERR_EOF:
    return "end of file reached";
  default:
    return "unknown error";
  }
}

inline void zt_debug_vprintf(const char *func, const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_DEBUG, "%s[DEBUG %s] %s ", FG_BLUE, func, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_DEBUG, fmt, args);
  va_end(args);
  fprintf(LOG_FP_DEBUG, "\n");
}

inline void zt_error_vprintf(const char *file, const int line, const char *fmt,
                             ...) {
  va_list args;

  fprintf(LOG_FP_ERROR, "%s[ERROR %s:%d] %s ", FG_RED, file, line, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_ERROR, fmt, args);
  va_end(args);
  fprintf(LOG_FP_ERROR, "\n");
}

inline void zt_error_vprintf_exit(const char *file, const int line,
                                  const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_ERROR, "%s[ERROR %s:%d] %s ", FG_RED, file, line, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_ERROR, fmt, args);
  va_end(args);
  fprintf(LOG_FP_ERROR, "\n");
  exit(EXIT_FAILURE);
}

inline void zt_info_vprintf(const char *func, const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_INFO, "%s[INFO %s] %s ", FG_MAGENTA, func, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_INFO, fmt, args);
  va_end(args);
  fprintf(LOG_FP_INFO, "\n");
}

inline void zt_warn_vprintf(const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_WARN, "%s%s[WARNING] %s ", FG_BOLD, FG_YELLOW, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_WARN, fmt, args);
  va_end(args);
  fprintf(LOG_FP_WARN, "\n");
}
