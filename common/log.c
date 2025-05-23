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

#define FG_BLUE   "\x1B[34m"
#define FG_RED    "\x1B[91m"
#define FG_GREEN  "\x1B[92m"
#define FG_CLEAR  "\x1B[0m"

inline void zt_debug_vprintf(const char *func, const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_DEBUG, "%s[DEBUG %s]%s ", FG_BLUE, func, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_DEBUG, fmt, args);
  va_end(args);
  printf("\n");
}

inline void zt_error_vprintf(const char *file, const int line, const char *fmt,
                             ...) {
  va_list args;

  fprintf(LOG_FP_ERROR, "%s[ERROR %s:%d]%s ", FG_RED, file, line, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_DEBUG, fmt, args);
  va_end(args);
  printf("\n");
}

ATTRIBUTE_NORETURN inline void
zt_error_vprintf_exit(const char *file, const int line, const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_ERROR, "%s[ERROR %s:%d]%s ", FG_RED, file, line, FG_CLEAR);
  va_start(args, fmt);
  vfprintf(LOG_FP_DEBUG, fmt, args);
  va_end(args);
  printf("\n");
  exit(EXIT_FAILURE);
}

inline void zt_info_vprintf(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  vfprintf(LOG_FP_INFO, fmt, args);
  va_end(args);
  printf("\n");
}
