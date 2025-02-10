#ifndef __TIMEDEFS_H__
#define __TIMEDEFS_H__

#include <stdint.h>
#include <time.h>

typedef struct _zt_timeval_st {
  time_t tv_sec; /* seconds */
  int tv_usec;   /* microseconds */
} zt_timeval_t;

#define TYPEOF_TIMEDIFF_T __int64_t
#define SIZEOF_TIMEDIFF_T sizeof(TYPEOF_TIMEDIFF_T)
#define TIMEDIFF_T_FMT "%lld"
#define TIMEDIFF_T_MAX INT64_MAX
#define TIMEDIFF_T_MIN INT64_MIN
typedef __int64_t timediff_t;

/**
 * Get the current time.
 *
 * @return the current time.
 */
zt_timeval_t zt_time_now();

/**
 * Returns the time in milliseconds, rounded up to the nearest millisecond.
 *
 * @param newer the newer time.
 * @param older the older time.
 * @return the time difference in milliseconds.
 */
timediff_t zt_timediff_msec(zt_timeval_t newer, zt_timeval_t older);

/**
 * Returns the time in microseconds.
 *
 * @param newer the newer time.
 * @param older the older time.
 * @return the time difference in microseconds.
 */
timediff_t zt_timediff_usec(zt_timeval_t newer, zt_timeval_t older);

#endif /* __TIMEDEFS_H__ */
