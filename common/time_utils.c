#include "time_utils.h"

/** */
zt_timeval_t zt_time_now() {
  struct timeval t;
  zt_timeval_t rv;
  gettimeofday(&t, NULL);
  rv.tv_sec = t.tv_sec;
  rv.tv_usec = t.tv_usec;
  return rv;
}

/**
 * Returns the time difference in milliseconds.
 *
 * For differences too large/small, it returns the maximum/minimum value.
 */
timediff_t zt_timediff_msec(zt_timeval_t newer, zt_timeval_t older) {
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if (diff >= TIMEDIFF_T_MAX / 1000)
    return TIMEDIFF_T_MAX;
  else if (diff <= TIMEDIFF_T_MIN / 1000)
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec - older.tv_usec) / 1000;
}

/**
 * Returns the time difference in milliseconds, rounded up to the nearest
 * millisecond.
 *
 * For differences too large/small, it returns the maximum/minimum value.
 */
timediff_t zt_timediff_msec_ceil(zt_timeval_t newer, zt_timeval_t older) {
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if (diff >= TIMEDIFF_T_MAX / 1000)
    return TIMEDIFF_T_MAX;
  else if (diff <= TIMEDIFF_T_MIN / 1000)
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec - older.tv_usec + 999) / 1000;
}

/**
 * Returns the time difference in microseconds.
 *
 * For differences too large/small, it returns the maximum/minimum value.
 */
timediff_t zt_timediff_usec(zt_timeval_t newer, zt_timeval_t older) {
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if (diff >= (TIMEDIFF_T_MAX / 1000000))
    return TIMEDIFF_T_MAX;
  else if (diff <= TIMEDIFF_T_MIN / 1000000)
    return TIMEDIFF_T_MIN;
  return diff * 1000000 + (newer.tv_usec - older.tv_usec);
}
