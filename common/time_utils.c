#include "time_utils.h"

/** */
zt_timeval_t zt_time_now() {
  struct timespec t;
  zt_timeval_t rv;
  if (clock_gettime(CLOCK_MONOTONIC, &t) == 0) {
    rv.tv_sec = t.tv_sec;
    rv.tv_usec = t.tv_nsec / 1000;
  } else {
    rv.tv_sec = time(NULL);
    rv.tv_usec = 0;
  }
  return rv;
}

/**
 * Returns the time in milliseconds, rounded up to the nearest millisecond.
 *
 * For differencces too large/small, it returns the maximum/minimum value.
 */
timediff_t zt_timediff_msec(zt_timeval_t newer, zt_timeval_t older) {
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if (diff >= TIMEDIFF_T_MAX)
    return TIMEDIFF_T_MAX;
  else if (diff <= TIMEDIFF_T_MIN)
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec - older.tv_usec + 999) / 1000;
}

/**
 * Returns the time in microseconds.
 *
 * For differences too large/small, it returns the maximum/minimum value.
 */
timediff_t zt_timediff_usec(zt_timeval_t newer, zt_timeval_t older) {
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if (diff >= (TIMEDIFF_T_MAX / 1000))
    return TIMEDIFF_T_MAX;
  else if (diff <= TIMEDIFF_T_MIN / 1000)
    return TIMEDIFF_T_MIN;
  return diff * 1000000 + (newer.tv_usec - older.tv_usec);
}
