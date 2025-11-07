/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * time_utils.c
 */

#include "time_utils.h"

/** Get current time. */
timeval_t zt_time_now() {
  timeval_t rv;
  struct timespec ts;
  struct timeval tv;
  /**
   * There may not be a monotonically increasing clock at
   * runtime, in which case we fall back to gettimeofday().
   */
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    rv.tv_sec = ts.tv_sec;
    rv.tv_usec = (int)(ts.tv_nsec / 1000);
  } else {
    (void)gettimeofday(&tv, NULL);
    rv.tv_sec = tv.tv_sec;
    rv.tv_usec = tv.tv_usec;
  }
  return rv;
}

/**
 * Returns the time difference in milliseconds.
 *
 * For differences too large/small, it returns the maximum/minimum value.
 */
timediff_t zt_timediff_msec(timeval_t newer, timeval_t older) {
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
timediff_t zt_timediff_msec_ceil(timeval_t newer, timeval_t older) {
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
timediff_t zt_timediff_usec(timeval_t newer, timeval_t older) {
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if (diff >= (TIMEDIFF_T_MAX / 1000000))
    return TIMEDIFF_T_MAX;
  else if (diff <= TIMEDIFF_T_MIN / 1000000)
    return TIMEDIFF_T_MIN;
  return diff * 1000000 + (newer.tv_usec - older.tv_usec);
}
