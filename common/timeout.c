#include "defines.h"

/**
 * @param[in] timeout The timeout.
 * @param[in] usec The timeout in microseconds.
 * @param[in] handler The timeout handler.
 * @return void
 *
 * Set a timeout.
 *
 * Note: If `usec < 0`, the timeout never expires.
 */
void zt_timeout_begin(zt_timeout_t *timeout, timediff_t usec,
                      timeout_cb handler) {
  zt_timeval_t tnow = zt_time_now();
  if (likely(timeout)) {
    timeout->begin = tnow;
    timeout->expire_in_usec = usec;
    timeout->handler = handler;
  }
}

/**
 * @param[in] timeout The timeout.
 * @return void
 *
 * Reset an already set timeout. To initialize a timeout, use
 * `zt_timeout_begin()`.
 */
void zt_timeout_reset(zt_timeout_t *timeout) {
  zt_timeval_t tnow = zt_time_now();
  if (likely(timeout))
    timeout->begin = tnow;
}

/**
 * @param[in] timeout The timeout.
 * @param[in] args The arguments to the timeout handler.
 * @return >0 if the timeout has expired, 0 if not,
 * <0 if NULL was passed for @p timeout.
 *
 * Check if a timeout has expired.
 */
int zt_timeout_expired(zt_timeout_t *timeout, void *args) {
  zt_timeval_t tnow = zt_time_now();
  if (likely(timeout)) {
    if (timeout->expire_in_usec < 0)
      return 0;
    timediff_t diff = zt_timediff_usec(tnow, timeout->begin);
    if (diff >= timeout->expire_in_usec) {
      if (timeout->handler)
        timeout->handler(args);
      return 1;
    }
    return 0;
  }
  return -1;
}
