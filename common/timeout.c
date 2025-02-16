#include "defines.h"

void zt_timeout_begin(zt_timeout_t *timeout, timediff_t usec, timeout_cb handler) {
  zt_timeval_t tnow = zt_time_now();
  if (timeout) {
    timeout->begin = tnow;
    timeout->expire_in_usec = usec;
    timeout->handler = handler;
  }
}

void zt_timeout_reset(zt_timeout_t *timeout) {
  zt_timeval_t tnow = zt_time_now();
  if (timeout) {
    timeout->begin = tnow;
  }
}

int zt_timeout_expired(zt_timeout_t *timeout, void *args) {
  zt_timeval_t tnow = zt_time_now();
  timediff_t diff = zt_timediff_usec(tnow, timeout->begin);
  if (diff >= timeout->expire_in_usec) {
    if (timeout->handler)
      timeout->handler(args);
    return 1;
  }
  return 0;
}
