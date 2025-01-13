#include "defs.h"

void timeout_begin(timeout_t *timeout, timediff_t usec, timeout_cb handler) {
  timeval_t tnow = now();
  if (timeout) {
    timeout->begin = tnow;
    timeout->expire_in_usec = usec;
    timeout->handler = handler;
  }
}

void timeout_reset(timeout_t *timeout) {
  timeval_t tnow = now();
  if (timeout) {
    timeout->begin = tnow;
  }
}

int timeout_expired(timeout_t *timeout, void *args) {
  timeval_t tnow = now();
  timediff_t diff = timediff_usec(tnow, timeout->begin);
  if (diff >= timeout->expire_in_usec) {
    if (timeout->handler)
      timeout->handler(args);
    return 1;
  }
  return 0;
}
