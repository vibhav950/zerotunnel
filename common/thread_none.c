#include "common/thread.h"

struct _zt_thread_noapi_st {};

zt_thread_t *zt_thread_create(int (*entry)(void *arg) ATTRIBUTE_UNUSED,
                              void *arg ATTRIBUTE_UNUSED) {
  return zt_thread_t_null;
}

void zt_thread_destroy(zt_thread_t *t ATTRIBUTE_UNUSED) { return; }

err_t zt_thread_join(zt_thread_t *t ATTRIBUTE_UNUSED) { return ERR_NOT_SUPPORTED; }

err_t zt_thread_setaffinity(zt_thread_t *t ATTRIBUTE_UNUSED,
                            char *cpumask ATTRIBUTE_UNUSED,
                            size_t mask_size ATTRIBUTE_UNUSED) {
  return ERR_NOT_SUPPORTED;
}

zt_thread_t zt_thread_self(void) { return zt_thread_t_null; }

int zt_thread_equal(zt_thread_t *t1 ATTRIBUTE_UNUSED, zt_thread_t *t2 ATTRIBUTE_UNUSED) {
  return 0;
}
