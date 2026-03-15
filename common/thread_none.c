/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * thread_none.c
 */

#include "common/thread.h"

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

zt_thread_t zt_thread_self(void) { return (zt_thread_t){0}; }

int zt_thread_equal(zt_thread_t *t1 ATTRIBUTE_UNUSED, zt_thread_t *t2 ATTRIBUTE_UNUSED) {
  return 0;
}

err_t zt_mutex_init(zt_mutex_t *mtx ATTRIBUTE_UNUSED) { return ERR_NOT_SUPPORTED; }

err_t zt_mutex_init_recursive(zt_mutex_t *mtx ATTRIBUTE_UNUSED) {
  return ERR_NOT_SUPPORTED;
}

void zt_mutex_destroy(zt_mutex_t *mtx ATTRIBUTE_UNUSED) { return; }

void zt_mutex_lock(zt_mutex_t *mtx ATTRIBUTE_UNUSED) { return; }

void zt_mutex_unlock(zt_mutex_t *mtx ATTRIBUTE_UNUSED) { return; }

err_t zt_rwlock_init(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) { return ERR_NOT_SUPPORTED; }

void zt_rwlock_destroy(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) { return; }

void zt_rwlock_rdlock(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) { return; }

err_t zt_rwlock_tryrdlock(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) {
  return ERR_NOT_SUPPORTED;
}

void zt_rwlock_rdunlock(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) { return; }

void zt_rwlock_wrlock(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) { return; }

err_t zt_rwlock_trywrlock(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) {
  return ERR_NOT_SUPPORTED;
}

void zt_rwlock_wrunlock(zt_rwlock_t *rwlock ATTRIBUTE_UNUSED) { return; }

void zt_once(zt_once_t *ctrl ATTRIBUTE_UNUSED, void (*callback)(void) ATTRIBUTE_UNUSED) {
  return;
}

err_t zt_cond_init(zt_cond_t *cond ATTRIBUTE_UNUSED) { return ERR_NOT_SUPPORTED; }

err_t zt_cond_destroy(zt_cond_t *cond ATTRIBUTE_UNUSED) { return ERR_NOT_SUPPORTED; }

void zt_cond_signal(zt_cond_t *cond ATTRIBUTE_UNUSED) { return; }

void zt_cond_broadcast(zt_cond_t *cond ATTRIBUTE_UNUSED) { return; }

void zt_cond_wait(zt_cond_t *cond ATTRIBUTE_UNUSED, zt_mutex_t *mutex ATTRIBUTE_UNUSED) {
  return;
}

err_t zt_cond_timedwait(zt_cond_t *cond ATTRIBUTE_UNUSED,
                        zt_mutex_t *mutex ATTRIBUTE_UNUSED,
                        uint64_t timeout_usec ATTRIBUTE_UNUSED) {
  return ERR_NOT_SUPPORTED;
}
