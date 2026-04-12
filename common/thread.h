/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2026 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * thread.c -- thread utilities
 */

#ifndef __THREAD_H__
#define __THREAD_H__

#include "common/defines.h"

#if defined(HAVE_POSIX_THREADS)

#include <pthread.h>

#define zt_thread_t pthread_t
#define zt_mutex_t pthread_mutex_t
#define zt_rwlock_t pthread_rwlock_t
#define zt_once_t pthread_once_t
#define zt_cond_t pthread_cond_t

#define zt_thread_t_null NULL
#define ZT_ONCE_INIT PTHREAD_ONCE_INIT

#else /* !defined(HAVE_POSIX_THREADS) */

struct thread_noapi_st {};

typedef struct thread_noapi_st zt_thread_t;
typedef struct thread_noapi_st zt_mutex_t;
typedef struct thread_noapi_st zt_rwlock_t;
typedef struct thread_noapi_st zt_once_t;
typedef struct thread_noapi_st zt_cond_t;

#define zt_thread_t_null NULL
#define ZT_ONCE_INIT {}

#endif /* defined(HAVE_POSIX_THREADS) */

zt_thread_t *zt_thread_create(err_t (*entry)(void *arg), void *arg,
                              void (*on_error_cb)(err_t, void *cbdata), void *cbdata);

void zt_thread_destroy(zt_thread_t *t);

err_t zt_thread_join(zt_thread_t *t);

err_t zt_thread_setaffinity(zt_thread_t *t, char *cpumask, size_t mask_size);

zt_thread_t zt_thread_self(void);

int zt_thread_equal(zt_thread_t *t1, zt_thread_t *t2);

err_t zt_mutex_init(zt_mutex_t *mtx);

err_t zt_mutex_init_recursive(zt_mutex_t *mtx);

void zt_mutex_destroy(zt_mutex_t *mtx);

void zt_mutex_lock(zt_mutex_t *mtx);

err_t zt_mutex_trylock(zt_mutex_t *mtx);

void zt_mutex_unlock(zt_mutex_t *mtx);

err_t zt_rwlock_init(zt_rwlock_t *rwlock);

void zt_rwlock_destroy(zt_rwlock_t *rwlock);

void zt_rwlock_rdlock(zt_rwlock_t *rwlock);

err_t zt_rwlock_tryrdlock(zt_rwlock_t *rwlock);

void zt_rwlock_rdunlock(zt_rwlock_t *rwlock);

void zt_rwlock_wrlock(zt_rwlock_t *rwlock);

err_t zt_rwlock_trywrlock(zt_rwlock_t *rwlock);

void zt_rwlock_wrunlock(zt_rwlock_t *rwlock);

void zt_once(zt_once_t *ctrl, void (*callback)(void));

err_t zt_cond_init(zt_cond_t *cond);

err_t zt_cond_destroy(zt_cond_t *cond);

void zt_cond_signal(zt_cond_t *cond);

void zt_cond_broadcast(zt_cond_t *cond);

void zt_cond_wait(zt_cond_t *cond, zt_mutex_t *mutex);

err_t zt_cond_timedwait(zt_cond_t *cond, zt_mutex_t *mutex, uint64_t timeout_usec);

#endif /* __THREAD_H__ */
