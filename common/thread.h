#ifndef __THREAD_H__
#define __THREAD_H__

#include "common/defines.h"

#if defined(HAVE_POSIX_THREADS)
#include <pthread.h>
#define zt_thread_t pthread_t
#define zt_mutex_t pthread_mutex_t
#define zt_rwlock_t pthread_rwlock_t
#define zt_once_t pthread_once_t

#define zt_thread_t_null NULL
#else
struct thread_noapi_st {};
typedef struct thread_noapi_st zt_thread_t;
typedef struct thread_noapi_st zt_mutex_t;
typedef struct thread_noapi_st zt_rwlock_t;
typedef struct thread_noapi_st zt_once_t;

#define zt_thread_t_null NULL
#endif

zt_thread_t *zt_thread_create(int (*entry)(void *arg), void *arg);

void zt_thread_destroy(zt_thread_t *t);

err_t zt_thread_join(zt_thread_t *t);

err_t zt_thread_setaffinity(zt_thread_t *t, char *cpumask, size_t mask_size);

zt_thread_t zt_thread_self(void);

int zt_thread_equal(zt_thread_t *t1, zt_thread_t *t2);

err_t zt_mutex_init(zt_mutex_t *mtx);

err_t zt_mutex_init_recursive(zt_mutex_t *mtx);

void zt_mutex_destroy(zt_mutex_t *mtx);

void zt_mutex_lock(zt_mutex_t *mtx);

void zt_mutex_unlock(zt_mutex_t *mtx);

#endif /* __THREAD_H__ */
