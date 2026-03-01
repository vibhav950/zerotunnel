#ifndef __THREAD_H__
#define __THREAD_H__

#include "common/defines.h"

#if defined(HAVE_POSIX_THREADS)
#include <pthread.h>
#define zt_thread_t pthread_t
#define zt_thread_t_null NULL
#else
typedef struct _zt_thread_noapi_st *zt_thread_t;
#define zt_thread_t_null NULL
#endif

zt_thread_t *zt_thread_create(int (*entry)(void *arg), void *arg);

void zt_thread_destroy(zt_thread_t *t);

err_t zt_thread_join(zt_thread_t *t);

err_t zt_thread_setaffinity(zt_thread_t *t, char *cpumask, size_t mask_size);

zt_thread_t zt_thread_self(void);

int zt_thread_equal(zt_thread_t *t1, zt_thread_t *t2);

#endif /* __THREAD_H__ */
