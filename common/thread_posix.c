/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * thread_posix.c -- the POSIX thread backend
 *
 * Closely based on libuv's POSIX thread backend:
 * https://github.com/libuv/libuv/blob/v1.x/src/unix/thread.c
 * Modified for zerotunnel
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>

#include "common/defines.h"
#include "common/log.h"
#include "common/thread.h"
#include "common/time_utils.h"

#if defined(__linux__) || (defined(__FreeBSD__) && __FreeBSD_version >= 1301000) ||      \
    defined(__MACH__)
#define CPU_AFFINITY_SUPPORTED 1
#else
#define CPU_AFFINITY_SUPPORTED 0
#endif

#if defined(__OpenBSD__)
#include <pthread_np.h>
#endif

#if defined(__linux__) || defined(__NetBSD__)
#include <sched.h>
#define _cpu_set_t cpu_set_t
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#include <sys/cpuset.h>
#include <sys/param.h>
#define _cpu_set_t cpuset_t
#elif defined(__MACH__)
#include <mach/mach.h>
#include <mach/thread_policy.h>
#endif

#ifdef __MACH__
#define SYSCTL_CORE_COUNT "machdep.cpu.core_count"
typedef struct cpu_set {
  uint32_t count;
} cpu_set_t;

static ATTRIBUTE_ALWAYS_INLINE void CPU_ZERO(cpu_set_t *cs) { cs->count = 0; }
static ATTRIBUTE_ALWAYS_INLINE void CPU_SET(int num, cpu_set_t *cs) {
  cs->count |= (1 << num);
}
static ATTRIBUTE_ALWAYS_INLINE int CPU_ISSET(int num, cpu_set_t *cs) {
  return (cs->count & (1 << num));
}

pthread_setaffinity_np(pthread_t thread, size_t cpuset_size, cpu_set_t *cpuset) {
  thread_port_t mach_thread;
  thread_affinity_policy_data_t policy;
  int core;

  for (core = 0; core < 8 * (int)cpuset_size; core++) {
    if (CPU_ISSET(core, cpuset))
      break;
  }

  policy.affinity_tag = core;
  mach_thread = pthread_mach_thread_np(thread);
  thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1);

  return 0;
}
#endif /* __MACH__ */

struct thread_entry {
  err_t (*func)(void *);
  void *arg;
};

static void *thread_create_thunk(void *arg) {
  struct thread_entry *te = arg;
  err_t (*func)(void *) = te->func;
  void *actual_arg = te->arg;

  free(te);

  (*func)(actual_arg);

  return NULL;
}

static void ATTRIBUTE_NORETURN thread_exit(void) { pthread_exit(NULL); }

zt_thread_t *zt_thread_create(err_t (*entry)(void *arg), void *arg) {
  zt_thread_t *t;
  struct thread_entry *te;

  t = zt_calloc(1, sizeof(zt_thread_t));
  te = zt_calloc(1, sizeof(struct thread_entry));
  if (!(t && te)) {
    return NULL;
  }

  te->func = entry;
  te->arg = arg;

  if (pthread_create(t, NULL, thread_create_thunk, te))
    goto err;

  return t;

err:
  zt_free(t);
  zt_free(te);
  return zt_thread_t_null;
}

void zt_thread_destroy(zt_thread_t *t) {
  if (t != zt_thread_t_null) {
    pthread_detach(*t);
    zt_free(t);
  }
}

err_t zt_thread_join(zt_thread_t *t) {
  if (t == zt_thread_t_null)
    return ERR_NULL_PTR;
  int rv;
  rv = pthread_join(*t, NULL);
  if (rv)
    return ERR_INTERNAL;
  return ERR_SUCCESS;
}

#if CPU_AFFINITY_SUPPORTED
err_t zt_thread_setaffinity(zt_thread_t *t, char *cpumask, size_t mask_size) {
  _cpu_set_t cpuset;

  if (t == zt_thread_t_null)
    return ERR_NULL_PTR;

  if (mask_size < CPU_SETSIZE)
    return ERR_BAD_ARGS;

  CPU_ZERO(&cpuset);
  for (size_t i = 0; i < CPU_SETSIZE; i++) {
    if (cpumask[i])
      CPU_SET(i, &cpuset);
  }

  if (pthread_setaffinity_np(*t, sizeof(cpuset), &cpuset))
    return ERR_INTERNAL;

  return ERR_SUCCESS;
}
#else
err_t zt_thread_setaffinity(zt_thread_t *t ATTRIBUTE_UNUSED,
                            char *cpumask ATTRIBUTE_UNUSED,
                            size_t mask_size ATTRIBUTE_UNUSED) {
  return ERR_NOT_SUPPORTED;
}
#endif /* CPU_AFFINITY_SUPPORTED */

zt_thread_t zt_thread_self(void) { return pthread_self(); }

int zt_thread_equal(zt_thread_t *t1, zt_thread_t *t2) {
  if (t1 == zt_thread_t_null || t2 == zt_thread_t_null)
    return 0;
  return pthread_equal(*t1, *t2);
}

err_t zt_mutex_init(zt_mutex_t *mtx) {
#if defined(NODEBUG) || !defined(PTHREAD_MUTEX_ERRORCHECK)
  if (pthread_mutex_init(mtx, NULL))
    return ERR_INTERNAL;
  return ERR_SUCCESS;
#else
  pthread_mutexattr_t attr;
  int rv;

  rv = pthread_mutexattr_init(&attr);
  if (rv)
    return ERR_INTERNAL;

  rv = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
  if (rv) {
    pthread_mutexattr_destroy(&attr);
    return ERR_INTERNAL;
  }

  rv = pthread_mutex_init(mtx, &attr);
  pthread_mutexattr_destroy(&attr);
  if (rv)
    return ERR_INTERNAL;
  return ERR_SUCCESS;
#endif
}

err_t zt_mutex_init_recursive(zt_mutex_t *mtx) {
  pthread_mutexattr_t attr;
  int rv;

  rv = pthread_mutexattr_init(&attr);
  if (rv)
    return ERR_INTERNAL;

  rv = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  if (rv) {
    pthread_mutexattr_destroy(&attr);
    return ERR_INTERNAL;
  }

  rv = pthread_mutex_init(mtx, &attr);
  pthread_mutexattr_destroy(&attr);
  if (rv)
    return ERR_INTERNAL;
  return ERR_SUCCESS;
}

void zt_mutex_destroy(zt_mutex_t *mtx) {
  if (pthread_mutex_destroy(mtx))
    thread_exit();
}

void zt_mutex_lock(zt_mutex_t *mtx) {
  if (pthread_mutex_lock(mtx))
    thread_exit();
}

void zt_mutex_unlock(zt_mutex_t *mtx) {
  if (pthread_mutex_unlock(mtx))
    thread_exit();
}

err_t zt_rwlock_init(zt_rwlock_t *rwlock) {
  if (pthread_rwlock_init(rwlock, NULL))
    return ERR_INTERNAL;
  return ERR_SUCCESS;
}

void zt_rwlock_destroy(zt_rwlock_t *rwlock) {
  if (pthread_rwlock_destroy(rwlock))
    thread_exit();
}

void zt_rwlock_rdlock(zt_rwlock_t *rwlock) {
  if (pthread_rwlock_rdlock(rwlock))
    thread_exit();
}

err_t zt_rwlock_tryrdlock(zt_rwlock_t *rwlock) {
  int rv;

  rv = pthread_rwlock_tryrdlock(rwlock);
  if (rv) {
    if (rv == EBUSY || rv == EAGAIN)
      return ERR_AGAIN;
    else
      thread_exit();
  }
  return ERR_SUCCESS;
}

void zt_rwlock_rdunlock(zt_rwlock_t *rwlock) {
  if (pthread_rwlock_unlock(rwlock))
    thread_exit();
}

void zt_rwlock_wrlock(zt_rwlock_t *rwlock) {
  if (pthread_rwlock_wrlock(rwlock))
    thread_exit();
}

err_t zt_rwlock_trywrlock(zt_rwlock_t *rwlock) {
  int rv;

  rv = pthread_rwlock_trywrlock(rwlock);
  if (rv) {
    if (rv == EBUSY || rv == EAGAIN)
      return ERR_AGAIN;
    else
      thread_exit();
  }
  return ERR_SUCCESS;
}

void zt_rwlock_wrunlock(zt_rwlock_t *rwlock) {
  if (pthread_rwlock_unlock(rwlock))
    thread_exit();
}

void zt_once(zt_once_t *ctrl, void (*callback)(void)) {
  if (pthread_once(ctrl, callback))
    thread_exit();
}

#if defined(__APPLE__) && defined(__MACH__)
err_t zt_cond_init(zt_cond_t *cond) {
  if (pthread_cond_init(cond, NULL))
    return ERR_INTERNAL;
  return ERR_SUCCESS;
}
#else
err_t zt_cond_init(zt_cond_t *cond) {
  pthread_condattr_t attr;
  int rv;

  rv = pthread_condattr_init(&attr);
  if (rv)
    return ERR_INTERNAL;

  rv = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (rv)
    goto err1;

  rv = pthread_cond_init(cond, &attr);
  if (rv)
    goto err1;

  rv = pthread_condattr_destroy(&attr);
  if (rv)
    goto err0;

  return ERR_SUCCESS;

err0:
  pthread_cond_destroy(cond);
err1:
  pthread_condattr_destroy(&attr);
  return ERR_INTERNAL;
}
#endif /* defined(__APPLE__) && defined(__MACH__) */

err_t zt_cond_destroy(zt_cond_t *cond) {
#if defined(__APPLE__) && defined(__MACH__)
  /** Ref: function uv_cond_destroy in
   * https://github.com/libuv/libuv/blob/v1.x/src/unix/thread.c */
  /* It has been reported that destroying condition variables that have been
   * signalled but not waited on can sometimes result in application crashes.
   * See https://codereview.chromium.org/1323293005.
   */
  pthread_mutex_t mutex;
  struct timespec ts;
  int rv;

  if (pthread_mutex_init(&mutex, NULL))
    abort();

  if (pthread_mutex_lock(&mutex))
    abort();

  ts.tv_sec = 0;
  ts.tv_nsec = 1;

  rv = pthread_cond_timedwait_relative_np(cond, &mutex, &ts);
  if (rv != 0 && rv != ETIMEDOUT)
    pthread_abort();

  if (pthread_mutex_unlock(&mutex))
    pthread_abort();

  if (pthread_mutex_destroy(&mutex))
    pthread_abort();
#else
  if (pthread_cond_destroy(cond))
    thread_exit();
#endif /* defined(__APPLE__) && defined(__MACH__) */
}

void zt_cond_signal(zt_cond_t *cond) {
  if (pthread_cond_signal(cond))
    thread_exit();
}

void zt_cond_broadcast(zt_cond_t *cond) {
  if (pthread_cond_broadcast(cond))
    thread_exit();
}

#if defined(__APPLE__) && defined(__MACH__)
void zt_cond_wait(zt_cond_t *cond, zt_mutex_t *mutex) {
  int rv;

  errno = 0;
  rv = pthread_cond_wait(cond, mutex);

  if (rv = EINVAL)
    if (errno = EBUSY)
      return;

  if (rv)
    thread_exit();
}
#else
void zt_cond_wait(zt_cond_t *cond, zt_mutex_t *mutex) {
  if (pthread_cond_wait(cond, mutex))
    thread_exit();
}
#endif /* defined(__APPLE__) && defined(__MACH__) */

err_t zt_cond_timedwait(zt_cond_t *cond, zt_mutex_t *mutex, uint64_t timeout_usec) {
  int rv;
  struct timespec ts;
#if defined(__APPLE__) && defined(__MACH__)
  ts.tv_sec = timeout_usec / 1000000;
  ts.tv_nsec = (timeout_usec * 1000) % 1000000000;
  rv = pthread_cond_timedwait_relative_np(cond, mutex, &ts);
#else
  timeval_t now;
  timediff_t diff_usec;

  now = zt_time_now();

  diff_usec = ((timediff_t)now.tv_sec * 1000000) + now.tv_usec;
  if (!((diff_usec + timeout_usec) * 1000 > diff_usec))
    thread_exit();
  diff_usec += timeout_usec;

  ts.tv_sec = diff_usec / 1000000;
  ts.tv_nsec = (diff_usec * 1000) % 1000000000;

  rv = pthread_cond_timedwait(cond, mutex, &ts);
#endif

  if (rv == 0)
    return ERR_SUCCESS;

  if (rv == ETIMEDOUT)
    return ERR_TIMEOUT;

  thread_exit();
  return ERR_INVALID; /* Satisfy the compiler. */
}
