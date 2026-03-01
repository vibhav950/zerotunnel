#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>

#include "common/defines.h"
#include "common/log.h"
#include "common/thread.h"

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
  return rv ? ERR_INTERNAL : ERR_SUCCESS;
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
