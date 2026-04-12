/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2026 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * threadpool.c -- asynchronous worker pool
 */

#include "common/threadpool.h"
#include "common/mpmcq.h"
#include "common/sem.h"
#include "common/thread.h"

#include <stdlib.h>

#define MAX_THREADPOOL_WORKERS 512
#define DEFAULT_THREADPOOL_WORKERS 8
#define WORK_QUEUE_CAPACITY 512

struct work_st {
  err_t (*work_cb)(struct work_st *work);
  void (*after_work_cb)(struct work_st *work, err_t status);
  void *data;
  uint32_t reserved;
};

enum {
  /* shutdown after all pending work (including queued work) is complete */
  shutdown_type_graceful = 1,
  /* shutdown after all ongoing work is complete, ignore queued work */
  shutdown_type_hard,
};

static zt_once_t once = ZT_ONCE_INIT;
static zt_cond_t cond;
static zt_mutex_t mutex;
static mpmc_queue_t work_queue;
static unsigned int num_workers;
static unsigned int idle_workers;
static volatile int shutdown;
static zt_thread_t **workers;
static zt_thread_t *default_workers[DEFAULT_THREADPOOL_WORKERS];

static int worker(void *arg) {
  struct work_st *work;
  mpmc_queue_t *wq;
  err_t err;

  zt_sem_post((zt_sem_t *)arg);
  arg = NULL;

  for (;;) {
    if (shutdown == shutdown_type_hard) {
      zt_cond_signal(&cond);
      break;
    }

    zt_mutex_lock(&mutex);

    while (mpmc_queue_dequeue(&wq, (void **)work, MPMC_Q_FAIL_IMMEDIATELY) == -1) {
      /** stop worker if a graceful shutdown is scheduled and there is no pending work */
      if (shutdown == shutdown_type_graceful) {
        zt_cont_signal(&cond);
        zt_mutex_unlock(&mutex);
        break;
      }

      idle_workers += 1;
      zt_cond_wait(&cond, &mutex);
      idle_workers -= 1;
    }

    zt_mutex_unlock(&mutex);

    err = work->work_cb(work);

    if (work->after_work_cb)
      work->after_work_cb(work, err);
  }
}

static void init_threads(void) {
  char *evar;
  zt_sem_t sem;

  evar = getenv("ZT_DEFAULT_THREADPOOL_WORKERS");
  if (evar) {
    num_workers = atoi(evar);
    if (num_workers == 0)
      num_workers = 1;
    else if (num_workers > MAX_THREADPOOL_WORKERS)
      num_workers = MAX_THREADPOOL_WORKERS;
  } else {
    num_workers = DEFAULT_THREADPOOL_WORKERS;
  }

  workers = default_workers;
  if (num_workers > DEFAULT_THREADPOOL_WORKERS) {
    workers = zt_malloc(num_workers * sizeof(zt_thread_t *));
    if (workers == NULL) {
      workers = default_workers;
      num_workers = DEFAULT_THREADPOOL_WORKERS;
    }
  }

  if (zt_cond_init(&cond))
    abort();

  if (zt_mutex_init(&mutex))
    abort();

  if (mpmc_queue_init(&work_queue, 512))
    abort();

  if (zt_sem_init(&sem, 0))
    abort();

  for (int i = 0; i < num_workers; ++i)
    if (!(workers[i] = zt_thread_create(worker, PTRV(&sem), NULL, NULL)))
      abort();

  for (int i = 0; i < num_workers; ++i)
    zt_sem_wait(&sem);

  zt_sem_destroy(&sem);
}

err_t zt_work_submit(zt_work_t *work, err_t (*work_cb)(zt_work_t *work),
                     void (*after_work_cb)(zt_work_t *work, err_t status)) {
  zt_once(&once, init_threads);

  if (work == NULL)
    return ERR_NULL_PTR;

  work->work_cb = work_cb;
  work->after_work_cb = after_work_cb;

  if (mpmc_queue_enqueue(&work_queue, PTRV(work), MPMC_Q_FAIL_IMMEDIATELY) == -1)
    return ERR_AGAIN; /* queue is full */

  return ERR_SUCCESS;
}

void 