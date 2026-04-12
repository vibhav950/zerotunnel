/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * sem.c - Platform-dependent semaphore
 *
 * Based off the implementation by the libuv authors,
 * available at https://github.com/libuv/libuv/
 */

#include "common/sem.h"
#include "common/thread.h"

#include <errno.h>
#include <error.h>

#if defined(_WIN32)

err_t zt_sem_init(zt_sem_t *sem, unsigned int value) {
  if (!sem)
    return ERR_NULL_PTR;

  *sem = CreateSemaphore(NULL, value, INT_MAX, NULL);
  if (*sem == NULL)
    return ERR_INTERNAL;
  else
    return ERR_SUCCESS;
}

void zt_sem_destroy(zt_sem_t *sem) {
  if (!CloseHandle(*sem))
    abort();
}

void zt_sem_post(zt_sem_t *sem) {
  if (!ReleaseSemaphore(*sem, 1, NULL))
    abort();
}

void zt_sem_wait(zt_sem_t *sem) {
  if (WaitForSingleObject(*sem, INFINITE) != WAIT_OBJECT_0)
    abort();
}

err_t zt_sem_trywait(zt_sem_t *sem) {
  DWORD rv;

  rv = WaitForSingleObject(*sem, 0);
  switch (rv) {
  case WAIT_OBJECT_0:
    return ERR_SUCCESS;
  case WAIT_TIMEOUT:
    return ERR_AGAIN;
  default:
    abort();
    return -1; /* Satisfy the compiler. */
  }
}

#elif defined(__APPLE__) && defined(__MACH__)

err_t zt_sem_init(zt_sem_t *sem, unsigned int value) {
  kern_return_t err;

  err = semaphore_create(mach_task_self(), sem, SYNC_POLICY_FIFO, value);
  if (err == KERN_SUCCESS)
    return ERR_SUCCESS;
  if (err == KERN_INVALID_ARGUMENT)
    return ERR_BAD_ARGS;
  if (err == KERN_RESOURCE_SHORTAGE)
    return ERR_MEM_FAIL;

  abort();
  return -1; /* Satisfy the compiler. */
}

void zt_sem_destroy(zt_sem_t *sem) {
  if (semaphore_destroy(mach_task_self(), *sem))
    abort();
}

void zt_sem_post(zt_sem_t *sem) {
  if (semaphore_signal(*sem))
    abort();
}

void zt_sem_wait(zt_sem_t *sem) {
  int r;

  do
    r = semaphore_wait(*sem);
  while (r == KERN_ABORTED);

  if (r != KERN_SUCCESS)
    abort();
}

err_t zt_sem_trywait(zt_sem_t *sem) {
  mach_timespec_t interval;
  kern_return_t err;

  interval.tv_sec = 0;
  interval.tv_nsec = 0;

  err = semaphore_timedwait(*sem, interval);
  if (err == KERN_SUCCESS)
    return ERR_SUCCESS;
  if (err == KERN_OPERATION_TIMED_OUT)
    return ERR_AGAIN;

  abort();
  return -1; /* Satisfy the compiler. */
}

#else /* !(defined(__APPLE__) && defined(__MACH__)) */

#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 22)

#define platform_needs_custom_semaphore 0

static err_t sem_init_(zt_sem_t *sem, unsigned int value) {
  if (sem_init(sem, 0, value))
    return ERR_INTERNAL;
  return ERR_SUCCESS;
}

static void sem_destroy_(zt_sem_t *sem) {
  if (sem_destroy(sem))
    abort();
}

static void sem_post_(zt_sem_t *sem) {
  if (sem_post(sem))
    abort();
}

static void sem_wait_(zt_sem_t *sem) {
  int rv;

  do
    rv = sem_wait(sem);
  while (rv == -1 && errno == EINTR);

  if (rv)
    abort();
}

static err_t sem_trywait_(zt_sem_t *sem) {
  int rv;

  do
    rv = sem_trywait(sem);
  while (rv == -1 && errno == EINTR);

  if (rv) {
    if (errno == EAGAIN)
      return ERR_AGAIN;
    abort();
  }
  return ERR_SUCCESS;
}

#else /* defined(__GLIBC__) && __GLIBC_PREREQ(2, 22) */

#define platform_needs_custom_semaphore 1

struct custom_sem_st {
  zt_mutex_t mutex;
  zt_cond_t cond;
  unsigned int value;
};

static err_t custom_sem_init(zt_sem_t *sem_, unsigned int value) {
  struct custom_sem_st *sem;
  int rv;

  if (unlikely(!sem_))
    return ERR_NULL_PTR;

  if ((sem = zt_calloc(1, sizeof(struct custom_sem_st))) == NULL)
    return ERR_MEM_FAIL;

  if ((rv = zt_mutex_init(&sem->mutex)) != ERR_SUCCESS) {
    zt_free(sem);
    return rv;
  }

  if ((rv = zt_cond_init(&sem->cond)) != ERR_SUCCESS) {
    zt_free(sem);
    return rv;
  }

  sem->value = value;
  *(struct custom_sem_st **)sem_ = sem;
  return ERR_SUCCESS;
}

static void custom_sem_destroy(zt_sem_t *sem_) {
  struct custom_sem_st *sem;

  if (unlikely(!sem_))
    return;

  sem = *sem_;

  zt_mutex_destroy(&sem->mutex);
  zt_cond_destroy(&sem->cond);
  zt_free(sem);
  *sem_ = NULL;
}

static void custom_sem_post(zt_sem_t *sem_) {
  struct custom_sem_st *sem;

  sem = *(struct custom_sem_st **)sem_;
  zt_mutex_lock(&sem->mutex);
  sem->value++;
  if (sem->value == 1)
    zt_cond_signal(&sem->cond);
  zt_mutex_unlock(&sem->mutex);
}

static void custom_sem_wait(zt_sem_t *sem_) {
  struct custom_sem_st *sem;

  sem = *(struct custom_sem_st **)sem_;
  zt_mutex_lock(&sem->mutex);
  while (sem->value == 0)
    zt_cond_wait(&sem->cond, &sem->mutex);
  sem->value--;
  zt_mutex_unlock(&sem->mutex);
}

static void custom_sem_trywait(zt_sem_t *sem_) {
  struct custom_sem_st *sem;

  sem = *(struct custom_sem_st **)sem_;
  if (zt_mutex_trylock(&sem->mutex) != ERR_SUCCESS)
    return ERR_AGAIN;

  if (sem->value == 0) {
    zt_mutex_unlock(&sem->mutex);
    return ERR_AGAIN;
  }

  sem->value--;
  zt_mutex_unlock(&sem->mutex);
  return ERR_SUCCESS;
}

#endif /* defined(__GLIBC__) && __GLIBC_PREREQ(2, 22) */

err_t zt_sem_init(zt_sem_t *sem, unsigned int value) {
#if (platform_needs_custom_semaphore)
  return custom_sem_init(sem, value);
#else
  return sem_init_(sem, value);
#endif
}

void zt_sem_destroy(zt_sem_t *sem) {
#if (platform_needs_custom_semaphore)
  custom_sem_destroy(sem);
#else
  sem_destroy_(sem);
#endif
}

void zt_sem_post(zt_sem_t *sem) {
#if (platform_needs_custom_semaphore)
  custom_sem_post(sem);
#else
  sem_post_(sem);
#endif
}

void zt_sem_wait(zt_sem_t *sem) {
#if (platform_needs_custom_semaphore)
  custom_sem_wait(sem);
#else
  sem_wait_(sem);
#endif
}

err_t zt_sem_trywait(zt_sem_t *sem) {
#if (platform_needs_custom_semaphore)
  custom_sem_trywait(sem);
#else
  sem_trywait_(sem);
#endif
}

#endif /* defined(__APPLE__) && defined(__MACH__) */
