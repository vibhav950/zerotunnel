/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * sem.h - Platform-dependent semaphore
 */

#ifndef __SEM_H__
#define __SEM_H__

#include "defines.h"

#include <features.h>

#if defined(_WIN32)
#include <Windows.h>
#define PLATFORM_SEM_T HANDLE
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) ||               \
    defined(__OpenBSD__)
#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 22)
#include <semaphore.h>
#define PLATFORM_SEM_T sem_t
#else /* defined(__GLIBC__) && __GLIBC_PREREQ(2, 22) */
#define PLATFORM_SEM_T struct custom_sem_st *
#endif
#elif defined(__APPLE__) && defined(__MACH__)
#include <mach/semaphore.h>
#include <mach/task.h>
#define PLATFORM_SEM_T semaphore_t
#else
#error "unsupported platform"
#endif

typedef PLATFORM_SEM_T zt_sem_t;
#undef PLATFORM_SEM_T

err_t zt_sem_init(zt_sem_t *sem, unsigned int value);

void zt_sem_destroy(zt_sem_t *sem);

void zt_sem_post(zt_sem_t *sem);

void zt_sem_wait(zt_sem_t *sem);

err_t zt_sem_trywait(zt_sem_t *sem);

#endif /* __SEM_H__ */
