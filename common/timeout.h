/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * timeout.h
 */

#ifndef __TIMEOUT_H__
#define __TIMEOUT_H__

#include "time_utils.h"

typedef void (*timeout_cb)(void *args);

typedef struct _zt_timeout_st {
  timeval_t begin;
  timediff_t expire_in_usec;
  timeout_cb handler;
} zt_timeout_t;

/**
 * Set a timeout now
 */
void zt_timeout_begin(zt_timeout_t *timeout, timediff_t usec, timeout_cb handler);

/**
 * Reset the timeout
 *
 * This function should only be called after a timeout has already been set
 * using zt_timeout_begin()
 */
void zt_timeout_reset(zt_timeout_t *timeout);

/**
 * Check if the timeout has expired
 *
 * This function should only be called after a timeout has already been set
 * using zt_timeout_begin()
 *
 * Returns 1 if the timeout has expired, 0 otherwise
 */
int zt_timeout_expired(zt_timeout_t *timeout, void *args);

#endif /* __TIMEOUT_H__ */
