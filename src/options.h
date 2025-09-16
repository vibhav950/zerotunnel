/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * options.h
 */

#pragma once

#include <stdlib.h>

typedef enum {
  EXIT_STATUS_SUCCESS = EXIT_SUCCESS,
  EXIT_STATUS_FAILED_INIT = 1,
  EXIT_STATUS_GENERIC = 2,
  EXIT_STATUS_BAD_PARSE = 3,
} exit_status_t;

typedef enum {
  cmdNone = (0UL),
  cmdSend = (1UL << 0),
  cmdReceive = (1UL << 1),
  cmdPassgen = (1UL << 2),
  cmdPassdel = (1UL << 3),
} command_t;

void set_exit_status(exit_status_t status);

exit_status_t get_exit_status(void);

command_t init_config(int argc, char *argv[]);

void deinit_config(void);
