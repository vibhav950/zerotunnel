/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * prompts.h
 */

#pragma once

typedef enum {
  /* Interaction required */
  OnBadPasswdIdentifier,
  OnIncorrectPasswdAttempt,
  OnFileTransferRequest,
  OnPasswdFileExists,
  OnPasswdFileTryDelete,
  /* Report status */
  OnServerListening,
  OnAuthTypeMismatch,
  OnIncomingTransfer,
  OnIncomingLiveRead,
  OnNewK0Password,
  OnNewK1PasswordFile,
  OnNewK2Password,
  OnSendSuccessful,
  OnReceiveSuccessful,
  OnSendFailure,
  OnReceiveFailure
} prompt_t;

/** Returns a CLI prompt string */
const char *get_cli_prompt(prompt_t prompt);
