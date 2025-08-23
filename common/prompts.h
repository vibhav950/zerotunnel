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
} prompt_t;

/** Returns a CLI prompt string */
const char *get_cli_prompt(prompt_t prompt);
