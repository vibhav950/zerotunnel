#pragma once

typedef enum {
  /* Interaction required */
  OnBadPasswdIdentifier,
  OnPossibleIncorrectPasswdAttempt,
  OnFileTransferRequest,
  OnPasswdFileExists,
  OnPasswdFileTryDelete,
  /* Report status */
  OnServerListening,
  /* Miscellaneous */
  OnNewK0Password,
  OnNewK1PasswordFile,
  OnNewK2Password,
  OnSendSuccessful,
  OnReceiveSuccessful,
} prompt_t;

/** Returns a CLI prompt string */
const char *get_cli_prompt(prompt_t prompt);
