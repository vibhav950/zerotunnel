#pragma once

#define CAUTIONPROMPT(desc, prompt)                                            \
  ("\x1b[1;31mCAUTION! " desc "\x1b[0m" prompt)

#define STATUSPROMPT(prompt) ("\x1b[1;35m" prompt "\x1b[0m")

enum {
  /** User input required */
  OnBadPasswdIdentifier,
  OnPossibleIncorrectPasswdAttempt,
  OnFileTransferRequest,
  /** Report status */
  OnServerListening,
};

const char *g_CLIPrompts[] = {
    [OnBadPasswdIdentifier] = CAUTIONPROMPT(
        "Handshake failed... either the password bundle is out-of-sync/has "
        "been tampered with, or this is a possible Man-In-The-Middle attack.\n",
        "Do you want to retry? [Y/n] "),
    [OnPossibleIncorrectPasswdAttempt] = CAUTIONPROMPT(
        "Handshake failed... either you or your correspondent "
        "entered incorrect credentials, or this is a possible "
        "Man-In-The-Middle attack and the attacker guessed wrong.\n",
        "Do you want to retry? [Y/n] "),
    [OnFileTransferRequest] = "Accept this file transfer? [Y/n] ",
    [OnServerListening] = STATUSPROMPT(
        "Listening for connections... Your correspondent may now send you a "
        "file using the \'zerotunnel send\' command.\n"),
};

#undef CAUTIONPROMPT
