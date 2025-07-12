#pragma once

#define CAUTIONPROMPT(desc, prompt)                                            \
  ("\x1b[1;31mCAUTION! " desc "\x1b[0m" prompt)

#define STATUSPROMPT(prompt) ("\x1b[1;35m" prompt "\x1b[0m")

enum {
  /** User input required */
  HandshakeRetryYesNo,
  HandshakeRestartYesNo,
  /** Report status */
  ServerListening,
};

const char *g_CLIPrompts[] = {
    [HandshakeRetryYesNo] = CAUTIONPROMPT(
        "Password verification failed... either the password bundle is "
        "out-of-sync or this is a possible Man-In-The-Middle attack.\n",
        "Do you want to retry? [Y/n] "),
    [HandshakeRestartYesNo] = CAUTIONPROMPT(
        "Handshake failed... either your correspondent typed the password "
        "wrong or this is a possible Man-In-The-Middle attack.\n",
        "Do you want to retry? [Y/n] "),
    [ServerListening] = STATUSPROMPT(
        "Listening for connections... Your correspondent may now send you a "
        "file using the \'zerotunnel send\' command.\n"),
};

#undef CAUTIONPROMPT
