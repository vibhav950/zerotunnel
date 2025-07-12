#pragma once

#define CAUTIONPROMPT(desc, prompt)                                            \
  ("\x1b[1;31mCAUTION! " desc "\x1b[0m" prompt)

enum {
  HandshakeRetryYesNo,
  HandshakeRestartYesNo,
};

const char *g_Prompts[] = {
    [HandshakeRetryYesNo] = CAUTIONPROMPT(
        "Password verification failed... either the password bundle is "
        "out-of-sync or this is a possible Man-In-The-Middle attack.\n",
        "Do you want to retry? (Y/n): "),
    [HandshakeRestartYesNo] = CAUTIONPROMPT(
        "Handshake failed... either your correspondent typed the password "
        "wrong or this is a possible Man-In-The-Middle attack.\n",
        "Do you want to retry? (Y/n): "),
};

#undef CAUTIONPROMPT
