#include "prompts.h"
#include "defines.h"

#define CAUTIONPROMPT(desc, prompt)                                            \
  ("\x1b[1;31mCAUTION! " desc "\x1b[0m" prompt)

#define STATUSPROMPT(prompt) ("\x1b[1;35m" prompt "\x1b[0m")

static const char *cli_prompts[] = {
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
    [OnPasswdFileExists] =
        CAUTIONPROMPT("The password file already exists.\n",
                      "Are you sure you want to overwrite it? [Y/n] "),
    [OnPasswdFileTryDelete] = CAUTIONPROMPT(
        "This will permanently delete all passwords from selected file.\n",
        "Are you sure you want to proceed? [Y/n] "),
    [OnServerListening] = STATUSPROMPT(
        "Listening for connections... Your correspondent may now send you a "
        "file using the \'zerotunnel send\' command.\n"
        "(address=%s, port=%s, Id=%x)\n"),
    [OnNewK0Password] = "\nNew password: %s\n",
    [OnNewK1PasswordFile] = "\nPassword bundle saved to %s\n",
    [OnNewK2Password] =
        "Session password: %s\nThis password is only valid for the current "
        "session, securely deliver it to your correspondent.",
    [OnSendSuccessful] = "File sent successfully.\n",
    [OnReceiveSuccessful] = "File saved to %s.\n",
};

const char *get_cli_prompt(prompt_t prompt) {
  if (prompt >= 0 && prompt < COUNTOF(cli_prompts))
    return cli_prompts[prompt];
  return NULL;
}

#undef CAUTIONPROMPT
