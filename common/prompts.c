#include "prompts.h"
#include "defines.h"

#define RED_FG "\033[38;5;196m"
#define PURPLE_FG "\033[38;5;211m"

#define CLEAR "\033[0m"

#define CAUTIONPROMPT(prompt, ...) (RED_FG "CAUTION! " prompt CLEAR __VA_ARGS__)

#define GENERICPROMPT(prompt) (PURPLE_FG prompt CLEAR)

#define ALERTPROMPT(prompt) (RED_FG prompt CLEAR)

static const char *cli_prompts[] = {
    [OnBadPasswdIdentifier] =
        CAUTIONPROMPT("\nHandshake failed... either the password bundle is "
                      "out-of-sync or this is a possible Man-In-The-Middle "
                      "attack and the attacker guessed wrong.",
                      "Do you want to retry? [Y/n] "),
    [OnIncorrectPasswdAttempt] = CAUTIONPROMPT(
        "\nHandshake failed... either you or your correspondent "
        "entered incorrect credentials, or this is a possible "
        "Man-In-The-Middle attack and the attacker guessed wrong.\n",
        "Do you want to retry? [Y/n] "),
    [OnFileTransferRequest] =
        GENERICPROMPT("\nAccept this file transfer? [Y/n] "),
    [OnPasswdFileExists] =
        CAUTIONPROMPT("\nA file with that name already exists.\n",
                      "Are you sure you want to overwrite it? [Y/n] "),
    [OnPasswdFileTryDelete] = CAUTIONPROMPT(
        "\nThis will permanently delete all passwords from selected file.\n",
        "Are you sure you want to proceed? [Y/n] "),
    [OnServerListening] =
        GENERICPROMPT("\nListening for connections... Your correspondent may "
                      "now initiate the transfer.\n"
                      "(Address=%s, Port=%s, Id=%08x...)\n"),
    [OnAuthTypeMismatch] =
        CAUTIONPROMPT("\nMismatch in authentication type... cannot proceed.\n"),
    [OnIncomingTransfer] =
        GENERICPROMPT("\nIncoming file transfer (name = %s, size = %jd %s)\n"),
    [OnNewK0Password] = GENERICPROMPT("\nNew password: %s\n Your correspondent "
                                      "must enter the same password."),
    [OnNewK1PasswordFile] = GENERICPROMPT("\nPassword bundle saved to %s\n"),
    [OnNewK2Password] =
        GENERICPROMPT("\nYour one-time use session password: %s\n"),
    [OnSendSuccessful] = GENERICPROMPT("File sent successfully.\n"),
    [OnReceiveSuccessful] = GENERICPROMPT("File saved to %s.\n"),
    [OnSendFailure] = ALERTPROMPT(
        "Failed to transfer file... either your correspondent declined "
        "the transfer or there was an unexpected network failure.\n"),
};

const char *get_cli_prompt(prompt_t prompt) {
  if (prompt >= 0 && prompt < COUNTOF(cli_prompts))
    return cli_prompts[prompt];
  return NULL;
}

#undef CAUTIONPROMPT
