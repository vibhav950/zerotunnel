#include "common/progressbar.h"
#include "common/prompts.h"
#include "common/tty_io.h"
#include "lib/auth.h"
#include "lib/client.h"
#include "lib/server.h"
#include "lib/ztlib.h"
#include "options.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef ZTLIB_OPEN_MAX
#define ZTLIB_OPEN_MAX 256
#endif

static volatile bool terminate;

static void entry_set_fd_limit(void) {
  struct rlimit rl;

  rl.rlim_cur = ZTLIB_OPEN_MAX;
  rl.rlim_max = ZTLIB_OPEN_MAX;
  if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
    exit(EXIT_STATUS_FAILED_INIT);
}

static int _open_devnull(int fd) {
  FILE *f = NULL;

  if (!fd)
    f = freopen(_PATH_DEVNULL, "rb", stdin);
  else if (fd == 1)
    f = freopen(_PATH_DEVNULL, "wb", stdout);
  else if (fd == 2)
    f = freopen(_PATH_DEVNULL, "wb", stderr);
  if (!f)
    return -1;
  return f && fileno(f) == fd;
}

static void entry_check_fds(void) {
  int fds;
  struct stat st;

  if ((fds = getdtablesize()) == -1)
    fds = sysconf(_SC_OPEN_MAX);

  /** Make sure all but the standards file descriptors are closed */
  for (int fd = 3; fd < fds; ++fd)
    close(fd);

  /**
   * Make sure the standard file descriptors 0, 1, and 2 (stdin, stdout, and
   * stderr) are open. If not, attempt to open them using /dev/null and exit
   * if this operation fails.
   * If these fds not open, the first three files opened by zerotunnel will be
   * used for input sources, received data or log output as these will
   * effectively act as stdin, stdout, and stderr.
   */
  for (int fd = 0; fd < 3; ++fd)
    if (fstat(fd, &st) == -1 && (errno == EBADF || !_open_devnull(fd)))
      exit(EXIT_STATUS_FAILED_INIT);
}

static void gsh(int sig) {
  switch (sig) {
  case SIGTERM:
    /* Exit on SIGTERM */
    exit(EXIT_STATUS_GENERIC);
  case SIGINT:
    /* Exit if Ctrl-C is pressed a second time */
    if (terminate)
      exit(EXIT_STATUS_GENERIC);
    terminate = true;
  case SIGWINCH:
    /* Handle window size changes */
    zt_progressbar_winsize_changed();
  }
}

static int do_send(void) {
  err_t e;
  zt_client_connection_t *client = NULL;
  bool done;

  e = zt_client_conn_alloc(&client);
  if (e != ERR_SUCCESS)
    return -1;

  e = zt_client_run(client, NULL, &done);

  if (e == ERR_SUCCESS && done)
    tty_printf(get_cli_prompt(OnSendSuccessful), GlobalConfig.filename);

  zt_client_conn_dealloc(client);

  return (e == ERR_SUCCESS && done) ? 0 : -1;
}

static int do_receive(void) {
  err_t e;
  zt_server_connection_t *server = NULL;
  bool done;

  e = zt_server_conn_alloc(&server);
  if (e != ERR_SUCCESS)
    return -1;

  e = zt_server_run(server, NULL, &done);
  if (e == ERR_SUCCESS && done) {
    if (strcmp(GlobalConfig.filename, "-"))
      tty_printf(get_cli_prompt(OnReceiveSuccessful), GlobalConfig.filename);
  }

  zt_server_conn_dealloc(server);

  return (e == ERR_SUCCESS && done) ? 0 : -1;
}

static int passgen(void) {
  if (GlobalConfig.auth_type == KAPPA_AUTHTYPE_1) {
    int fd;

    if (access(GlobalConfig.passwdfile, F_OK) == 0) {
      if (!tty_get_answer_is_yes(get_cli_prompt(OnPasswdFileExists)))
        return -1;
    }

    fd = open(GlobalConfig.passwdfile, O_RDWR | O_CREAT | O_TRUNC,
              S_IRUSR | S_IWUSR);
    if (fd < 0)
      return -1;

    if (zt_auth_passwd_db_new(fd, GlobalConfig.hostname,
                              GlobalConfig.password_chars,
                              GlobalConfig.password_bundle_size) < 0) {
      close(fd);
      return -1;
    }
    close(fd);

    tty_printf(get_cli_prompt(OnNewK1PasswordFile), GlobalConfig.passwdfile);
  } else if (GlobalConfig.auth_type == KAPPA_AUTHTYPE_0) {
    struct passwd *passwd;

    passwd = zt_auth_passwd_single_new(GlobalConfig.password_chars, false);
    if (!passwd)
      return -1;

    tty_printf(get_cli_prompt(OnNewK0Password), passwd->pw);

    zt_auth_passwd_free(passwd, NULL);
  }

  return 0;
}

static int passdel(void) {
  int rv;

  if (access(GlobalConfig.passwdfile, F_OK))
    return -1;

  if (!tty_get_answer_is_yes(get_cli_prompt(OnPasswdFileTryDelete)))
    return 0;

  rv =
      zt_auth_passwd_delete(GlobalConfig.passwdfile, GlobalConfig.hostname, -1);
  return rv < 0 ? -1 : 0;
}

int main(int argc, char **argv) {
  int rv;
  command_t command;
  struct sigaction sa = {.sa_handler = SIG_IGN};

  entry_set_fd_limit();

  entry_check_fds();

  sigaction(SIGPIPE, &sa, NULL);
  sa.sa_handler = gsh;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGWINCH, &sa, NULL);

  set_exit_status(EXIT_STATUS_SUCCESS);

  if ((command = init_config(argc, argv)) == cmdNone)
    goto out;

  switch (command) {
  case cmdSend:
    rv = do_send();
    break;
  case cmdReceive:
    rv = do_receive();
    break;
  case cmdPassgen:
    rv = passgen();
    break;
  case cmdPassdel:
    rv = passdel();
    break;
  }

  if (rv)
    set_exit_status(EXIT_STATUS_GENERIC);

out:
  deinit_config();
  return get_exit_status();
}
