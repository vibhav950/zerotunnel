/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * tty_io.c - TTY i/o functions
 *
 * Based on the implementation from GnuPG (https://github.com/gpg/gnupg/)
 */

#include "tty_io.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int initialized;
static int prev_prompt_len;
static int no_terminal;

static FILE *ttyfp;

static struct termios termios_save;
static int restore_termios;

const char *tty_get_name(void) {
  static char *name;
  static int have_name;

  /* ctermid() always returns "/dev/tty" on glibc
   * but do this just to be safe for the future */
  if (!have_name) {
    const char *s;
    char buf[L_ctermid];

    s = ctermid(buf);
    if (s)
      name = strdup(s);
    have_name = 1;
  }
  /* assume standard tty on memory error */
  return name ? name : "/dev/tty";
}

static void cleanup(void) {
  if (restore_termios) {
    restore_termios = 0;
    if (tcsetattr(fileno(ttyfp), TCIFLUSH, &termios_save) != 0)
      log_error(NULL, "tcsetattr() failed (%s)", strerror(errno));
  }
}

static void tty_initfp(void) {
  if (initialized)
    return;

  ttyfp = fopen(tty_get_name(), "r+");
  if (!ttyfp)
    log_error(NULL, "cannot open '%s' (%s)", tty_get_name(), strerror(errno));
  atexit(cleanup);
}

void tty_printf(const char *fmt, ...) {
  va_list ap;

  if (no_terminal)
    return;

  if (unlikely(!initialized))
    tty_initfp();

  va_start(ap, fmt);
  prev_prompt_len += vfprintf(ttyfp, fmt, ap);
  fflush(ttyfp);
  va_end(ap);
}

static char *do_get(const char *prompt, int hidden) {
  char *buf;
  int n; /* allocated size of `buf` */
  int i; /* number of bytes in `buf` */
  int c;
  uint8_t ch[1];

  if (no_terminal)
    log_error(NULL, "no terminal available -- can't get input");

  if (unlikely(!initialized))
    tty_initfp();

  prev_prompt_len = 0;
  tty_printf("%s", prompt);
  buf = zt_malloc(n = 50);
  i = 0;

  if (hidden) {
    struct termios term;

    if (tcgetattr(fileno(ttyfp), &termios_save) != 0)
      log_error(NULL, "tcgetattr() failed (%s)", strerror(errno));
    restore_termios = 1;
    term = termios_save;
    term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    if (tcsetattr(fileno(ttyfp), TCSANOW, &term) != 0)
      log_error(NULL, "tcsetattr() failed (%s)", strerror(errno));
  }

  while (read(fileno(ttyfp), ch, 1) == 1 && *ch != '\n') {
    if (!hidden)
      prev_prompt_len++;
    c = *ch;
    if (c == '\t')
      c = ' '; /* replace tab with space */
    else if ((c >= 0 && c <= 0x1f) || c == 0x7f)
      continue; /* skip control characters */
    else if (c >= 0x80)
      continue; /* skip non-ASCII characters */
    if (!(i < n - 1)) {
      n += 50;
      buf = zt_realloc(buf, n);
    }
    buf[i++] = c;
  }

  if (hidden) {
    if (tcsetattr(fileno(ttyfp), TCSANOW, &termios_save) != 0)
      log_error(NULL, "tcsetattr() failed (%s)", strerror(errno));
    restore_termios = 0;
  }

  buf[i] = '\0';
  return buf;
}

char *tty_get(const char *prompt) { return do_get(prompt, 0); }

char *tty_get_hidden(const char *prompt) { return do_get(prompt, 1); }

char *tty_getf(const char *promptfmt, ...) {
  va_list ap;
  char *prompt;
  char *answer;

  va_start(ap, promptfmt);
  if (vasprintf(&prompt, promptfmt, ap) < 0)
    log_error(NULL, "vasprintf() failed (%s)", strerror(errno));
  va_end(ap);
  answer = tty_get(prompt);
  free(prompt);
  return answer;
}

void tty_kill_prompt(void) {
  int i;

  if (no_terminal)
    return;

  if (!initialized)
    tty_initfp();

  if (!prev_prompt_len)
    return;

  putc('\r', ttyfp);
  for (i = 0; i < prev_prompt_len; i++)
    putc(' ', ttyfp);
  putc('\r', ttyfp);
  fflush(ttyfp);
  prev_prompt_len = 0;
}

static inline int answer_is_yes_no_default(const char *ans, int default_ans) {
  if (*ans && strchr("yY", *ans) && !ans[1]) /* 'y'/'Y' */
    return 1;
  if (!strcasecmp(ans, "yes")) /* long yes */
    return 1;
  if (*ans && strchr("nN", *ans) && !ans[1]) /* 'n'/'N' */
    return 0;
  if (!strcasecmp(ans, "no")) /* long no */
    return 0;
  return default_ans;
}

int tty_get_answer_is_yes(const char *prompt) {
  int yes;
  char *p;

  p = tty_get(prompt);
  tty_kill_prompt();
  yes = answer_is_yes_no_default(p, 0);
  zt_free(p);
  return yes;
}

static inline int get_opt(const char *opt, int default_opt) {
  char *p;

  if (!opt || !*opt)
    return default_opt;
  for (p = (char *)opt; p && isdigit(*p); p++)
    ;
  if (*p)
    return -1; /* not a number -- invalid choice */
  return atoi(opt);
}

/** returns -1 for invalid inputs */
int tty_get_option_number(const char *prompt, int default_opt) {
  char *p;
  int opt;

  p = tty_get(prompt);
  tty_kill_prompt();
  opt = get_opt(p, default_opt);
  zt_free(p);
  return opt;
}

int tty_no_terminal(int onoff) {
  int old = no_terminal;
  no_terminal = onoff ? 1 : 0;
  return old;
}
