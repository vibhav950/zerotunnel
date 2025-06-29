#ifndef __TTY_IO_H__
#define __TTY_IO_H__

#include "defines.h"

const char *tty_get_name(void);

#if GCC_VERSION_AT_LEAST(2, 5)
void tty_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
char *tty_getf(const char *prompt, ...) __attribute__((format(scanf, 1, 2)));
#else
void tty_printf(const char *fmt, ...);
char *tty_getf(const char *fmt, ...);
#endif

char *tty_get(const char *prompt);
char *tty_get_hidden(const char *prompt);

void tty_kill_prompt(void);

int tty_get_answer_is_yes(const char *prompt);

int tty_get_option_number(const char *prompt, int default_opt);

int tty_no_terminal(int onoff);

#endif /* __TTY_IO_H__ */