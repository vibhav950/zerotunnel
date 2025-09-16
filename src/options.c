/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * options.c -- parse command line arguments and initialize the library config.
 *
 * The argument parser is a bare-bones version of the one used for wget2,
 * originally written by Tim Rühsen.
 * Ref: https://gitlab.com/gnuwget/wget2/-/blob/master/src/options.c.
 */

#include "options.h"
#include "common/defines.h"
#include "common/hex.h"
#include "common/log.h"
#include "common/sha256.h"
#include "common/ztver.h"
#include "lib/ztlib.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wordexp.h>

/** The order MUST match the order of the command_t enum */
static const char *command_names[] = {"send", "receive", "passgen", "passdel"};

typedef struct option option_t; // forward declaration

struct option {
  const char long_name[22];
  char short_name;
  void *var;
  void *flag;
  int (*parser_f)(option_t *opt, const char *val, bool invert);
  int args;
  command_t command;
  const char *help[4];
};

static exit_status_t exit_status;

#define CHECK_RANGE(param, val, min, max)                                                \
  do {                                                                                   \
    if (!(((val) <= (max)) && ((val) >= (min)))) {                                       \
      log_error(NULL, "Invalid %s: %d, expected in range [%d, %d]", param, val, min,     \
                max);                                                                    \
      goto err;                                                                          \
    }                                                                                    \
  } while (0)

void set_exit_status(exit_status_t status) {
  if (exit_status) {
    if (status < exit_status)
      exit_status = status;
  } else {
    exit_status = status;
  }
}

exit_status_t get_exit_status(void) { return exit_status; }

static void print_help(command_t command);

static void print_version(void) {
  static const char version_text[] = "zerotunnel version " ZT_VERSION_STRING;
  fprintf(stdout, "%s\n", version_text);
}

static int parse_string(option_t *opt, const char *val, bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  zt_free(*((char **)opt->var));
  *((const char **)opt->var) = zt_strdup(val);
  if (opt->flag)
    *((char *)opt->flag) = 1;
  return 0;
}

static int parse_filename(option_t *opt, const char *val, bool invert ATTRIBUTE_UNUSED) {
  wordexp_t wexp;

  ASSERT(opt);
  zt_free(*((char **)opt->var));
  if (wordexp(val, &wexp, 0) == 0) {
    *((char **)opt->var) = zt_strdup(wexp.we_wordv[0]);
    if (opt->flag)
      *((char *)opt->flag) = 1;
    wordfree(&wexp);
    log_debug(NULL, "Expanded filepath: '%s'", *((char **)opt->var));
    return 0;
  }
  log_error(NULL, "Error parsing string argument '%s'", val);
  return -1;
}

static int parse_boolean(option_t *opt, const char *val, bool invert) {
  ASSERT(opt);

  if (opt->var) {
    if (!val || !strcmp(val, "1") || !strcasecmp(val, "true") ||
        !strcasecmp(val, "yes") || !strcasecmp(val, "on")) {
      *((bool *)opt->var) = !invert;
    } else if (!*val || !strcmp(val, "0") || !strcasecmp(val, "false") ||
               !strcasecmp(val, "no") || !strcasecmp(val, "off")) {
      *((bool *)opt->var) = invert;
    } else {
      log_error(NULL, "Invalid boolean value '%s'", val);
      return -1;
    }
  }
  return 0;
}

static int parse_int(option_t *opt, const char *val, bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  *((int *)opt->var) = val ? atoi(val) : 0;
  if (opt->flag)
    *((char *)opt->flag) = 1;
  return 0;
}

static int parse_uint(option_t *opt, const char *val, bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  long int uval = val ? strtol(val, NULL, 10) : 0;
  if (uval >= 0 && uval <= UINT_MAX) {
    *((unsigned int *)opt->var) = (unsigned int)uval;
    if (opt->flag)
      *((char *)opt->flag) = 1;
    return 0;
  }
  log_error(NULL, "Value out of range [0, %u]: '%s'", UINT_MAX, val);
  return -1;
}

static int parse_uint16(option_t *opt, const char *val, bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  int port = val ? atoi(val) : 0;
  if (port >= 0 && port <= UINT16_MAX) {
    *((uint16_t *)opt->var) = (uint16_t)port;
    if (opt->flag)
      *((char *)opt->flag) = 1;
    return 0;
  }
  log_error(NULL, "Value out of range [0, 65535]: '%s'", val);
  return -1;
}

static int parse_numbytes(option_t *opt, const char *val, bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  char *endptr;
  unsigned long long nbytes = strtoull(val, &endptr, 10);
  if (endptr == val) {
    log_error(NULL, "Invalid number of bytes: '%s'", val);
    return -1;
  }
  switch (tolower((unsigned char)*endptr)) {
  case 'g':
    nbytes *= SIZE_GB;
    endptr++;
    break;
  case 'm':
    nbytes *= SIZE_MB;
    endptr++;
    break;
  case 'k':
    nbytes *= SIZE_KB;
    endptr++;
    break;
  default:
    break;
  }
  if (*endptr != '\0') {
    log_error(NULL, "Invalid suffix in number of bytes: '%s'", val);
    return -1;
  }
  if (nbytes > LONG_MAX) {
    log_error(NULL, "Number of bytes too large (max %ld): '%s'", LONG_MAX, val);
    return -1;
  }
  *((long *)opt->var) = zt_ulltol(nbytes);
  if (opt->flag)
    *((char *)opt->flag) = 1;
  return 0;
}

static int parse_padding_factor(option_t *opt, const char *val,
                                bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  unsigned long uval = val ? strtoul(val, NULL, 10) : 0;
  /* check bounds and power of 2 */
  if (uval > 0 && (uval & (uval - 1)) == 0 && uval <= 65536) {
    *((uint32_t *)opt->var) = (uint32_t)uval;
    if (opt->flag)
      *((char *)opt->flag) = 1;
    return 0;
  }
  log_error(NULL, "Value not of the form 2^n (1<=n<=16): '%s'", val);
  return -1;
}

static int parse_help_command(option_t *opt ATTRIBUTE_UNUSED, const char *val,
                              bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  if (!strcmp(val, "send")) {
    print_help(cmdSend);
    return 0;
  } else if (!strcmp(val, "receive")) {
    print_help(cmdReceive);
    return 0;
  } else if (!strcmp(val, "passgen")) {
    print_help(cmdPassgen);
    return 0;
  }
  return -1;
}

static int parse_help(option_t *opt ATTRIBUTE_UNUSED, const char *val ATTRIBUTE_UNUSED,
                      bool invert ATTRIBUTE_UNUSED) {
  /* This will be handled specially in init_config */
  return 0;
}

/**
 * Global configuration structure used across the library.
 * Initialize it here with default values, which may be
 * overridden by command line options or configuration files.
 */
struct config GlobalConfig = {
    .ciphersuite = "K-01",
    .preferredFamily = '4',
    .maxFileRecvSize = 4 * SIZE_GB,
    .passwordBundleSize = 20,
    .passwordChars = 32,
    .passwordWords = 4,
    .flagLZ4Compression = true,
    .flagTCPFastOpen = true,
};

// clang-format off
static option_t options[] = {
    // long name, short name, config variable, config flag, parser function, args, option section, option help
    // Add options in alphabetical order by long name
    {
      "auth-type",
      'a',
      &GlobalConfig.authType,
      NULL,
      parse_int,
      1,
      cmdSend | cmdReceive | cmdPassgen,
      {
        "KAPPA mode of authentication.\n",
        "(default: KAPPA0).\n"
      }
    },
    {
      "bundle-size",
      0,
      &GlobalConfig.passwordBundleSize,
      NULL,
      parse_uint,
      1,
      cmdPassgen,
      {
        "Maximum number of passwords in a bundle.\n",
        "Must be in the range [1, 90].\n",
        "(default: 20).\n"
      }
    },
    {
      "ciphersuite",
      'c',
      &GlobalConfig.ciphersuite,
      NULL,
      parse_string,
      1,
      cmdSend,
      {
        "KAPPA ciphersuite name or alias for this session.\n",
        "(default: K-01).\n"
      }
    },
    {
      "compress",
      'C',
      &GlobalConfig.flagLZ4Compression,
      NULL,
      parse_boolean,
      -1,
      cmdSend,
      {
        "Enable LZ4 message compression.\n",
        "(default: on).\n"
      }
    },
    {
      "connect-timeout",
      0,
      &GlobalConfig.connectTimeout,
      NULL,
      parse_uint,
      1,
      cmdSend | cmdReceive,
      {
        "Timeout for host name resolution (in milliseconds).\n",
        "(default: 15000).\n"
      }
    },
    {
      "help",
      'h',
      NULL,
      NULL,
      parse_help,
      0,
      cmdSend | cmdReceive | cmdPassgen | cmdPassdel,
      {
        "Show this help message and exit.\n"
      }
    },
    {
      "hostname",
      'H',
      &GlobalConfig.hostname,
      NULL,
      parse_string,
      1,
      cmdSend | cmdReceive | cmdPassgen | cmdPassdel,
      {
        "Host address of the peer.\n",
        "Can be a host name or an IPv4/IPv6 address.\n"
      }
    },
    {
      "identifier",
      'I',
      &GlobalConfig.passwdBundleId,
      NULL,
      parse_string,
      1,
      cmdSend | cmdReceive | cmdPassgen | cmdPassdel,
      {
        "Unique identifier for the password bundle.\n"
      }
    },
    {
      "idle-timeout",
      0,
      &GlobalConfig.idleTimeout,
      NULL,
      parse_uint,
      1,
      cmdSend | cmdReceive,
      {
        "Timeout for the server being idle (in milliseconds).\n",
        "(default: 120000).\n"
      }
    },
    {
      "ipv4-only",
      '4',
      &GlobalConfig.flagIPv4Only,
      NULL,
      parse_boolean,
      -1,
      cmdSend | cmdReceive,
      {
        "Force the use of IPv4 addresses.\n",
        "(default: off).\n"
      }
    },
    {
      "ipv6-only",
      '6',
      &GlobalConfig.flagIPv6Only,
      NULL,
      parse_boolean,
      -1,
      cmdSend | cmdReceive,
      {
        "Force the use of IPv6 addresses.\n",
        "(default: off).\n"
      }
    },
    {
      "keyfile",
      'k',
      &GlobalConfig.passwdFile,
      NULL,
      parse_filename,
      1,
      cmdSend | cmdReceive,
      {
        "Path to the password bundle file for KAPPA2 authentication.\n",
        "If not specified, try to load a bundle for the provided hostname\n",
        "from the default location specified by the ZTNL_PASSWORDS_DIR\n",
        "environment variable, defaulting to '~/.zerotunnel/passwords/'.\n",
      }
    },
    {
      "listen",
      'l',
      &GlobalConfig.hostname,
      NULL,
      parse_string,
      1,
      cmdReceive,
      {
        "Listen on the specified host name or IP address.\n",
        "(default: 0.0.0.0 -- all IPv4 interfaces).\n"
      }
    },
    {
      "live-read",
      'L',
      &GlobalConfig.flagLiveRead,
      NULL,
      parse_boolean,
      -1,
      cmdSend,
      {
        "Read from a live output stream (e.g. a pipe).\n",
        "(default: off).\n"
      }
    },
    {
      "message-padding",
      'P',
      &GlobalConfig.paddingFactor,
      &GlobalConfig.flagLengthObfuscation,
      parse_padding_factor,
      1,
      cmdSend,
      {
        "Enable message padding and set the padding factor. This\n",
        "avoids leaking file length information at the cost of\n",
        "increased message size. MUST be of the form 2^n, 1<=n<=16.\n",
        "(default: 0 -- i.e., padding disabled).\n"
      }
    },
    {
      "password-chars",
      0,
      &GlobalConfig.passwordChars,
      NULL,
      parse_uint,
      1,
      cmdPassgen,
      {
        "Number of characters in the generated password.\n",
        "Must be in the range [12, 256].\n",
        "(default: 64).\n"
      }
    },
    {
      "password-words",
      0,
      &GlobalConfig.passwordWords,
      NULL,
      parse_uint,
      1,
      cmdPassgen,
      {
        "Number of words in the generated phonetic password.\n",
        "Must be in the range [3, 20].\n",
        "(default: 4).\n"
      }
    },
    {
      "port",
      'p',
      &GlobalConfig.servicePort,
      &GlobalConfig.flagExplicitPort,
      parse_uint16,
      1,
      cmdSend | cmdReceive,
      {
        "Port number to listen on or connect to.\n",
        "(default: 9500).\n"
      }
    },
    {
      "preferred-family",
      0,
      &GlobalConfig.preferredFamily,
      NULL,
      parse_string,
      1,
      cmdSend | cmdReceive,
      {
        "Preferred address family for the connection.\n",
        "Can be '4' for IPv4 or '6' for IPv6.\n",
        "(default: '4').\n"
      }
    },
    {
      "receive-limit",
      'R',
      &GlobalConfig.maxFileRecvSize,
      NULL,
      parse_numbytes,
      1,
      cmdReceive,
      {
        "Maximum number of bytes to receive on an incoming transfer.\n",
        "An incoming or outgoing live read will be limited to this size.\n",
        "(default: 4G).\n"
      }
    },
    {
      "recv-timeout",
      0,
      &GlobalConfig.recvTimeout,
      NULL,
      parse_uint,
      1,
      cmdSend | cmdReceive,
      {
        "Timeout for receiving data (in milliseconds).\n",
        "(default: 120000).\n"
      }
    },
    {
      "send-timeout",
      0,
      &GlobalConfig.sendTimeout,
      NULL,
      parse_uint,
      1,
      cmdSend | cmdReceive,
      {
        "Timeout for sending data (in milliseconds).\n",
        "(default: 120000).\n"
      }
    },
    {
      "tcp-fastopen",
      0,
      &GlobalConfig.flagTCPFastOpen,
      NULL,
      parse_boolean,
      -1,
      cmdSend | cmdReceive,
      {
        "Enable TCP Fast Open (RFC 7413).\n",
        "(default: on).\n"
      }
    },
    {
      "tcp-nodelay",
      0,
      &GlobalConfig.flagTCPNoDelay,
      NULL,
      parse_boolean,
      -1,
      cmdSend | cmdReceive,
      {
        "Enable TCP_NODELAY (disable Nagle's algorithm).\n",
        "(default: off).\n"
      }
    },
    {
      "wordlist",
      'W',
      &GlobalConfig.wordlistFile,
      NULL,
      parse_filename,
      1,
      cmdSend,
      {
        "Path to a SQLite3 wordlist file for password generation.\n",
        "This is only supported for KAPPA2 passwords.\n"
      }
    }
};
// clang-format on

/*
  width: 2 (spaces) + 3 (-X,) + 2 (spaces) + 2 (--) + 20 (name col) + 4 (spaces)
*/
#define HELP_OPTION_INDENT_SPACES (2 + 3 + 2 + 2 + 20 + 4)

static void print_help(command_t command) {
  static const char help_header_text[] =
      "\n"
      "zerotunnel v" ZT_VERSION_STRING " - A secure file transfer utility.\n\n";

  static const char help_footer_text[] =
      "\n"
      "Example boolean option:\n"
      "\t--no-tcp-fastopen or --tcp-fastopen=off or --tcp-fastopen off\n"
      "Example string option:\n"
      "\t--hostname=example.com or --hostname example.com\n";

  static const char help_generic_text[] =
      "Usage: zerotunnel <command> [options] [target]\n\n"
      "Commands:\n"
      "  send     Send a file over the tunnel.\n"
      "  receive  Receive a file over the tunnel.\n"
      "  passgen  Generate authentication credentials.\n"
      "  passdel  Securely delete a password file.\n"
      "\n"
      "For command-specific help, use `<command> --help`.\n"
      "\n";

  const char *cmd_usage = "Usage: zerotunnel %s [options] [file]\n";

  fputs(help_header_text, stdout);

  const char *cmd;
  switch (command) {
  case cmdNone:
    fputs(help_generic_text, stdout);
    return;
  case cmdSend:
    cmd = "send";
    break;
  case cmdReceive:
    cmd = "receive";
    break;
  case cmdPassgen:
    cmd = "passgen";
    break;
  case cmdPassdel:
    cmd = "passdel";
    break;
  }
  fprintf(stdout, cmd_usage, cmd);

  fputs("\nOptions:\n", stdout);

  for (size_t i = 0; i < COUNTOF(options); ++i) {
    if (options[i].command & command) {
      const option_t *opt = &options[i];
      if (!opt->help[0])
        continue;
      if (opt->short_name) {
        /* print first line with short option */
        fprintf(stdout, "  -%c,  --%-20s    %s", opt->short_name, opt->long_name,
                opt->help[0]);
      } else {
        /* maintain alignment: replace the " -X  " segment with spaces */
        fprintf(stdout, "       --%-20s    %s", opt->long_name, opt->help[0]);
      }
      /* subsequent lines aligned under first help column */
      for (int h = 1; h < 4 && opt->help[h]; ++h)
        fprintf(stdout, "%*s%s", HELP_OPTION_INDENT_SPACES, "", opt->help[h]);
    }
  }
  fputs(help_footer_text, stdout);
}

static int ATTRIBUTE_PURE ATTRIBUTE_NONNULL(1, 2)
    option_compare(const void *key, const void *option) {
  return strcmp((const char *)key, ((const option_t *)option)->long_name);
}

static int ATTRIBUTE_NONNULL(1)
    set_long_option(const char *name, const char *val, command_t command) {
  option_t *opt;
  bool invert = false, value_present = false;
  char namebuf[sizeof(options[0].long_name) + 5 /*len("--") + len("no-")*/], *p;
  int ret = 0, rv;

  /* Handle options with value directly appended, like --foo=bar */
  if ((p = strchr(name, '='))) {
    if (p - name >= (int)sizeof(namebuf)) {
      log_error(NULL, "Unknown option: '%s'", name);
      return -1;
    }
    memcpy(namebuf, name, p - name);
    namebuf[p - name] = '\0';
    name = namebuf;
    val = p + 1;
    value_present = true;
  }

  /* If the option is negated (--no-), delete the prefix and set invert flag */
  if (!strncmp(name, "no-", 3)) {
    invert = true;
    name += 3;
  }

  opt = bsearch(name, options, COUNTOF(options), sizeof(options[0]), option_compare);

  if (!opt) {
    log_error(NULL, "Unknown option: '%s'", name);
    return -1;
  }

  if (!(opt->command & command)) {
    log_error(NULL, "Option '%s' is not valid for this command", name);
    return -1;
  }

  if (value_present) {
    // "option=*"
    if (invert) {
      if (!opt->args || opt->parser_f == parse_string ||
          opt->parser_f == parse_filename) {
        log_error(NULL, "Option 'no-%s' does not allow arguments", name);
        return -1;
      }
    } else if (!opt->args) {
      log_error(NULL, "Option '%s' does not allow arguments", name);
      return -1;
    }
  } else {
    // "option"
    switch (opt->args) {
    case 0:
      val = NULL;
      break;
    case 1:
      if (!val) {
        log_error(NULL, "Option '%s' requires an argument", name);
        return -1;
      }

      if (invert && (opt->parser_f == parse_string || opt->parser_f == parse_filename)) {
        /* unset the value */
        val = NULL;
      } else {
        ret = opt->args;
      }
      break;
    case -1:
      val = NULL;
      break;
    default:
      break;
    }
  }

  if ((rv = opt->parser_f(opt, val, invert)) < 0)
    return rv;

  return ret;
}

static int ATTRIBUTE_NONNULL(2) argparser(int argc, char *argv[], command_t command) {
  static char option_shortcut_table[128];
  const char *first_arg = NULL;
  int n, rv;

  /* Init the short option name lookup */
  if (!option_shortcut_table[0] /*init only once*/) {
    for (char i = 0; i < COUNTOF(options); ++i)
      if (options[i].short_name)
        option_shortcut_table[(unsigned char)options[i].short_name] = i + 1;
  }

  for (n = 2; n < argc && first_arg != argv[n]; ++n) {
    const char *argp = argv[n]; /* store the last cmdline arg */

    if (argp[0] != '-') {
      // Move args behind options to allow mixed args/options like getopt().
      // In the end, the order of the args is as before.
      char *cur = argv[n];
      for (int i = n; i < argc - 1; ++i)
        argv[i] = argv[i + 1];
      argv[argc - 1] = cur;

      if (!first_arg)
        first_arg = cur;

      n--;
      continue;
    }

    if (argp[1] == '-') {
      /* Long option */
      if (argp[2] == '\0')
        return n + 1;

      if ((rv = set_long_option(argp + 2, n < argc - 1 ? argv[n + 1] : NULL, command)) <
          0) {
        return rv;
      }

      n += rv;
    } else if (argp[1]) {
      /* Short option(s) */
      for (int pos = 1; argp[pos]; pos++) {
        option_t *opt;
        int idx;

        if (isalnum(argp[pos]) &&
            (idx = option_shortcut_table[(unsigned char)argp[pos]])) {
          opt = &options[idx - 1];

          if (!(opt->command & command)) {
            log_error(NULL, "Option '-%c' is not valid for this command", argp[pos]);
            return -1;
          }

          if (opt->args > 0) {
            const char *val;

            if (!argp[pos + 1] && argc <= n + opt->args) {
              log_error(NULL, "Missing argument(s) for option '-%c'", argp[pos]);
              return -1;
            }
            val = argp[pos + 1] ? argp + pos + 1 : argv[++n];
            if ((rv = opt->parser_f(opt, val, 0)) < 0)
              return rv;
            n += rv;
            break;
          } else { // if (opt->args == 0)
            if ((rv = opt->parser_f(opt, NULL, 0)) < 0)
              return rv;
          }
        } else {
          log_error(NULL, "Unknown option '-%c'", argp[pos]);
          return -1;
        }
      }
    }
  }

  return n;
}

#define DEFAULT_PASSWORDS_DIR "~/.zerotunnel/passwords/"

static char *get_password_file_location(const char *name, bool check) {
  int n;
  char *dir;
  char *fname = NULL;
  unsigned char *hex = NULL;
  wordexp_t wexp;
  sha256_ctx_t ctx;
  unsigned char hash[SHA256_DIGEST_LEN];

  dir = getenv("ZTNL_PASSWORDS_DIR");
  dir = (dir && *dir) ? dir : DEFAULT_PASSWORDS_DIR;

  if (wordexp(dir, &wexp, 0) == 0)
    dir = wexp.we_wordv[0];
  else
    return NULL;

  n = strlen(dir) - 1;
  if (dir[n] == '/')
    dir[n] = '\0';

  if (access(dir, R_OK | W_OK | X_OK) != 0) {
    wordfree(&wexp);
    log_error(NULL, "Password dir not accessible");
    return NULL;
  }

  SHA256(PTR8(name), strlen(name), hash);

  if (zt_hex_encode(hash, SHA256_DIGEST_LEN, &hex)) {
    fname = zt_malloc(n + strlen(hex) + 2);
    if (fname)
      sprintf(fname, "%s/%s", dir, hex);
    wordfree(&wexp);
    zt_free(hex);
  }

  if (check && fname) {
    if (access(fname, R_OK | W_OK) != 0) {
      zt_free(fname);
      fname = NULL;
      log_error(NULL, "Password file not accessible for name '%s'", name);
    }
  }
  return fname;
}

command_t init_config(int argc, char *argv[]) {
  int n;
  command_t command = 0;
  const char *target = NULL;

  set_exit_status(EXIT_STATUS_BAD_PARSE);

  /* These will be freed in deinit_config() */
  GlobalConfig.ciphersuite = zt_strdup(GlobalConfig.ciphersuite);

  if (argc < 2) {
    print_help(cmdNone);
    set_exit_status(EXIT_STATUS_SUCCESS);
    return cmdNone;
  }

  /* Check for global help flags: zerotunnel --help or zerotunnel -h */
  if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
    print_help(cmdNone);
    set_exit_status(EXIT_STATUS_SUCCESS);
    return cmdNone;
  }

  for (int i = 0; i < COUNTOF(command_names); ++i) {
    if (!strcmp(argv[1], command_names[i])) {
      command = (command_t)(1UL << i);
      break;
    }
  }
  if (!command) {
    log_error(NULL, "Unknown command: '%s'", argv[1]);
    return cmdNone;
  }

  /* Check for command-specific help flag */
  if (argc == 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
    print_help(command);
    set_exit_status(EXIT_STATUS_SUCCESS);
    return cmdNone;
  }

  if ((n = argparser(argc, argv, command)) < 0)
    return cmdNone;

  /* Extract target from remaining arguments */
  if (n < argc)
    target = argv[n++];

  /* Handle mutually exclusive and otherwise incompatible or incorrect option values,
   * now that all user options have been processed */

  CHECK_RANGE("bundle-size", GlobalConfig.passwordBundleSize, 1, 90);

  CHECK_RANGE("password-chars", GlobalConfig.passwordChars, 12, 256);

  CHECK_RANGE("password-words", GlobalConfig.passwordWords, 3, 20);

  if (GlobalConfig.flagLengthObfuscation && GlobalConfig.flagLZ4Compression) {
    log_error(NULL, "Can't have both --compression and --message-padding on");
    goto err;
  }

  if (command == cmdPassdel || GlobalConfig.authType == KAPPA_AUTHTYPE_1) {
    if (!GlobalConfig.passwdBundleId) {
      log_error(NULL, "Missing required option --identifier");
      goto err;
    }
  } else if (GlobalConfig.passwdBundleId) {
    log_error(NULL, "Option --identifier does not apply for this command");
    goto err;
  }

  if (GlobalConfig.authType != KAPPA_AUTHTYPE_1 && GlobalConfig.passwdFile) {
    log_error(NULL, "Option --keyfile does not apply for KAPPA0 or KAPPA2 auth types");
    goto err;
  }

  if (GlobalConfig.flagIPv4Only && GlobalConfig.flagIPv6Only) {
    log_error(NULL, "Can't have both --ipv4-only and --ipv6-only");
    goto err;
  }

  switch (command) {
  case cmdSend: {
    if (!GlobalConfig.hostname)
      goto err;

    if (GlobalConfig.authType == KAPPA_AUTHTYPE_1 && !GlobalConfig.passwdFile) {
      char *fname = get_password_file_location(GlobalConfig.hostname, true);
      if (!fname)
        return cmdNone;
      GlobalConfig.passwdFile = fname;
    }

    if (GlobalConfig.flagLiveRead) {
      if (target)
        goto err;
      GlobalConfig.filePath = zt_strdup("-"); /* read from STDIN */
    } else if (target) {
      GlobalConfig.filePath = zt_strdup(target);
    } else {
      goto err;
    }

    break;
  }

  case cmdReceive: {
    if (GlobalConfig.authType == KAPPA_AUTHTYPE_1 && !GlobalConfig.passwdFile) {
      if (!GlobalConfig.hostname)
        goto err;

      char *fname = get_password_file_location(GlobalConfig.hostname, true);
      if (!fname)
        return cmdNone;
      GlobalConfig.passwdFile = fname;
    }

    if (!target)
      GlobalConfig.filePath = zt_strdup("-"); /* write to STDOUT */
    else
      GlobalConfig.filePath = zt_strdup(target);

    break;
  }

  case cmdPassgen: {
    if (GlobalConfig.authType == KAPPA_AUTHTYPE_2)
      goto err;

    /* We either need a explicit target file location or a hostname
     * to locate one in the default passwords directory */
    if (GlobalConfig.authType == KAPPA_AUTHTYPE_1) {
      if (!target && !GlobalConfig.hostname) {
        goto err;
      } else if (target) {
        GlobalConfig.passwdFile = zt_strdup(target);
      } else {
        char *fname = get_password_file_location(GlobalConfig.hostname, false);
        if (!fname)
          return cmdNone;
        GlobalConfig.passwdFile = fname;
      }
    } else if (target || GlobalConfig.hostname) {
      /* K0 does not take these arguments */
      // TODO: can we have a better way of handling these restricted
      // combinations without this messy logic?
      goto err;
    }

    break;
  }

  case cmdPassdel: {
    if (!target && !GlobalConfig.hostname)
      goto err; /* no way to locate the K1 password file */

    if (target) {
      GlobalConfig.passwdFile = zt_strdup(target);
    } else {
      char *fname = get_password_file_location(GlobalConfig.hostname, true);
      if (!fname)
        return cmdNone;
      GlobalConfig.passwdFile = fname;
    }
  }
  }

  if (n != argc)
    goto err;

  set_exit_status(EXIT_STATUS_SUCCESS);
  return command;

err:
  log_error(NULL, "Bad args for command '%s'", argv[1]);
  return cmdNone;
}

void deinit_config(void) {
  zt_free(GlobalConfig.hostname);
  zt_free(GlobalConfig.passwdFile);
  zt_free(GlobalConfig.ciphersuite);
  zt_free(GlobalConfig.filePath);
  zt_free(GlobalConfig.passwdBundleId);
}
