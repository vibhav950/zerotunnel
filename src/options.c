#include "options.h"
#include "common/defines.h"
#include "common/hex.h"
#include "common/log.h"
#include "common/sha256.h"
#include "common/ztver.h"
#include "lib/ztlib.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wordexp.h>

// clang-format off
typedef enum {
  COMMAND_SEND                = (1UL << 0),
  COMMAND_RECEIVE             = (1UL << 1),
  COMMAND_PASSGEN             = (1UL << 2),
  COMMAND_PASSDEL             = (1UL << 3),
  COMMAND_NONE                = (0UL)
} command_t;

/** The order MUST match the order of the command_t enum */
const char *command_names[] = {
  "send",
  "receive",
  "passgen",
  "passdel"
};
// clang-format on

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
  printf("%s\n", version_text);
}

static int parse_string(option_t *opt, const char *val,
                        bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  zt_free(*((char **)opt->var));
  *((const char **)opt->var) = zt_strdup(val);
  if (opt->flag)
    *((char *)opt->flag) = 1;
  return 0;
}

static int parse_filename(option_t *opt, const char *val,
                          bool invert ATTRIBUTE_UNUSED) {
  wordexp_t wexp;

  ASSERT(opt);
  zt_free(*((char **)opt->var));
  if (wordexp(val, &wexp, 0) == 0) {
    *((char **)opt->var) = zt_strdup(wexp.we_wordv[0]);
    if (opt->flag)
      *((char *)opt->flag) = 1;
    wordfree(&wexp);
    log_debug(NULL, "Expanded filename: '%s'", *((char **)opt->var));
    return 0;
  }
  log_error(NULL, "Error parsing string argument '%s'", val);
  return -1;
}

static int parse_boolean(option_t *opt, const char *val, bool invert) {
  ASSERT(opt);
  if (!val || !strcmp(val, "1") || !strcasecmp(val, "true") ||
      !strcasecmp(val, "yes") || !strcasecmp(val, "on")) {
    *((bool *)opt->var) = !invert;
    goto jsetflag;
  } else if (!*val || !strcmp(val, "0") || !strcasecmp(val, "false") ||
             !strcasecmp(val, "no") || !strcasecmp(val, "off")) {
    *((bool *)opt->var) = invert;
    goto jsetflag;
  }
  log_error(NULL, "Invalid boolean value '%s'", val);
  return -1;
jsetflag:
  if (opt->flag)
    *((char *)opt->flag) = 1;
  return 0;
}

static int parse_int(option_t *opt, const char *val,
                     bool invert ATTRIBUTE_UNUSED) {
  ASSERT(opt);
  *((int *)opt->var) = val ? atoi(val) : 0;
  if (opt->flag)
    *((char *)opt->flag) = 1;
  return 0;
}

static int parse_uint(option_t *opt, const char *val,
                      bool invert ATTRIBUTE_UNUSED) {
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

static int parse_uint16(option_t *opt, const char *val,
                        bool invert ATTRIBUTE_UNUSED) {
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
    print_help(COMMAND_SEND);
    return 0;
  } else if (!strcmp(val, "receive")) {
    print_help(COMMAND_RECEIVE);
    return 0;
  } else if (!strcmp(val, "passgen")) {
    print_help(COMMAND_PASSGEN);
    return 0;
  }
  return -1;
}

/**
 * Global configuration structure used across the library.
 * We initialize it here with default values, and override them
 * with command line options or configuration files.
 */
static struct config g_config = {
    .ciphersuite = "K-01",
    .preferred_family = '4',
    .flag_lz4_compression = true,
    .flag_tcp_fastopen = true,
};

// clang-format off
static const option_t options[] = {
    // long name, short name, config variable, config flag, parser function, args, option section, option help
    // Add options in alphabetical order by long name
    {
      "auth-type",
      'a',
      &g_config.auth_type,
      NULL,
      parse_int,
      1,
      COMMAND_SEND | COMMAND_RECEIVE | COMMAND_PASSGEN,
      {
        "KAPPA mode of authentication.\n",
        "(default: KAPPA0).\n"
      }
    },
    {
      "ciphersuite",
      'c',
      &g_config.ciphersuite,
      NULL,
      parse_string,
      1,
      COMMAND_SEND,
      {
        "KAPPA ciphersuite name or alias for this session.\n",
        "(default: K-01).\n"
      }
    },
    {
      "compress",
      'C',
      NULL,
      &g_config.flag_lz4_compression,
      parse_boolean,
      -1,
      COMMAND_SEND,
      {
        "Enable LZ4 message compression.\n",
        "(default: on).\n"
      }
    },
    {
      "connect-timeout",
      0,
      &g_config.connect_timeout,
      NULL,
      parse_uint,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Timeout for host name resolution (in milliseconds).\n",
        "(default: 10000).\n"
      }
    },
    {
      "hostname",
      'H',
      &g_config.hostname,
      NULL,
      parse_string,
      1,
      COMMAND_SEND | COMMAND_RECEIVE | COMMAND_PASSGEN | COMMAND_PASSDEL,
      {
        "Host address of the peer.\n",
        "Can be a host name or an IPv4/IPv6 address.\n"
      }
    },
    {
      "idle-timeout",
      0,
      &g_config.idle_timeout,
      NULL,
      parse_uint,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Timeout for the server being idle (in milliseconds).\n",
        "(default: 60000).\n"
      }
    },
    {
      "ipv4-only",
      '4',
      NULL,
      &g_config.flag_ipv4_only,
      parse_boolean,
      -1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Force the use of IPv4 addresses.\n",
        "(default: off).\n"
      }
    },
    {
      "ipv6-only",
      '6',
      NULL,
      &g_config.flag_ipv6_only,
      parse_boolean,
      -1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Force the use of IPv6 addresses.\n",
        "(default: off).\n"
      }
    },
    {
      "keyfile",
      'k',
      &g_config.passwddb_file,
      NULL,
      parse_filename,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
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
      &g_config.hostname,
      NULL,
      parse_string,
      1,
      COMMAND_RECEIVE,
      {
        "Listen on the specified host name or IP address.\n",
        "(default: 0.0.0.0 -- all IPv4 interfaces).\n"
      }
    },
    /* {
      "live-read",
      'L',
      NULL,
      &g_config.flag_live_read,
      parse_boolean,
      -1,
      COMMAND_SEND,
      {
        "Read from a live output stream (e.g. a pipe).\n",
        "(default: off).\n"
      }
    }, */
    {
      "message-padding",
      'P',
      &g_config.padding_factor,
      &g_config.flag_length_obfuscation,
      parse_padding_factor,
      1,
      COMMAND_SEND,
      {
        "Enable message padding and set the padding factor. This\n",
        "avoids leaking file length information at the cost of\n",
        "increased message size. MUST be of the form 2^n, 1<=n<=16.\n",
        "(default: 0 -- i.e., padding disabled).\n"
      }
    },
    {
      "port",
      'p',
      &g_config.port,
      &g_config.flag_explicit_port,
      parse_uint16,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Port number to listen on or connect to.\n",
        "(default: 9500).\n"
      }
    },
    {
      "preferred-family",
      0,
      &g_config.preferred_family,
      NULL,
      parse_string,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Preferred address family for the connection.\n",
        "Can be '4' for IPv4 or '6' for IPv6.\n",
        "(default: '4').\n"
      }
    },
    {
      "recv-timeout",
      0,
      &g_config.recv_timeout,
      NULL,
      parse_uint,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Timeout for receiving data (in milliseconds).\n",
        "(default: 5000).\n"
      }
    },
    {
      "send-timeout",
      0,
      &g_config.send_timeout,
      NULL,
      parse_uint,
      1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Timeout for sending data (in milliseconds).\n",
        "(default: 5000).\n"
      }
    },
    {
      "size",
      's',
      &g_config.password_size,
      NULL,
      parse_uint,
      1,
      COMMAND_PASSGEN,
      {
        "Size of the generated password in characters.\n",
        "Must be in the range [12, 256].\n",
        "(default: 32).\n"
      }
    },
    {
      "tcp-fastopen",
      0,
      NULL,
      &g_config.flag_tcp_fastopen,
      parse_boolean,
      -1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Enable TCP Fast Open (RFC 7413).\n",
        "(default: on).\n"
      }
    },
    {
      "tcp-nodelay",
      0,
      NULL,
      &g_config.flag_tcp_nodelay,
      parse_boolean,
      -1,
      COMMAND_SEND | COMMAND_RECEIVE,
      {
        "Enable TCP_NODELAY (disable Nagle's algorithm).\n",
        "(default: off).\n"
      }
    },
    {
      "words",
      'w',
      &g_config.password_size,
      NULL,
      parse_uint,
      1,
      COMMAND_PASSGEN,
      {
        "Number of words in the generated password.\n",
        "Must be in the range [3, 20].\n",
        "(default: 8).\n"
      }
    }
};
// clang-format on

/*
  width: 2 (spaces) + 2 (--) + 20 (name col) + 2 (spaces) + 2 (-X) + 1 (space)
*/
#define OPTION_HELP_INDENT (2 + 2 + 20 + 2 + 2 + 1)

static void print_help(command_t command) {
  static const char common_help_header_text[] =
      "\n"
      "zerotunnel v" ZT_VERSION_STRING " - A secure file transfer utility.\n";

  static const char generic_help_text[] =
      "Usage: zerotunnel <command> [options] [target]\n"
      "Commands:\n"
      "  send     Send a file over the tunnel.\n"
      "  receive  Receive a file over the tunnel.\n"
      "  passgen  Generate authentication credentials.\n"
      "  passdel  Securely delete a password file.\n"
      "\n"
      "For command-specific help, use `<command> --help`.\n"
      "\n";

  static const char help_footer_text[] =
      "\n"
      "Example boolean option:\n"
      "\t--no-tcp-fastopen or --tcp-fastopen=off or --tcp-fastopen off\n"
      "Example string option:\n"
      "\t--hostname=example.com or --hostname example.com\n";

  // clang-format off
  static const char *help_text[] = {
    [0] = {
      "Usage: zerotunnel send [options] [file]\n"
      "\n"
      "Examples:\n"
      "\tzerotunnel send --hostname example.com --port 8000 /path/to/file\n"
      "\tcat hello.txt | zerotunnel send -H example.com -p 8000 -L\n"
    },
    [1] = {
      "Usage: zerotunnel receive [options] [file]\n"
      "\n"
      "Examples:\n"
      "\tzerotunnel receive --port 8000 /path/to/file\n"
    },
    [2] = {
      "Usage: zerotunnel passgen [options] [file]\n"
      "\n"
      "Examples:\n"
      "\tzerotunnel passgen --auth-type KAPPA0 -s 32\n"
      "\tzerotunnel passgen --auth-type KAPPA1 -s 32 /path/to/passwords.txt -s 32\n"
      "\tzerotunnel passgen --auth-type KAPPA2 -w 8\n"
    },
    [3] = {
      "Usage: zerotunnel passdel [options] [file]\n"
      "\n"
      "Examples:\n"
      "\tzerotunnel passdel -H 127.0.0.1\n"
      "\tzerotunnel passdel passwords.txt\n"
    }
  };
  // clang-format on

  fputs(common_help_header_text, stdout);
  switch (command) {
  case COMMAND_NONE:
    fputs(generic_help_text, stdout);
    return;
  case COMMAND_SEND:
    fputs(help_text[0], stdout);
    break;
  case COMMAND_RECEIVE:
    fputs(help_text[1], stdout);
    break;
  case COMMAND_PASSGEN:
    fputs(help_text[2], stdout);
    break;
  case COMMAND_PASSDEL:
    fputs(help_text[3], stdout);
    break;
  default:
    fprintf(stdout, "Command not found '%d'", command);
    exit(EXIT_STATUS_BAD_PARSE);
  }
  fputs("\nOptions:\n", stdout);

  for (size_t i = 0; i < COUNTOF(options); ++i) {
    if (options[i].command & command) {
      const option_t *opt = &options[i];
      if (!opt->help[0])
        continue;
      if (opt->short_name) {
        /* print first line with short option */
        printf("  --%-20s -%c  %s", opt->long_name, opt->short_name,
               opt->help[0]);
      } else {
        /* maintain alignment: replace the " -X  " segment with spaces */
        printf("  --%-20s     %s", opt->long_name, opt->help[0]);
      }
      /* subsequent lines aligned under first help column */
      for (int h = 1; h < 4 && opt->help[h]; ++h)
        printf("%*s%s", OPTION_HELP_INDENT, "", opt->help[h]);
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

  opt = bsearch(name, options, COUNTOF(options), sizeof(options[0]),
                option_compare);

  if (!opt) {
    log_error(NULL, "Unknown option: '%s'", name);
    return -1;
  }

  if (!(opt->command & command)) {
    log_error(NULL, "Option '%s' is not valid for this command", name);
    return -1;
  }

  if (value_present) {
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
    switch (opt->args) {
    case 0:
      val = NULL;
      break;
    case 1:
      if (!val) {
        log_error(NULL, "Option '%s' requires an argument", name);
        return -1;
      }

      if (invert && opt->parser_f == parse_string ||
          opt->parser_f == parse_filename) {
        /* unset the value */
        val = NULL;
      } else {
        ret = opt->args;
      }
      break;
    case -1:
      if (val)
        ret = 1;
      break;
    default:
      break;
    }
  }

  if ((rv = opt->parser_f(opt, val, invert)) < 0)
    return rv;

  return ret;
}

int ATTRIBUTE_NONNULL(2) argparser(int argc, char *argv[], command_t command) {
  static char option_shortcut_table[128];
  const char *first_arg = NULL;
  int n, rv;

  /* Init the short option name lookup */
  if (!option_shortcut_table[0] /*init only once*/) {
    for (char i = 0; i < COUNTOF(options); ++i)
      if (options[i].short_name)
        option_shortcut_table[(unsigned char)options[i].short_name] = i + 1;
  }

  /* This is very clever :O -- again, all credit to Tim Rühsen */
  for (n = 1; n < argc && first_arg != argv[n]; ++n) {
    const char *argp = argv[n]; /* store the last cmdline arg */

    if (argp[0] != '-') {
      // Move args behind options to allow mixed args/options like getopt().
      // In the end, the order of the args is as before.
      const char *cur = argv[n];
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

      if ((rv = set_long_option(argp + 2, n < argc - 1 ? argv[n + 1] : NULL,
                                command)) < 0) {
        return rv;
      }

      n += rv;
    } else if (argp[1]) {
      /* Short option(s) */
      for (int pos = 1; argp[pos]; pos++) {
        option_t *opt;
        int idx;

        if (c_isalnum(argp[pos]) &&
            (idx = option_shortcut_table[(unsigned char)argp[pos]])) {
          opt = &options[idx - 1];

          if (!(opt->command & command)) {
            log_error(NULL, "Option '-%c' is not valid for this command",
                      argp[pos]);
            return -1;
          }

          if (opt->args > 0) {
            const char *val;

            if (!argp[pos + 1] && argc <= n + opt->args) {
              log_error(NULL, "Missing argument(s) for option '-%c'",
                        argp[pos]);
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

static char *get_password_bundle_file(const char *hostname, bool check) {
  char *fname = NULL;
  unsigned char *hex = NULL;
  const char *dir = getenv("ZTNL_PASSWORDS_DIR");
  wordexp_t wexp;
  sha256_ctx_t ctx;
  unsigned char hash[SHA256_DIGEST_LEN];

  dir = (dir && *dir) ? dir : DEFAULT_PASSWORDS_DIR;
  if (dir[0] == '~') {
    if (wordexp(dir, &wexp, 0) == 0)
      dir = wexp.we_wordv[0];
    else
      return NULL;
  }

  /* Check passwords dir exists */
  if (access(dir, R_OK | W_OK | X_OK) != 0) {
    wordfree(&wexp);
    log_error(NULL,
              "Password directory '%s' does not exist or is not accessible");
    return NULL;
  }

  (void)sha256_init(&ctx);
  (void)sha256_update(&ctx, (const unsigned char *)hostname, strlen(hostname));
  (void)sha256_finalize(&ctx, hash);

  if (zt_hex_encode(hash, SHA256_DIGEST_LEN, &hex) /*success*/) {
    fname = zt_malloc(strlen(dir) + strlen(hex) + 2);
    if (fname)
      sprintf(fname, "%s/%s", dir, hex);
    wordfree(&wexp);
    zt_free(hex);
  }

  if (check && fname) {
    if (access(fname, R_OK | W_OK) != 0) {
      zt_free(fname);
      fname = NULL;
      log_error(
          NULL,
          "Password file for hostname '%s' does not exist or is not accessible",
          hostname);
    }
  }
  return fname;
}

command_t init_config_from_cli(int argc, char *argv[]) {
  command_t command = 0;
  int n;
  const char *target = NULL;

  set_exit_status(EXIT_STATUS_BAD_PARSE);

  if (argc < 2) {
    log_error(NULL, "No command specified\n");
    print_help(COMMAND_NONE);
    return -1;
  }

  for (int i = 0; i < COUNTOF(command_names); ++i) {
    if (!strcmp(argv[1], command_names[i])) {
      command = (command_t)(1UL << i);
      break;
    }
  }
  if (!command) {
    log_error(NULL, "Unknown command: '%s'", argv[1]);
    // print_help(COMMAND_ALL);
    return -1;
  }

  /* These will be freed in deinit_config() */
  g_config.ciphersuite = zt_strdup(g_config.ciphersuite);

  if ((n = argparser(argc, argv, command)) < 0)
    return -1;

  /* Extract target from remaining arguments */
  if (n < argc)
    target = argv[n];

  /* Validate arguments on a per-command basis. This will get messy but there
   * seems to be no better way right now. */
  switch (command) {
  case COMMAND_SEND: {
    if (!g_config.hostname)
      goto err;

    if (!g_config.passwddb_file && g_config.auth_type == KAPPA_AUTHTYPE_1) {
      char *fname = get_password_bundle_file(g_config.hostname, true);
      if (!fname)
        return -1;
      g_config.passwddb_file = fname;
    }

    if (g_config.flag_live_read) {
      if (target)
        goto err;
      g_config.filename = zt_strdup("-"); /* read from STDIN */
    } else if (target) {
      g_config.filename = zt_strdup(target);
    } else {
      goto err;
    }

    break;
  }

  case COMMAND_RECEIVE: {
    if (!g_config.hostname)
      goto err;

    if (!g_config.passwddb_file && g_config.auth_type == KAPPA_AUTHTYPE_1) {
      char *fname = get_password_bundle_file(g_config.hostname, true);
      if (!fname)
        return -1;
      g_config.passwddb_file = fname;
    }

    if (!target)
      g_config.filename = zt_strdup("-"); /* write to STDOUT */
    else
      g_config.filename = zt_strdup(target);

    break;
  }

  case COMMAND_PASSGEN: {
    /* We either need a target location for a password file or a hostname to
     * locate one in the default passwords directory */
    if (!target && !g_config.hostname) {
      goto err;
    } else if (target) {
      g_config.passwddb_file = zt_strdup(target);
    } else {
      char *fname = get_password_bundle_file(g_config.hostname, true);
      if (!fname)
        return -1;
      g_config.passwddb_file = fname;
    }

    break;
  }

  case COMMAND_PASSDEL: {
    if (!target && !g_config.hostname) {
      goto err;
    } else if (target) {
      g_config.passwddb_file = zt_strdup(target);
    } else {
      char *fname = get_password_bundle_file(g_config.hostname, false);
      if (!fname)
        return -1;
      g_config.passwddb_file = fname;
    }
  }
  }

  if (++target)
    goto err;

  set_exit_status(EXIT_STATUS_SUCCESS);
  return command;

err:
  log_error(NULL, "Bad set of arguments for command '%s'",
            command_names[command]);
  return -1;
}

void deinit_config(void) {
  zt_free(g_config.hostname);
  zt_free(g_config.passwddb_file);
  zt_free(g_config.ciphersuite);
  zt_free(g_config.filename);
}
