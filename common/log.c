#include "log.h"
#include "defines.h"

#include <stdarg.h>
#include <stdio.h>

struct logger_cb_chain_node {
  log_cb cb;
  void *args;
  struct logger_cb_chain_node *next;
};

static zt_logger_t global_logger;

const char *zt_error_str(err_t err) {
  switch (err) {
  case ERR_SUCCESS:
    return "success";
  case ERR_NOT_ALLOC:
    return "memory/interface not allocated";
  case ERR_NOT_INIT:
    return "not initialized";
  case ERR_NULL_PTR:
    return "null pointer argument(s)";
  case ERR_BAD_ARGS:
    return "invalid argument(s)";
  case ERR_MEM_FAIL:
    return "out of memory";
  case ERR_BUFFER_TOO_SMALL:
    return "buffer too small";
  case ERR_REQUEST_TOO_LARGE:
    return "request exceeded maximum allowed size";
  case ERR_NOT_SUPPORTED:
    return "operation not supported";
  case ERR_INTERNAL:
    return "internal library failure";
  case ERR_INVALID:
    return "invalid operation sequence";
  case ERR_OPERATION_LIMIT_REACHED:
    return "operation limit reached";
  case ERR_BAD_CONTROL_FLOW:
    return "deviated from expected control flow";
  case ERR_INVALID_DATUM:
    return "mismatch from expected data";
  case ERR_HSHAKE_ABORTED:
    return "handshake aborted due to failure";
  case ERR_AUTH_FAIL:
    return "authentication failure";
  case ERR_AGAIN:
    return "try again";
  case ERR_TIMEOUT:
    return "operation timed out";
  case ERR_NORESOLVE:
    return "could not resolve host";
  case ERR_TCP_ACCEPT:
    return "failed to accept TCP connection";
  case ERR_TCP_CONNECT:
    return "TCP connection failed";
  case ERR_TCP_SEND:
    return "TCP send failed";
  case ERR_TCP_RECV:
    return "TCP receive failed";
  case ERR_ALREADY:
    return "already in progress";
  case ERR_FIO_READ:
    return "failed to read file";
  case ERR_FIO_WRITE:
    return "failed to write file";
  case ERR_EOF:
    return "end of file reached";
  default:
    return "unknown error";
  }
}

#define WALK_CB_CHAIN(chain)                                                   \
  do {                                                                         \
    struct logger_cb_chain_node *cur = (struct logger_cb_chain_node *)(chain); \
    while (cur) {                                                              \
      cur->cb(cur->args);                                                      \
      cur = cur->next;                                                         \
    }                                                                          \
  } while (0)

void zt_log_debug(zt_logger_t *logger, const char *fmt, ...) {
  va_list args;

  logger = logger ? logger : &global_logger;

  if (logger->level == LOG_LEVEL_DEBUG) {
    WALK_CB_CHAIN(logger->before_cb_chain);

    fprintf(LOG_FP_DEBUG, "%s[DEBUG %s] ", FG_BLUE, logger->name);
    va_start(args, fmt);
    vfprintf(LOG_FP_DEBUG, fmt, args);
    va_end(args);
    fprintf(LOG_FP_DEBUG, "%s\n", FG_CLEAR);

    WALK_CB_CHAIN(logger->after_cb_chain);
  }
}

void zt_log_info(zt_logger_t *logger, const char *fmt, ...) {
  va_list args;

  logger = logger ? logger : &global_logger;

  if (logger->level <= LOG_LEVEL_INFO) {
    WALK_CB_CHAIN(logger->before_cb_chain);

    fprintf(LOG_FP_INFO, "%s[INFO %s] ", FG_MAGENTA, logger->name);
    va_start(args, fmt);
    vfprintf(LOG_FP_INFO, fmt, args);
    va_end(args);
    fprintf(LOG_FP_INFO, "%s\n", FG_CLEAR);

    WALK_CB_CHAIN(logger->after_cb_chain);
  }
}

void zt_log_warn(zt_logger_t *logger, const char *fmt, ...) {
  va_list args;

  logger = logger ? logger : &global_logger;

  if (logger->level <= LOG_LEVEL_WARN) {
    WALK_CB_CHAIN(logger->before_cb_chain);

    fprintf(LOG_FP_WARN, "%s[WARN %s] ", FG_YELLOW, logger->name);
    va_start(args, fmt);
    vfprintf(LOG_FP_WARN, fmt, args);
    va_end(args);
    fprintf(LOG_FP_WARN, "%s\n", FG_CLEAR);

    WALK_CB_CHAIN(logger->after_cb_chain);
  }
}

void zt_log_error(zt_logger_t *logger, const char *fmt, ...) {
  va_list args;

  logger = logger ? logger : &global_logger;

  WALK_CB_CHAIN(logger->before_cb_chain);

  fprintf(LOG_FP_ERROR, "%s[ERROR %s] ", FG_RED, logger->name);
  va_start(args, fmt);
  vfprintf(LOG_FP_ERROR, fmt, args);
  va_end(args);
  fprintf(LOG_FP_ERROR, "%s\n", FG_CLEAR);

  WALK_CB_CHAIN(logger->after_cb_chain);
}

void zt_log_fatal(const char *fmt, ...) {
  va_list args;

  fprintf(LOG_FP_ERROR, "%s[FATAL %s] ", FG_RED, "");
  va_start(args, fmt);
  vfprintf(LOG_FP_ERROR, fmt, args);
  va_end(args);
  fprintf(LOG_FP_ERROR, "%s\n", FG_CLEAR);
  exit(EXIT_FAILURE);
}

zt_logger_t *zt_logger_new(const char *name, zt_log_t level) {
  zt_logger_t *logger = zt_malloc(sizeof(zt_logger_t));
  if (logger) {
    strcpy(logger->name, name ? name : "unknown");
    logger->level = level;
  }
  return logger;
}

void zt_logger_set_level(zt_logger_t *logger, zt_log_t level) {
  logger = logger ? logger : &global_logger;
  logger->level = level;
}

zt_log_t zt_logger_get_level(zt_logger_t *logger) {
  return logger ? logger->level : global_logger.level;
}

static inline int _add_cb(struct logger_cb_chain_node **head, log_cb cb,
                          void *args) {
  struct logger_cb_chain_node *new_node, *p;

  new_node = malloc(sizeof(struct logger_cb_chain_node));
  if (!new_node)
    return -1;
  new_node->cb = cb;
  new_node->args = args;
  new_node->next = NULL;

  if (!*head) {
    *head = new_node;
  } else {
    p = *head;
    while (p->next)
      p = p->next;
    p->next = new_node;
  }

  return 0;
}

int zt_logger_append_before_cb(zt_logger_t *logger, log_cb cb, void *args) {
  logger = logger ? logger : &global_logger;

  if (cb && logger->before_chain_len < ZT_LOGGER_MAX_CB_CHAIN_LEN) {
    int rv = _add_cb((struct logger_cb_chain_node **)&logger->before_cb_chain,
                     cb, args);

    if (rv == 0) {
      logger->before_chain_len++;
      return 0;
    }
  }
  return -1;
}

int zt_logger_append_after_cb(zt_logger_t *logger, log_cb cb, void *args) {
  logger = logger ? logger : &global_logger;

  if (cb && logger->after_chain_len < ZT_LOGGER_MAX_CB_CHAIN_LEN) {
    int rv = _add_cb((struct logger_cb_chain_node **)&logger->after_cb_chain,
                     cb, args);

    if (rv == 0) {
      logger->after_chain_len++;
      return 0;
    }
  }
  return -1;
}

static inline void _remove_cb(struct logger_cb_chain_node **head, log_cb cb) {
  struct logger_cb_chain_node *p = *head, *prev = NULL;

  while (p) {
    if (p->cb == cb) {
      if (prev)
        prev->next = p->next;
      else
        *head = p->next;

      free(p);
      return;
    }
    prev = p;
    p = p->next;
  }
}

void zt_logger_remove_before_cb(zt_logger_t *logger, log_cb cb) {
  logger = logger ? logger : &global_logger;

  if (cb && logger->before_cb_chain) {
    _remove_cb((struct logger_cb_chain_node **)&logger->before_cb_chain, cb);
    logger->before_chain_len--;
  }
}

void zt_logger_remove_after_cb(zt_logger_t *logger, log_cb cb) {
  logger = logger ? logger : &global_logger;

  if (cb && logger->after_cb_chain) {
    _remove_cb((struct logger_cb_chain_node **)&logger->after_cb_chain, cb);
    logger->after_chain_len--;
  }
}
