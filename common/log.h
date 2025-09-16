/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * log.h - Logging utilities
 */

#ifndef __LOG_H__
#define __LOG_H__

#include "defines.h"

typedef void (*log_cb)(void *args);

// clang-format off
typedef enum {
   LOG_LEVEL_DEBUG  = 0,
  LOG_LEVEL_INFO    = 1,
  LOG_LEVEL_WARN    = 2,
  LOG_LEVEL_ERROR   = 3,
} zt_log_t;

#define ZT_LOGGER_MAX_NAME           32
#define ZT_LOGGER_MAX_CB_CHAIN_LEN   8

typedef struct zt_logger_st {
  char name[ZT_LOGGER_MAX_NAME];
  void *before_cb_chain;
  void *after_cb_chain;
  int before_chain_len, after_chain_len;
  zt_log_t level;
} zt_logger_t;

#ifndef LOG_FP_DEBUG
#define LOG_FP_DEBUG      stderr
#endif

#ifndef LOG_FP_ERROR
#define LOG_FP_ERROR      stderr
#endif

#ifndef LOG_FP_INFO
#define LOG_FP_INFO       stderr
#endif

#ifndef LOG_FP_WARN
#define LOG_FP_WARN       stderr
#endif

/* Log text colors */
#define FG_BLUE           "\x1B[94m"
#define FG_MAGENTA        "\x1B[95m"
#define FG_RED            "\x1B[91m"
#define FG_GREEN          "\x1B[92m"
#define FG_YELLOW         "\x1B[33m"
#define FG_CLEAR          "\x1B[0m"
/* Log text formatting */
#define FG_BOLD           "\x1B[1m"
#define FG_UNDERLINE      "\x1B[4m"
// clang-format on

/**
 * Initialize a new logger with the given name and log level.
 *
 * @param name The name of the logger.
 * @param level The log level for the logger.
 * @return A pointer to the initialized logger, or NULL on failure.
 */
zt_logger_t *zt_logger_new(const char *name, zt_log_t level);

/**
 * Set the log level of a logger.
 *
 * @param logger The logger to modify. If NULL, the global logger will be used.
 * @param level The new log level for the logger.
 * @return void.
 */
void zt_logger_set_level(zt_logger_t *logger, zt_log_t level);

/**
 * Get the log level of a logger.
 *
 * @param logger The logger to query. If NULL, the global logger will be used.
 * @return The log level of the logger.
 */
zt_log_t zt_logger_get_level(zt_logger_t *logger);

/**
 * Append a callback function to a logger's callback chain that will be invoked
 * before the log message is printed. The relative order of callbacks in the
 * chain is preserved when these callbacks are invoked.
 *
 * @note Cannot have more than `ZT_LOGGER_MAX_CB_CHAIN_LEN` callbacks in the
 *       'before' chain of any one logger.
 * @note These callback functions should take care of things like rearranging
 *       the output stream before a log is about to be printed to it.
 *       These are NOT meant for exception handling. No callbacks will be
 *       invoked if the log level of the logger is lower than the log level
 *       of the message being logged, otherwise all installed callbacks will
 *       be invoked in the order they were added.
 * @note Do not add the same callback function multiple times to a logger.
 *
 * @param logger The logger to modify. If NULL, the global logger will be used.
 * @param cb The callback function to append.
 * @param arg The argument to pass to the callback function.
 * @return 0 on success, or -1 on failure.
 */
int zt_logger_append_before_cb(zt_logger_t *logger, log_cb cb, void *args);

/**
 * Remove a callback function that was added to this logger's 'before' callback
 * chain using `zt_logger_append_before_cb()`. If the callback function is not
 * found, no changes are made.
 *
 * @note This function will remove the first occurrence of the callback
 *       function in the 'before' chain. The callback function must only
 *       appear once in the chain to begin with.
 *
 * @param logger The logger to modify. If NULL, the global logger will be used.
 * @param cb The callback function to remove.
 * @param args The argument to match the callback function.
 * @return 0 on success, or -1 on failure.
 */
void zt_logger_remove_before_cb(zt_logger_t *logger, log_cb cb);

/**
 * Append a callback function to a logger's callback chain that will be
 * invoked after the log message is printed. The relative order of callbacks in
 * the chain is preserved when these callbacks are invoked.
 *
 * @note Cannot have more than `ZT_LOGGER_MAX_CB_CHAIN_LEN` callbacks in the
 *       'after' chain of any one logger.
 * @note The callback will not be invoked if the log level of the logger is
 *       lower than the log level of the message being logged, otherwise all
 *       installed callbacks will be invoked in the order they were added.
 * @note Do not add the same callback function multiple times to a logger.
 *
 * @param logger The logger to modify. If NULL, the global logger will be used.
 * @param cb The callback function to append.
 * @param arg The argument to pass to the callback function.
 * @return 0 on success, or -1 on failure.
 */
int zt_logger_append_after_cb(zt_logger_t *logger, log_cb cb, void *args);

/**
 * Remove a callback function that was added to this logger's 'after' callback
 * chain using `zt_logger_append_after_cb()`. If the callback function is not
 * found, no changes are made.
 *
 * @note This function will remove the first occurrence of the callback
 *       function in the 'after' chain. The callback function must only
 *       appear once in the chain to begin with.
 *
 * @param logger The logger to modify. If NULL, the global logger will be used.
 * @param cb The callback function to remove.
 * @param args The argument to match the callback function.
 * @return 0 on success, or -1 on failure.
 */
void zt_logger_remove_after_cb(zt_logger_t *logger, log_cb cb);

// =============================================================================

void zt_log_debug(zt_logger_t *logger, const char *fmt, ...)
    ATTRIBUTE_FORMAT_PRINTF(2, 3);

void zt_log_info(zt_logger_t *logger, const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(2, 3);

void zt_log_warn(zt_logger_t *logger, const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(2, 3);

void zt_log_error(zt_logger_t *logger, const char *fmt, ...)
    ATTRIBUTE_FORMAT_PRINTF(2, 3);

/**
 * Log an error message using the global logger and exit with failure.
 *
 * @warning This function will ignore any before/after callback chains
 * installed on the global logger.
 */
extern void zt_log_fatal(const char *fmt, ...)
    ATTRIBUTE_FORMAT_PRINTF(1, 2) ATTRIBUTE_NORETURN;

#if defined(DEBUG)
#define log_debug(logger, fmt, ...)                                                      \
  zt_log_debug(logger, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define log_info(logger, fmt, ...)                                                       \
  zt_log_info(logger, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define log_warn(logger, fmt, ...)                                                       \
  zt_log_warn(logger, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define log_error(logger, fmt, ...)                                                      \
  zt_log_error(logger, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else /* DEBUG */
#define log_debug(logger, fmt, ...) zt_log_debug(logger, fmt, ##__VA_ARGS__)

#define log_info(logger, fmt, ...) zt_log_info(logger, fmt, ##__VA_ARGS__)

#define log_warn(logger, fmt, ...) zt_log_warn(logger, fmt, ##__VA_ARGS__)

#define log_error(logger, fmt, ...) zt_log_error(logger, fmt, ##__VA_ARGS__)

#endif /* DEBUG */

/** Get a string representation of an error code. */
const char *zt_error_str(err_t err);

#endif /* __LOG_H__ */
