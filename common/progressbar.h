/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * progressbar.h
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * Initialize the file transfer progressbar. This function MUST be paired with a
 * call to `zt_progressbar_destroy()` to avoid memory leaks. This will install
 * hooks to the global logger and start the progressbar update thread.
 *
 * @note Make sure that the necessary signal handlers are set up to handle
 * window size changes before this function is called.
 *
 * @return 0 on success, -1 on failure.
 */
int zt_progressbar_init(void);

/** Destroy the progressbar. */
void zt_progressbar_destroy(void);

/**
 * Start the progressbar for a file transfer. This function should be called
 * before starting the transfer and after a successful call to
 * `zt_progressbar_init()`. The output window will be updated with the transfer
 * details.
 * @param recipient The name of the recipient (must be NUL-terminated).
 * @param filename The name of the file being transferred (must be
 * NUL-terminated).
 * @param filesize The total size of the file in bytes.
 *
 * @return void.
 */
void zt_progressbar_begin(const char *recipient, const char *filename, size_t filesize);

/**
 * Update the progressbar with the number of bytes transferred since the last
 * call. This function should be called recurrently as the file transfer progresses.
 *
 * @param nbytes The number of bytes transferred since the last call.
 *
 * @return void.
 */
void zt_progressbar_update(size_t xferd_size);

/**
 * Mark the output window size as changed. This function should be called when
 * the terminal window size changes (e.g., on SIGWINCH signal). The next refresh
 * will adjust the progressbar to the new window size.
 *
 * @return void.
 */
void zt_progressbar_winsize_changed(void);

/**
 * Mark the progressbar as completed. This function should be called when the
 * file transfer is completed. The next update will cleanup the output window.
 *
 * @return void.
 */
void zt_progressbar_complete(void);
