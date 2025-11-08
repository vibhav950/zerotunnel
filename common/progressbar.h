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

#include <stddef.h>

#include "log.h"

/** Progress bar object */
typedef struct _progressbar_st progressbar_t;

/**
 * Create a progressbar with independent slots per transfer. If @p bar is NULL,
 * a new object will be heap-allocated and must be freed with `zt_progressbar_free()`.
 * @param[in] bar Pointer to a @p progressbar_t object, or NULL.
 * @param[in] slots Number of slots in the progressbar.
 * @param[in] logger Pointer to the currently active logger.
 * @return Pointer to initialized @p progressbar_t object.
 */
progressbar_t *zt_progressbar_init(progressbar_t *bar, int slots, zt_logger_t *logger);

/**
 * Release the progressbar's resources without freeing the @p bar pointer itself.
 * @param[in] bar Pointer to an initialized @p progressbar_t object.
 * @return void.
 */
void zt_progressbar_deinit(progressbar_t *bar);

/**
 * Free the @p bar pointer and all associated resources.
 * @param[in] bar Pointer to an initialized @p progressbar_t object.
 * @return void.
 */
void zt_progressbar_free(progressbar_t *bar);

/**
 * Update the number of slots printed on the screen. This function will instantly reserve
 * the required number of lines for @p nslots progressbar slots on the screen.
 * If @p nslots is lower than the slots already drawn on the screen, nothing happens.
 * @param[in] bar Pointer to an initialized @p progressbar_t object.
 * @param[in] nslots Number of slots in the progressbar.
 * @return void.
 */
void zt_progressbar_set_slots(progressbar_t *bar, int nslots);

/**
 * Enable the progressbar slot indexed @p slot for a new transfer.
 * This function should be called before the associated transfer begins.
 * @param[in] bar Pointer to an initialized @p progressbar_t object.
 * @param[in] slot Index of the slot to begin (0-based).
 * @param[in] filename Name of the file being transferred (can be NULL).
 * @param[in] recipient Name of the transfer recipient (can be NULL).
 * @param[in] filesize Total size of the file being transferred (in bytes).
 * @param[in] upload True if the transfer is an upload, false if download.
 * @return void.
 */
void zt_progressbar_slot_begin(progressbar_t *bar, int slot, const char *filename,
                               const char *recipient, size_t filesize, bool upload);

/**
 * Update the progressbar slot indexed @p slot with the number of bytes transferred since
 * the last call. This function should be called recurrently as the transfer associated
 * with this slot progresses.
 * @param[in] bar Pointer to an initialized @p progressbar_t object.
 * @param[in] slot Index of the slot to update (0-based).
 * @param[in] nbytes The number of bytes transferred since the last call.
 * @return void.
 */
void zt_progressbar_update(progressbar_t *bar, int slot, size_t nbytes);

/**
 * Mark the progressbar slot indexed @p slot as complete. This function should be called
 * when the transfer associated with this slot finishes.
 * @param[in] bar Pointer to an initialized @p progressbar_t object.
 * @param[in] slot Index of the slot to mark as complete (0-based).
 * @return void.
 */
void zt_progressbar_slot_complete(progressbar_t *bar, int slot);

/**
 * Mark the output window size as changed. This function should be called when
 * the terminal window size changes (e.g., on SIGWINCH signal). The next refresh
 * will adjust the progressbar to the new window size.
 * @return void.
 */
void zt_progressbar_winsize_changed(void);
