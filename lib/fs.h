/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * fs.h - Filesystem iteration utilities
 */

#ifndef __FS_H__
#define __FS_H__

#include "common/defines.h"

/** Object representing a single filesystem entry */
typedef struct _fs_entry_st fs_entry_t;

/** Opaque object representing an iterator for multiple filesystem entries */
typedef struct _fs_iter_st fs_iter_t;

struct _fs_entry_st {
  char *name;    /* path relative to the target root directory */
  uint64_t size; /* physical size in bytes */
  uint32_t mode; /* permission flags */
  uint32_t id;   /* 32-bit streamId */
};

typedef enum {
  FS_ITER_ORDER_NONE = 0, /* No specific order */
  FS_ITER_ORDER_NAME_ASC, /* Order by name ascending */
  FS_ITER_ORDER_NAME_DSC, /* Order by name descending */
  FS_ITER_ORDER_SIZE_ASC, /* Order by size ascending */
  FS_ITER_ORDER_SIZE_DSC, /* Order by size descending */
} fs_iter_order_t;

err_t fs_iter_new(fs_iter_t *iter, const char *path, fs_iter_order_t order, int limit,
                  secure_random_func_t *f_rand);

void fs_iter_destroy(fs_iter_t *iter);

err_t fs_iter_export(fs_iter_t *iter, uint8_t **buf, size_t *len);

err_t fs_iter_import(fs_iter_t *iter, const uint8_t *buf, size_t len);

#endif /* __FS_H__ */
