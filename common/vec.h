/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * vec.h - vector implementation based on the one from wget2, originally written by Tim
 * Ruehsen. Modified for zerotunnel. Reference:
 * https://gitlab.com/gnuwget/wget2/-/blob/master/libwget/vector.c
 */

#ifndef __VEC_H__
#define __VEC_H__

#include "defines.h"

#include <stdarg.h>

/** Default vector capacity (max number of entries) */
#define ZT_VEC_DEFAULT_CAPACITY 128

/**
 * Default resize factor for vector capacity
 * After a resize, `new_size = old_size * resize_factor`
 */
#define ZT_VEC_DEFAULT_RESIZE_FACTOR 2.0

/** Comparison function for vector entries (compatible with stdlib qsort). */
typedef int(zt_vec_cmp_func_t)(const void *entry1, const void *entry2);

/** Iterator function for vector entries. */
typedef void(zt_vec_iter_func_t)(void *entry);

/** Search through the vector entries given \p search_arg ,returning `true` on a match. */
typedef bool(zt_vec_search_func_t)(const void *search_arg, const void *entry);

/** Function that returns `true` when an entry is found. */
typedef bool(zt_vec_find_func_t)(const void *entry);

/** The vector object */
typedef struct _zt_vec_st zt_vec_t;

zt_vec_t *zt_vec_new(size_t capacity, zt_vec_cmp_func_t *cmp);

int zt_vec_insert(zt_vec_t *vec, const void *entry, int idx);

int zt_vec_insert_sorted(zt_vec_t *vec, const void *entry);

int zt_vec_append(zt_vec_t *vec, const void *entry);

int zt_vec_append_shallowcopy(zt_vec_t *vec, const void *entry, size_t size);

int zt_vec_append_vprintf(zt_vec_t *vec, const char *fmt, va_list args);

int zt_vec_append_printf(zt_vec_t *vec, const char *fmt, ...);

int zt_vec_replace(zt_vec_t *vec, const void *entry, int idx);

void zt_vec_remove(zt_vec_t *vec, int idx);

void *zt_vec_remove_nofree(zt_vec_t *vec, int idx);

int zt_vec_move(zt_vec_t *vec, int old_idx, int new_idx);

int zt_vec_swap(zt_vec_t *vec, int idx1, int idx2);

void zt_vec_clear(zt_vec_t *vec);

void zt_vec_clear_nofree(zt_vec_t *vec);

void zt_vec_free(zt_vec_t **vec);

int zt_vec_deepcopy(zt_vec_t *dest, zt_vec_t *src);

int zt_vec_size(zt_vec_t *vec);

void *zt_vec_get(zt_vec_t *vec, int idx);

int zt_vec_search(zt_vec_t *vec, zt_vec_search_func_t *search_func,
                  const void *search_arg, void **out);

int zt_vec_find_memcmp(zt_vec_t *vec, const void *ele, size_t size, void **out);

int zt_vec_find(zt_vec_t *vec, const void *ele);

bool zt_vec_contains(zt_vec_t *vec, const void *ele);

int zt_vec_find_ex(zt_vec_t *vec, const void *ele, int start_idx, int direction,
                   zt_vec_find_func_t *find_func);

void zt_vec_iterate(zt_vec_t *vec, zt_vec_iter_func_t *iter_func);

void zt_vec_set_destructor(zt_vec_t *vec, zt_vec_iter_func_t *destructor);

void zt_vec_set_cmp_func(zt_vec_t *vec, zt_vec_cmp_func_t *cmp);

void zt_vec_set_resize_factor(zt_vec_t *vec, float factor);

void zt_vec_sort(zt_vec_t *vec);

#endif /* __VEC_H__ */
