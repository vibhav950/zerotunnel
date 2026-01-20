/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * iomem.h - Thread-safe i/o buffer pool
 */

#ifndef __IOMEM_H__
#define __IOMEM_H__

#include <stddef.h>

#define IOMEM_BACKING_STORE_ALIGN 128

typedef struct _iomem_chunk_st {
  char *mem;
  size_t size;
} iomem_chunk_t;

typedef struct _iomem_pool_st iomem_pool_t;

/**
 * Return a new i/o memory pool
 *
 * @param[in] capacity   Number of chunks in the pool (must be power of 2)
 * @param[in] chunk_size Size of each chunk in bytes
 *
 * @return Pointer to the initialized iomem_pool_t structure, or NULL on error.
 */
iomem_pool_t *iomem_pool_new(size_t capacity, size_t chunk_size);

/** Deinitialize an i/o memory pool */
void iomem_pool_destroy(iomem_pool_t *pool);

/**
 * Get a chunk from the i/o memory pool
 *
 * This function blocks until a chunk is available.
 *
 * @param[in] pool Pointer to the iomem_pool_t instance
 *
 * @return Pointer to the allocated iomem_chunk_t chunk, or NULL on error.
 */
iomem_chunk_t *iomem_pool_get_chunk(iomem_pool_t *pool);

/**
 * Free a chunk back to the i/o memory pool
 *
 * @param[in] pool Pointer to the iomem_pool_t instance
 * @param[in] chunk Pointer to the iomem_chunk_t chunk to be freed
 *
 * @return void
 */
void iomem_pool_free_chunk(iomem_pool_t *pool, iomem_chunk_t *chunk);

/**
 * Get the size of each chunk in the i/o memory pool
 *
 * @param[in] pool Pointer to the iomem_pool_t instance
 *
 * @return Size of each chunk in bytes
 */
size_t iomem_pool_chunk_size(const iomem_pool_t *pool);

#endif /* __IOMEM_H__ */
