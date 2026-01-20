/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * iomem.c - Thread-safe i/o buffer pool
 */

#include "iomem.h"
#include "common/defines.h"
#include "common/mpmcq.h"

#include <errno.h>
#include <stdlib.h>

struct _iomem_pool_st {
  void *backing;         /* internal memory backing, passed to free() */
  iomem_chunk_t *chunks; /* array[capacity] */
  size_t chunk_size;     /* size of each chunk in bytes */
  size_t capacity;       /* total number of chunks */
  void *const free_q;    /* queue of free chunks */
};

iomem_pool_t *iomem_pool_new(size_t capacity, size_t chunk_size) {
  iomem_pool_t *pool;
  size_t nmem;
  int rv;

  /* must be power of 2 */
  if ((capacity & (capacity - 1)) != 0)
    return NULL;

  nmem = chunk_size * capacity;
  if (nmem / chunk_size != capacity)
    goto cleanup0;

  pool = zt_calloc(1, sizeof(iomem_pool_t));
  if (!pool)
    return NULL;

  pool->capacity = capacity;
  pool->chunk_size = chunk_size;

  /* allocate backing memory for this mempool */
  pool->backing = zt_aligned_alloc(IOMEM_BACKING_STORE_ALIGN, nmem);
  if (!pool->backing)
    goto cleanup0;

  pool->chunks = zt_calloc(capacity, sizeof(iomem_chunk_t));
  if (!pool->chunks)
    goto cleanup1;

  if (!mpmc_queue_init(pool->free_q, capacity))
    goto cleanup2;

  /* carve backing into chunks and enqueue all of them */
  char *base = (char *)pool->backing;
  for (size_t i = 0; i < capacity; ++i) {
    pool->chunks[i].mem = base + i * chunk_size;
    pool->chunks[i].size = chunk_size;
    /* push into free queue */
    rv = mpmc_queue_enqueue(pool->free_q, &pool->chunks[i], MPMC_Q_FAIL_IMMEDIATELY);
    ASSERT(rv == 0);
  }

  return pool;

cleanup3:
  iomem_pool_destroy(pool);
cleanup2:
  zt_free(pool->chunks);
cleanup1:
  zt_free(pool->backing);
cleanup0:
  zt_free(pool);
  return NULL;
}

void iomem_pool_destroy(iomem_pool_t *pool) {
  mpmc_queue_deinit(pool->free_q);
  zt_free(pool->chunks);
  zt_free(pool->backing);
  memset(pool, 0, sizeof(*pool));
}

iomem_chunk_t *iomem_pool_get_chunk(iomem_pool_t *pool) {
  iomem_chunk_t *chunk = NULL;

  /* dequeue a free chunk from the pool, blocking this thread till we get memory */
  (void)mpmc_queue_dequeue(pool->free_q, PTRV(&chunk), MPMC_Q_NONE);
  return chunk;
}

void iomem_pool_free_chunk(iomem_pool_t *pool, iomem_chunk_t *chunk) {
  /* return the chunk to the free queue */
  int rv = mpmc_queue_enqueue(pool->free_q, chunk, MPMC_Q_FAIL_IMMEDIATELY);
  ASSERT(rv == 0);
}

size_t iomem_pool_chunk_size(const iomem_pool_t *pool) { return pool->chunk_size; }