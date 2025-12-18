/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * mpmcq.h - Header-only MPMC "Vyukov" queue
 */

#pragma once

#ifndef __MPMCQ_H__
#define __MPMCQ_H__

// clang-format off

#include "common/defines.h"
#include "common/timeout.h"

#include <stdatomic.h>
#include <stddef.h>

#define CACHELINE_SIZE 64

typedef char __cacheline_pad_t[CACHELINE_SIZE];

/** Each queue slot tracks an isolated memory region */
typedef struct mpmc_queue_slot_st {
  atomic_size_t seq;
  void *chunk;
} mpmc_queue_slot_t;

/** The MPMC queue object */
typedef struct mpmc_queue_st {
  // size_t capacity;  /* number of slots (power of 2) */
  __cacheline_pad_t __pad0;
  size_t mask;              /* read-mostly index mask (capacity - 1) */
  mpmc_queue_slot_t *slots; /* array[capacity] */
  __cacheline_pad_t __pad1;
  atomic_size_t head; /* dequeue position */
  __cacheline_pad_t __pad2;
  atomic_size_t tail; /* enqueue position */
  __cacheline_pad_t __pad3;
} mpmc_queue_t;

/**
 * Allocate memory for the allocated queue object \p q to hold \p capacity chunks.
 * The resulting queue is initialized in the empty state.
 * Note: \p capacity must be a power of 2.
 */
static bool mpmc_queue_init(mpmc_queue_t *q, size_t capacity) {
  ASSERT(q != NULL);
  ASSERT((capacity & (capacity - 1)) == 0);

  q->mask = capacity - 1;
  atomic_store_explicit(&q->head, 0, memory_order_relaxed);
  atomic_store_explicit(&q->tail, 0, memory_order_relaxed);

  q->slots = zt_calloc(capacity, sizeof(mpmc_queue_slot_t));
  if (!q->slots)
    return false;

  for (size_t i = 0; i < capacity; i++) {
    atomic_store_explicit(&q->slots[i].seq, i, memory_order_relaxed);
    q->slots[i].chunk = NULL;
  }
  return true;
}

// /**
//  * Check if the queue \p q is empty (for internal use only)
//  * Concurrent code might get inconsistent/stale results
//  */
// static inline bool _mpmc_queue_is_empty(mpmc_queue_t *q) {
//   size_t head = atomic_load_explicit(&q->head, memory_order_acquire);
//   size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
//   return head == tail;
// }

/**
 * Destroy the queue object \p q
 */
static void mpmc_queue_deinit(mpmc_queue_t *q) {
  ASSERT(q != NULL);

  if (q->slots) {
    zt_free(q->slots);
    q->slots = NULL;
  }
}

/* No flags */
#define MPMC_Q_NONE             0x00
/* Fail immediately if the queue is full on enqueue or empty on dequeue */
#define MPMC_Q_FAIL_IMMEDIATELY 0x01

/**
 * Enqueue a chunk into the MPMC queue \p q.
 *
 * @param[in] q The MPMC queue.
 * @param[in] chunk The chunk to enqueue.
 * @param[in] flags Operation flags (MPMC_Q_*).
 * @return 0 on success, -1 on failure.
 * 
 * - MPMC_Q_NONE will prevent failure by blocking the operation until
 *   the writer thread has enqueued a chunk (default behaviour).
 * - To avoid indefinite blocking, use the MPMC_Q_FAIL_IMMEDIATELY flag.
 */
static int mpmc_queue_enqueue(mpmc_queue_t *q, void *chunk, unsigned char flags) {
  mpmc_queue_slot_t *slot;
  size_t pos, seq;
  intptr_t diff;
  int pause = 32, pause32 = 64;

  while (1) {
    pos = atomic_load_explicit(&q->tail, memory_order_relaxed);
    slot = &q->slots[pos & q->mask];
    seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
    diff = (intptr_t)seq - (intptr_t)pos;

    if (diff == 0) {
      /* if the slot is free, try to acquire it */
      if (atomic_compare_exchange_weak_explicit(
              &q->tail, &pos, pos + 1, memory_order_relaxed, memory_order_relaxed)) {
        /* calling thread acquired this slot */
        slot->chunk = chunk;
        atomic_store_explicit(&slot->seq, pos + 1, memory_order_release);
        return 0;
      }
    } else if (diff < 0 && (flags & MPMC_Q_FAIL_IMMEDIATELY)) {
      /* queue is full and caller doesn't want to wait */
      return -1;
    } else {
      /* failed enqueue due to contention; try again */
      decaying_sleep(pause, pause32);
    }
  }
}

/**
 * Dequeue a chunk from the MPMC queue \p q.
 *
 * @param[in] q The MPMC queue.
 * @param[out] out Pointer to store the dequeued chunk.
 * @param[in] flags Operation flags (MPMC_Q_*).
 * @return 0 on success, -1 on failure.
 * 
 * - MPMC_Q_NONE will prevent failure by blocking the operation until
 *   the reader thread has consumed a chunk (default behaviour).
 * - To avoid indefinite blocking, use the MPMC_Q_FAIL_IMMEDIATELY flag.
 */
static int mpmc_queue_dequeue(mpmc_queue_t *q, void **out, unsigned char flags) {
  mpmc_queue_slot_t *slot;
  size_t pos, seq;
  intptr_t diff;
  int pause = 32, pause32 = 64;

  while (1) {
    pos = atomic_load_explicit(&q->head, memory_order_relaxed);
    slot = &q->slots[pos & q->mask];
    seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
    diff = (intptr_t)seq - (intptr_t)(pos + 1);

    if (diff == 0) {
      /* if the slot is ready, try to acquire it */
      if (atomic_compare_exchange_weak_explicit(
              &q->head, &pos, pos + 1, memory_order_relaxed, memory_order_relaxed)) {
        /* calling thread acquired this slot */
        void *chunk = slot->chunk;
        slot->chunk = NULL;
        atomic_store_explicit(&slot->seq, pos + q->mask + 1, memory_order_release);
        *out = chunk;
        return 0;
      }
    } else if (diff < 0 && (flags & MPMC_Q_FAIL_IMMEDIATELY)) {
      /* queue is empty and caller doesn't want to wait */
      return -1;
    } else {
      /* failed dequeue due to contention; try again */
      decaying_sleep(pause, pause32);
    }
  }
}

#undef CACHELINE_SIZE

#endif /* __MPMCQ_H__ */
