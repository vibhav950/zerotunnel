/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * hmac.h - Hash-based Message Authentication Code
 */

#ifndef __HMAC_H__
#define __HMAC_H__

#include "common/defines.h"

// clang-format off

typedef enum {
  HMAC_FLAG_ALLOC = (1U << 0),
  HMAC_FLAG_INIT  = (1U << 1),
} hmac_flag_t;

/* List of potential HMAC algorithms; the underlying
  crypto library must provide these options at runtime */
enum {
  HMAC_SHA256     = (1U << 0),
  HMAC_SHA384     = (1U << 1),
  HMAC_SHA512     = (1U << 2),
  HMAC_SHA3_256   = (1U << 3),
  HMAC_SHA3_384   = (1U << 4),
  HMAC_SHA3_512   = (1U << 5),
  HMAC_ALG_ALL    = HMAC_SHA256 |
                    HMAC_SHA384 |
                    HMAC_SHA512 |
                    HMAC_SHA3_256 |
                    HMAC_SHA3_384 |
                    HMAC_SHA3_512,
};

// clang-format on

/** Fixed-size HMAC identifier */
typedef uint8_t hmac_alg_t;

/** A pointer type for @p hmac_st, which is defined later */
typedef struct hmac_st *hmac_ptr_t;

typedef err_t (*hmac_alloc_func_t)(hmac_ptr_t *h, size_t key_len, size_t out_len,
                                   hmac_alg_t alg);

typedef void (*hmac_dealloc_func_t)(hmac_ptr_t ctx);

typedef err_t (*hmac_init_func_t)(hmac_ptr_t h, const uint8_t *key, size_t key_len);

typedef err_t (*hmac_update_func_t)(hmac_ptr_t h, const uint8_t *data, size_t data_len);

typedef err_t (*hmac_compute_func_t)(hmac_ptr_t h, const uint8_t *msg, size_t msg_len,
                                     uint8_t *digest, size_t digest_len);

typedef struct hmac_intf_st {
  hmac_alloc_func_t alloc;
  hmac_dealloc_func_t dealloc;
  hmac_init_func_t init;
  hmac_update_func_t update;
  hmac_compute_func_t compute;
  hmac_alg_t supported_algs;
} hmac_intf_t;

typedef struct hmac_st {
  const hmac_intf_t *intf;
  void *ctx;
  hmac_ptr_t h;
  size_t key_len;
  hmac_alg_t alg;
  unsigned int flags;
} hmac_t;

/**
 * Get string name of HMAC algorithm.
 *
 * @param[in] alg HMAC algorithm
 * @return String representation of the HMAC algorithm
 */
const char *hmac_alg_to_string(hmac_alg_t alg);

/**
 * Check if an HMAC algorithm is supported by the given HMAC interface.
 *
 * @param[in] intf HMAC interface
 * @param[in] alg  HMAC algorithm to check
 * @return Non-zero if supported, zero otherwise
 */
int hmac_intf_alg_is_supported(const hmac_intf_t *intf, hmac_alg_t alg);

/**
 * Get the status of a specific flag in the HMAC context.
 *
 * @param[in] h    HMAC context
 * @param[in] flag HMAC flag to check
 * @return Non-zero if the flag is set, zero otherwise
 */
int hmac_flag_get(hmac_t *h, hmac_flag_t flag);

/**
 * Get the length of the HMAC digest in bytes.
 *
 * @param[in] h HMAC context
 * @return Length of the HMAC digest in bytes, or 0 if h is NULL
 */
size_t hmac_digest_len(hmac_t *h);

/**
 * Allocate an HMAC context using the specified HMAC interface.
 *
 * @param[in] intf    HMAC interface
 * @param[out] h      Pointer to the allocated HMAC context (also a pointer)
 * @param[in] key_len Length of the HMAC key
 * @param[in] out_len Length of the output digest
 * @param[in] alg     HMAC algorithm
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @note The allocated HMAC context must be deallocated using `hmac_dealloc()`.
 */
err_t hmac_intf_alloc(const hmac_intf_t *intf, hmac_t **h, size_t key_len, size_t out_len,
                      hmac_alg_t alg);

/**
 * Deallocate and securely erase an HMAC context.
 *
 * @param[in] h HMAC context to deallocate
 * @return Void
 */
void hmac_dealloc(hmac_t *h);

/**
 * Initialize an HMAC context with the specified key.
 *
 * @param[in] h HMAC context
 * @param[in] key HMAC key
 * @param[in] key_len Length of the HMAC key
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t hmac_init(hmac_t *h, const uint8_t *key, size_t key_len);

/**
 * Update the HMAC context with message data.
 *
 * @param[in] h HMAC context
 * @param[in] msg Message data (can be NULL if msg_len is 0)
 * @param[in] msg_len Length of the message data
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t hmac_update(hmac_t *h, const uint8_t *msg, size_t msg_len);

/**
 * Compute the HMAC digest of the provided message.
 *
 * @param[in] h HMAC context
 * @param[in] msg Message data (can be NULL)
 * @param[in] msg_len Length of the message data
 * @param[out] digest Output buffer for the HMAC digest
 * @param[in] digest_len Length of the output buffer
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t hmac_compute(hmac_t *h, const uint8_t *msg, size_t msg_len, uint8_t *digest,
                   size_t digest_len);

#endif /* __HMAC_H__ */
