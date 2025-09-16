/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * kex.h
 */

#ifndef __KEX_H__
#define __KEX_H__

#include "common/defines.h"

// clang-format off

typedef enum {
  KEX_FLAG_ALLOC  = (1U << 0),
  KEX_FLAG_KEYGEN = (1U << 1),
} kex_flag_t;

/** List of potential KEX curves. For the option(s) to
  be available at runtime, they must  be made available
  by the underlying crypto library. */
enum {
  KEX_CURVE_secp256k1   = (1U << 0),
  KEX_CURVE_secp384r1   = (1U << 1),
  KEX_CURVE_secp521r1   = (1U << 2),
  KEX_CURVE_prime239v3  = (1U << 3),
  KEX_CURVE_prime256v1  = (1U << 4),
  KEX_CURVE_X25519      = (1U << 5),
  KEX_CURVE_X448        = (1U << 6),
};

// clang-format on

/* Fixed-size key-exchange curve identifier */
typedef uint8_t kex_curve_t;

/* kex_* pointers that are required but not yet defined */
typedef struct kex_st *kex_ptr_t;
typedef struct kex_peer_share_st *kex_peer_share_ptr_t;

typedef err_t (*kex_alloc_func_t)(kex_ptr_t *kex, kex_curve_t curve);

typedef void (*kex_dealloc_func_t)(kex_ptr_t kex);

typedef err_t (*kex_key_gen_func_t)(kex_ptr_t kex);

typedef err_t (*kex_get_peer_data_func_t)(kex_ptr_t kex, kex_peer_share_ptr_t peer_data);

typedef err_t (*kex_new_peer_data_func_t)(kex_peer_share_ptr_t peer_data,
                                          const uint8_t *ec_pub, size_t ec_pub_len,
                                          const uint8_t *ec_curvename,
                                          size_t ec_curvename_len);

typedef void (*kex_free_peer_data_func_t)(kex_peer_share_ptr_t peer_data);

typedef err_t (*kex_derive_shared_key_func_t)(kex_ptr_t kex,
                                              kex_peer_share_ptr_t peer_data,
                                              unsigned char **shared_key,
                                              size_t *shared_key_len);

typedef err_t (*kex_get_public_key_bytes_func_t)(kex_ptr_t kex, uint8_t **pubkey,
                                                 size_t *pubkey_len);

typedef struct kex_intf_st {
  kex_alloc_func_t alloc;
  kex_dealloc_func_t dealloc;
  kex_key_gen_func_t key_gen;
  kex_get_peer_data_func_t get_peer_data;
  kex_new_peer_data_func_t new_peer_data;
  kex_free_peer_data_func_t free_peer_data;
  kex_derive_shared_key_func_t derive_shared_key;
  kex_get_public_key_bytes_func_t get_public_key_bytes;
  kex_curve_t supported_curves;
} kex_intf_t;

typedef struct kex_peer_share_st {
  void *ec_pub;
  size_t ec_pub_len;
  void *ec_curvename;
  size_t ec_curvename_len;
} kex_peer_share_t;

typedef struct kex_st {
  const kex_intf_t *intf;
  kex_curve_t curve;
  void *ctx;
  kex_flag_t flags;
} kex_t;

/**
 * Get the string name of a KEX curve.
 *
 * @param[in] id KEX curve identifier
 * @return String representation of the curve identifier.
 */
const char *kex_curve_name(kex_curve_t id);

/**
 * Check if a KEX curve is supported by the given KEX interface.
 *
 * @param[in] intf KEX interface
 * @param[in] curve KEX curve identifier
 * @return 1 if supported, 0 otherwise
 */
int kex_intf_curve_is_supported(const kex_intf_t *intf, kex_curve_t curve);

/**
 * Get the value of a KEX flag.
 *
 * @param[in] kex KEX context
 * @param[in] flag KEX flag to check
 * @return 1 if the flag is set, 0 otherwise
 */
int kex_flag_get(kex_t *kex, kex_flag_t flag);

/**
 * Allocate resources for a KEX context.
 *
 * @param[in] intf KEX interface
 * @param[out] kex Pointer to pointer to allocated KEX context
 * @param[in] curve KEX curve identifier
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t kex_intf_alloc(const kex_intf_t *intf, kex_t **kex, kex_curve_t curve);

/**
 * Deallocate and securely erase a KEX context.
 *
 * @param[in] kex KEX context to deallocate
 * @return Void
 */
void kex_dealloc(kex_t *kex);

/**
 * Generate a public/private key pair.
 *
 * @param[in] kex KEX context
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t kex_key_gen(kex_t *kex);

/**
 * Get the peer data to share with the peer.
 *
 * @param[in] kex KEX context
 * @param[out] peer_data Pointer to peer data structure to populate
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @note The memory allocated in @p peer_data must be freed by calling
 * `kex_free_peer_data()` after use.
 *
 * @note This function may only be called after a successful call to
 * `kex_key_gen()`.
 */
err_t kex_get_peer_data(kex_t *kex, kex_peer_share_t *peer_data);

/**
 * Populate a peer data structure with the given public key and curve name.
 *
 * @param[in] kex KEX context
 * @param[out] peer_data Pointer to peer data structure to populate
 * @param[in] ec_pub Pointer to the peer's public key bytes
 * @param[in] ec_pub_len Length of the peer's public key bytes
 * @param[in] ec_curvename Pointer to the peer's curve name bytes (can be NULL)
 * @param[in] ec_curvename_len Length of the peer's curve name bytes (0 if not provided)
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @note The memory allocated in @p peer_data must be freed by calling
 * `kex_free_peer_data()` after use.
 */
err_t kex_new_peer_data(kex_t *kex, kex_peer_share_t *peer_data, const uint8_t *ec_pub,
                        size_t ec_pub_len, const uint8_t *ec_curvename,
                        size_t ec_curvename_len);

/**
 * Free the memory allocated in a peer data structure.
 *
 * @param[in] kex KEX context
 * @param[in] peer_data Pointer to peer data structure to free
 * @return Void
 */
void kex_free_peer_data(kex_t *kex, kex_peer_share_t *peer_data);

/**
 * Derive the shared secret using the peer's public key.
 *
 * @param[in] kex KEX context
 * @param[in] peer_data Pointer to peer data structure containing the peer's public key
 * @param[out] shared_key Pointer to buffer to hold the derived shared key (allocated by
 * the function)
 * @param[out] shared_key_len Length of the derived shared key buffer
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @note The memory allocated in @p shared_key must be securely freed by calling
 * `zt_clr_free()` after use.
 *
 * @note This function may only be called after a successful call to
 * `kex_key_gen()`.
 *
 */
err_t kex_derive_shared_key(kex_t *kex, kex_peer_share_t *peer_data,
                            unsigned char **shared_key, size_t *shared_key_len);

/**
 * Get the public key bytes to share with the peer.
 * @param[in] kex KEX context
 * @param[out] pubkey Pointer to buffer to hold the public key (allocated by the function)
 * @param[out] pubkey_len Length of the public key buffer
 * @return ERR_SUCCESS on success, error code otherwise
 * @note The memory allocated in @p pubkey must be freed by calling
 * `zt_clr_free()` after use.
 */
err_t kex_get_public_key_bytes(kex_t *kex, uint8_t **pubkey, size_t *pubkey_len);

#endif /* __KEX_H__ */
