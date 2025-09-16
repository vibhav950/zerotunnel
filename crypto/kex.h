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

typedef err_t (*kex_get_peer_data_func_t)(kex_ptr_t kex,
                                          kex_peer_share_ptr_t peer_data);

typedef err_t (*kex_new_peer_data_func_t)(kex_peer_share_ptr_t peer_data,
                                          const uint8_t *ec_pub,
                                          size_t ec_pub_len,
                                          const uint8_t *ec_curvename,
                                          size_t ec_curvename_len);

typedef void (*kex_free_peer_data_func_t)(kex_peer_share_ptr_t peer_data);

typedef err_t (*kex_derive_shared_key_func_t)(kex_ptr_t kex,
                                              kex_peer_share_ptr_t peer_data,
                                              unsigned char **shared_key,
                                              size_t *shared_key_len);

typedef err_t (*kex_get_public_key_bytes_func_t)(kex_ptr_t kex,
                                                 uint8_t **pubkey,
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

const char *kex_curve_name(kex_curve_t id);

int kex_intf_curve_is_supported(const kex_intf_t *intf, kex_curve_t curve);

int kex_flag_get(kex_t *kex, kex_flag_t flag);

err_t kex_intf_alloc(const kex_intf_t *intf, kex_t **kex, kex_curve_t curve);

void kex_dealloc(kex_t *kex);

err_t kex_key_gen(kex_t *kex);

err_t kex_get_peer_data(kex_t *kex, kex_peer_share_t *peer_data);

err_t kex_new_peer_data(kex_t *kex, kex_peer_share_t *peer_data,
                        const uint8_t *ec_pub, size_t ec_pub_len,
                        const uint8_t *ec_curvename, size_t ec_curvename_len);

void kex_free_peer_data(kex_t *kex, kex_peer_share_t *peer_data);

err_t kex_derive_shared_key(kex_t *kex, kex_peer_share_t *peer_data,
                            unsigned char **shared_key, size_t *shared_key_len);

err_t kex_get_public_key_bytes(kex_t *kex, uint8_t **pubkey,
                               size_t *pubkey_len);

#endif /* __KEX_H__ */
