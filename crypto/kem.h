/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * kem.h
 */

#ifndef __KEM_H__
#define __KEM_H__

#include "common/defines.h"

// clang-format off

typedef enum {
  KEM_FLAG_ALLOC          = (1U << 0),
  KEM_FLAG_KEYGEN         = (1U << 1),
} kem_flag_t;

enum {
  KEM_Kyber_512           = (1U << 0),
  KEM_Kyber_768           = (1U << 1),
  KEM_Kyber_1024          = (1U << 2),
};

// clang-format on

/* Fixed-size KEM algorithm identifier */
typedef uint8_t kem_alg_t;

/* Forward declaration */
typedef struct kem_st *kem_ptr_t;

typedef err_t (*kem_alloc_func_t)(kem_ptr_t *kem, kem_alg_t alg);

typedef void (*kem_dealloc_func_t)(kem_ptr_t kem);

typedef void (*kem_mem_free_func_t)(void *ptr, size_t len);

typedef err_t (*kem_keygen_func_t)(kem_ptr_t kem, uint8_t **pubkey,
                                   size_t *pubkey_len);

typedef err_t (*kem_encapsulate_func_t)(kem_ptr_t kem,
                                        const uint8_t *peer_pubkey,
                                        size_t peer_pubkey_len, uint8_t **ct,
                                        size_t *ct_len, uint8_t **ss,
                                        size_t *ss_len);

typedef err_t (*kem_decapsulate_func_t)(kem_ptr_t kem, const uint8_t *ct,
                                        size_t ct_len, uint8_t **ss,
                                        size_t *ss_len);

typedef struct kem_intf_st {
  kem_alloc_func_t alloc;
  kem_dealloc_func_t dealloc;
  kem_mem_free_func_t mem_free;
  kem_keygen_func_t keygen;
  kem_encapsulate_func_t encapsulate;
  kem_decapsulate_func_t decapsulate;
  kem_alg_t supported_algs;
} kem_intf_t;

typedef struct kem_st {
  const kem_intf_t *intf;
  void *ctx;
  uint8_t *privkey;
  size_t privkey_len;
  kem_alg_t alg;
  kem_flag_t flags;
} kem_t;

const char *kem_alg_to_string(kem_alg_t alg);

int kem_intf_alg_is_supported(const kem_intf_t *intf, kem_alg_t alg);

int kem_flag_get(kem_t *kem, kem_flag_t flag);

err_t kem_intf_alloc(const kem_intf_t *intf, kem_t **kem, kem_alg_t alg);

void kem_dealloc(kem_t *kem);

void kem_mem_free(const kem_intf_t *intf, void *ptr, size_t len);

err_t kem_keygen(kem_t *kem, uint8_t **pubkey, size_t *pubkey_len);

err_t kem_encapsulate(kem_t *kem, const uint8_t *peer_pubkey,
                      size_t peer_pubkey_len, uint8_t **ct, size_t *ct_len,
                      uint8_t **ss, size_t *ss_len);

err_t kem_decapsulate(kem_t *kem, const uint8_t *ct, size_t ct_len,
                      uint8_t **ss, size_t *ss_len);

#endif /* __KEM_H__ */
