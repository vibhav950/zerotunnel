/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * kem.c
 */

#include "kem.h"

const char *kem_alg_to_string(kem_alg_t alg) {
  switch (alg) {
  case KEM_Kyber_512:
    return "Kyber-512";
  case KEM_Kyber_768:
    return "Kyber-768";
  case KEM_Kyber_1024:
    return "Kyber-1024";
  default:
    return "unknown type";
  }
}

int kem_intf_alg_is_supported(const kem_intf_t *intf, kem_alg_t alg) {
  return (intf) && (intf->supported_algs & alg);
}

int kem_flag_get(kem_t *kem, kem_flag_t flag) {
  return (kem) && (kem->flags & flag);
}

err_t kem_intf_alloc(const kem_intf_t *intf, kem_t **kem, kem_alg_t alg) {
  if (!intf || !intf->alloc || !kem)
    return ERR_NULL_PTR;

  return (intf)->alloc(kem, alg);
}

void kem_dealloc(kem_t *kem) {
  if (!kem || !kem->intf)
    return;

  ((kem)->intf)->dealloc(kem);
}

void kem_mem_free(const kem_intf_t *intf, void *ptr, size_t len) {
  if (!intf)
    return;

  (intf)->mem_free(ptr, len);
}

err_t kem_keygen(kem_t *kem, uint8_t **pubkey, size_t *pubkey_len) {
  if (!kem || !kem->intf)
    return ERR_NULL_PTR;

  return ((kem)->intf)->keygen(kem, pubkey, pubkey_len);
}

err_t kem_encapsulate(kem_t *kem, const uint8_t *peer_pubkey,
                      size_t peer_pubkey_len, uint8_t **ct, size_t *ct_len,
                      uint8_t **ss, size_t *ss_len) {
  if (!kem || !kem->intf)
    return ERR_NULL_PTR;

  return ((kem)->intf)
      ->encapsulate(kem, peer_pubkey, peer_pubkey_len, ct, ct_len, ss, ss_len);
}

err_t kem_decapsulate(kem_t *kem, const uint8_t *ct, size_t ct_len,
                      uint8_t **ss, size_t *ss_len) {
  if (!kem || !kem->intf)
    return ERR_NULL_PTR;

  return ((kem)->intf)->decapsulate(kem, ct, ct_len, ss, ss_len);
}
