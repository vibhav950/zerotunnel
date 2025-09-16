/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * kem_kyber_defs.h
 */

#ifndef __KEM_KYBER_OQS_H__
#define __KEM_KYBER_OQS_H__

// clang-format off

/**
 * ML-KEM/Kyber approved parameter sets (FIPS 203).
 *
 * These defines MUST NOT be changed.
 */

#define KEM_KYBER_512_PUBKEY_SIZE       800
#define KEM_KYBER_512_PRIVKEY_SIZE      1632
#define KEM_KYBER_512_CIPHERTEXT_SIZE   768
#define KEM_KYBER_512_SHAREDKEY_SIZE    32

#define KEM_KYBER_768_PUBKEY_SIZE       1184
#define KEM_KYBER_768_PRIVKEY_SIZE      2400
#define KEM_KYBER_768_CIPHERTEXT_SIZE   1088
#define KEM_KYBER_768_SHAREDKEY_SIZE    32

#define KEM_KYBER_1024_PUBKEY_SIZE      1568
#define KEM_KYBER_1024_PRIVKEY_SIZE     3168
#define KEM_KYBER_1024_CIPHERTEXT_SIZE  1568
#define KEM_KYBER_1024_SHAREDKEY_SIZE   32

// 32-byte random public rho
#define KEM_KYBER_PUBLIC_SEED_SIZE      32

#endif /* __KEM_KYBER_OQS_H__ */
