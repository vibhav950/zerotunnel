/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * sha256.h - SHA-256 hash algorithm
 */

#ifndef __SHA256_H__
#define __SHA256_H__

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN 64

typedef struct _sha256_ctx_st {
  uint8_t rem_data[SHA256_BLOCK_LEN];
  uint32_t state[8];
  size_t len;
  size_t rem_len;
} sha256_ctx_t;

int sha256_init(sha256_ctx_t *ctx);

int sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len);

int sha256_finalize(sha256_ctx_t *ctx, uint8_t hash[32]);

int SHA256(const uint8_t data[], size_t len, uint8_t hash[32]);

#if defined(DEBUG)
/** Built-in KAT self tests */
int sha256_self_test(void);
#endif

#endif /* __SHA256_H__ */
