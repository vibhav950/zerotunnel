/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * hmac_defs.h
 */

#ifndef __HMAC_OSSL_H__
#define __HMAC_OSSL_H__

// clang-format off

/* ========= HMAC key lengths ========= */

#define HMAC_SHA256_KEY_LEN           32U
#define HMAC_SHA384_KEY_LEN           48U
#define HMAC_SHA512_KEY_LEN           64U
#define HMAC_SHA3_256_KEY_LEN         32U
#define HMAC_SHA3_384_KEY_LEN         48U
#define HMAC_SHA3_512_KEY_LEN         64U
#define HMAC_MAX_KEY_LEN              64U

/* ========= HMAC digest/output lengths ========= */

#define HMAC_SHA256_MAX_OUT_LEN       HMAC_SHA256_KEY_LEN
#define HMAC_SHA384_MAX_OUT_LEN       HMAC_SHA384_KEY_LEN
#define HMAC_SHA512_MAX_OUT_LEN       HMAC_SHA512_KEY_LEN
#define HMAC_SHA3_256_MAX_OUT_LEN     HMAC_SHA3_256_KEY_LEN
#define HMAC_SHA3_384_MAX_OUT_LEN     HMAC_SHA3_384_KEY_LEN
#define HMAC_SHA3_512_MAX_OUT_LEN     HMAC_SHA3_512_KEY_LEN
#define HMAC_MAX_OUT_LEN              HMAC_MAX_KEY_LEN

#endif /* __HMAC_OSSL_H__ */
