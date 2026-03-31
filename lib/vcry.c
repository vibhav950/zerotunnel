/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * vcry.c - Virtual cryptography interface
 */

#include "vcry.h"
#include "common/log.h"
#include "crypto/cipher_defs.h"
#include "crypto/hmac_defs.h"
#include "crypto/kdf.h"
#include "crypto/kem.h"
#include "crypto/kem_kyber_defs.h"
#include "crypto/kex.h"
#include "crypto/types.h"
#include "random/systemrand.h"

#include <string.h>

// clang-format off

#define VCRY_K_MAC_INI_OFFSET           (0U)
#define VCRY_K_MAC_RES_OFFSET           (VCRY_K_MAC_INI_OFFSET   + VCRY_K_MAC_LEN)
#define VCRY_K_ENCR_INI_OFFSET          (VCRY_K_MAC_RES_OFFSET   + VCRY_K_MAC_LEN)
#define VCRY_K_ENCR_RES_OFFSET          (VCRY_K_ENCR_INI_OFFSET  + VCRY_K_ENCR_LEN)
#define VCRY_IV_ENCR_INI_OFFSET         (VCRY_K_ENCR_RES_OFFSET  + VCRY_K_ENCR_LEN)
#define VCRY_IV_ENCR_RES_OFFSET         (VCRY_IV_ENCR_INI_OFFSET + VCRY_IV_ENCR_LEN)

#define VCRY_FLAG_SET(x)                ((void)(ctx->flags |= (x)))
#define VCRY_FLAG_GET(x)                ((int)(ctx->flags & (x)))

#define VCRY_ERR_SET(ctx, e)            ((ctx)->err_set = (e))

#define VCRY_HSHAKE_ROLE(ctx)           (ctx->role)

#define VCRY_STATE(ctx)                 ((ctx)->state)
#define VCRY_STATE_CHANGE(ctx, next)    ((void)((ctx)->state = (next)))

#define VCRY_EXPECT(retval, expectval, jmp)                                              \
  do {                                                                                   \
    if ((ret = (retval)) != (expectval)) {                                               \
      VCRY_ERR_SET(ctx, retval);                                                         \
      goto jmp;                                                                          \
    }                                                                                    \
  } while (0)

#define VCRY_ALG_LOOP(arr, stmts)                                                        \
  const struct vcry_alg_entry_st *p;                                                     \
  for (p = (arr); p->name; p++) {                                                        \
    stmts                                                                                \
  }

struct vcry_alg_entry_st {
  const char *name;
  int id;
};

static const struct vcry_alg_entry_st vcry_cipher_entry_arr[] = {
    { "AES-CTR-128", VCRY_CIPHER_AES_CTR_128 },
    { "AES-CTR-192", VCRY_CIPHER_AES_CTR_192 },
    { "AES-CTR-256", VCRY_CIPHER_AES_CTR_256 },
    { "CHACHA20", VCRY_CIPHER_CHACHA20 },
    { NULL, -1 }
};

static const struct vcry_alg_entry_st vcry_aead_entry_arr[] = {
    { "AES-GCM-128", VCRY_AEAD_AES_GCM_128 },
    { "AES-GCM-192", VCRY_AEAD_AES_GCM_192 },
    { "AES-GCM-256", VCRY_AEAD_AES_GCM_256 },
    { "CHACHA20-POLY1305", VCRY_AEAD_CHACHA20_POLY1305 },
    { NULL, -1 }
};

static const struct vcry_alg_entry_st vcry_hmac_entry_arr[] = {
    { "HMAC-SHA256", VCRY_HMAC_SHA256 },
    { "HMAC-SHA384", VCRY_HMAC_SHA384 },
    { "HMAC-SHA512", VCRY_HMAC_SHA512 },
    { "HMAC-SHA3-256", VCRY_HMAC_SHA3_256 },
    { "HMAC-SHA3-384", VCRY_HMAC_SHA3_384 },
    { "HMAC-SHA3-512", VCRY_HMAC_SHA3_512 },
    { NULL, -1 }
};

static const struct vcry_alg_entry_st vcry_ecdh_entry_arr[] = {
    { "ECDH-SECP256K1", VCRY_KEX_ECDH_SECP256K1 },
    { "ECDH-SECP384R1", VCRY_KEX_ECDH_SECP384R1 },
    { "ECDH-SECP521R1", VCRY_KEX_ECDH_SECP521R1 },
    { "ECDH-PRIME239V3", VCRY_KEX_ECDH_PRIME239V3 },
    { "ECDH-PRIME256V1", VCRY_KEX_ECDH_PRIME256V1 },
    { "ECDH-X25519", VCRY_KEX_ECDH_X25519 },
    { "ECDH-X448", VCRY_KEX_ECDH_X448 },
    { NULL, -1 }
};

static const struct vcry_alg_entry_st vcry_kem_entry_arr[] = {
    { "KEM-KYBER512", VCRY_KEM_KYBER512 },
    { "KEM-KYBER768", VCRY_KEM_KYBER768 },
    { "KEM-KYBER1024", VCRY_KEM_KYBER1024 },
    { NULL, -1 }
};

static struct vcry_alg_entry_st vcry_kdf_entry_arr[] = {
    { "KDF-PBKDF2", VCRY_KDF_PBKDF2 },
    { "KDF-SCRYPT", VCRY_KDF_SCRYPT },
    { "KDF-ARGON2", VCRY_KDF_ARGON2 },
    { NULL, -1 }
};

/**
 * Roles
 */
enum {
  vcry_hshake_role_initiator = (1U << 0),
  vcry_hshake_role_responder = (1U << 1),
};

/**
 * Flags to enforce strict call sequence
 */
enum {
  vcry_fl_cipher_set        = (1U << 0),
  vcry_fl_aead_set          = (1U << 1),
  vcry_fl_mac_set           = (1U << 2),
  vcry_fl_kex_set           = (1U << 3),
  vcry_fl_kem_set           = (1U << 4),
  vcry_fl_kdf_set           = (1U << 5),
  vcry_fl_all_set           = (vcry_fl_cipher_set
                            |  vcry_fl_aead_set
                            |  vcry_fl_mac_set
                            |  vcry_fl_kex_set
                            |  vcry_fl_kem_set
                            |  vcry_fl_kdf_set)
};

/**
 * Handshake states
 */
enum {
  vcry_hs_none              = (0U),
  vcry_hs_initiate          = (1U << 0),
  vcry_hs_response          = (1U << 1),
  vcry_hs_complete          = (1U << 2),
  vcry_hs_verify_initiate   = (1U << 3),
  vcry_hs_verify_complete   = (1U << 4),
  vcry_hs_done              = (1U << 5)
};

struct vcry_ctx_st {
  /**
   * handles for the crypto engine
   */

  cipher_t *cipher, *aead;
  hmac_t *mac;
  kex_t *kex;
  kem_t *kem;
  kdf_t *kdf;

  /** the peer's EC share */
  kex_peer_share_t peer_ec_share;

  uint8_t
    *authpass, /** master password */
    *pqk,      /** own PQ-KEM public key */
    *peer_pqk, /** peer's PQ-KEM public key */
    *ss;       /** PQ-KEM shared secret  */

  uint8_t
    salt[VCRY_HSHAKE_SALT_LEN], /** initiator salt */
    skey[VCRY_SESSION_KEY_LEN]; /** session key */

  size_t
    authpass_len, /** len(authpass) */
    pqk_len,      /** len(pqk) for initiator and len(pqk_peer) for responder */
    ss_len;       /** len(ss) */

  int
    role,  /** role in handshake */
    state, /** most recent state marked 'complete' */
    flags; /** flags for validating the global config */

  uint64_t
    sn_self, /** self sequence number */
    sn_peer; /** peer sequence number */

  err_t
    err_set; /** most recent failure status code */
};

// clang-format on

static inline ATTRIBUTE_ALWAYS_INLINE
ATTRIBUTE_NONNULL(1) uint8_t *vcry_self_mac_key(struct vcry_ctx_st *ctx) {
  if (ctx->role == vcry_hshake_role_initiator)
    return ctx->skey + VCRY_K_MAC_INI_OFFSET;
  else
    return ctx->skey + VCRY_K_MAC_RES_OFFSET;
}

static inline ATTRIBUTE_ALWAYS_INLINE
ATTRIBUTE_NONNULL(1) uint8_t *vcry_peer_mac_key(struct vcry_ctx_st *ctx) {
  if (ctx->role == vcry_hshake_role_initiator)
    return ctx->skey + VCRY_K_MAC_RES_OFFSET;
  else
    return ctx->skey + VCRY_K_MAC_INI_OFFSET;
}

static inline ATTRIBUTE_ALWAYS_INLINE
ATTRIBUTE_NONNULL(1) uint8_t *vcry_encr_key(struct vcry_ctx_st *ctx) {
  if (ctx->role == vcry_hshake_role_initiator)
    return ctx->skey + VCRY_K_ENCR_INI_OFFSET;
  else
    return ctx->skey + VCRY_K_ENCR_RES_OFFSET;
}

static inline ATTRIBUTE_ALWAYS_INLINE
ATTRIBUTE_NONNULL(1) uint8_t *vcry_decr_key(struct vcry_ctx_st *ctx) {
  if (ctx->role == vcry_hshake_role_initiator)
    return ctx->skey + VCRY_K_ENCR_RES_OFFSET;
  else
    return ctx->skey + VCRY_K_ENCR_INI_OFFSET;
}

static inline ATTRIBUTE_ALWAYS_INLINE
ATTRIBUTE_NONNULL(1) uint8_t *vcry_encr_iv(struct vcry_ctx_st *ctx) {
  if (ctx->role == vcry_hshake_role_initiator)
    return ctx->skey + VCRY_IV_ENCR_INI_OFFSET;
  else
    return ctx->skey + VCRY_IV_ENCR_RES_OFFSET;
}

static inline ATTRIBUTE_ALWAYS_INLINE
ATTRIBUTE_NONNULL(1) uint8_t *vcry_decr_iv(struct vcry_ctx_st *ctx) {
  if (ctx->role == vcry_hshake_role_initiator)
    return ctx->skey + VCRY_IV_ENCR_RES_OFFSET;
  else
    return ctx->skey + VCRY_IV_ENCR_INI_OFFSET;
}

static inline ATTRIBUTE_NONNULL(1) const uint8_t *vcry_encr_nonce(
    struct vcry_ctx_st *ctx) {
  static uint8_t nonce[VCRY_IV_ENCR_LEN];
  uint64_t sn;

  ASSERT(VCRY_IV_ENCR_LEN >= sizeof(uint64_t));

  memcpy(nonce, vcry_encr_iv(ctx), VCRY_IV_ENCR_LEN);

#ifdef __LITTLE_ENDIAN__
  sn = BSWAP64(ctx->sn_self);
#else
  sn = ctx->sn_self;
#endif

  PTR64(nonce)[0] ^= sn;

  return nonce;
}

static inline ATTRIBUTE_NONNULL(1) const uint8_t *vcry_decr_nonce(
    struct vcry_ctx_st *ctx) {
  static uint8_t nonce[VCRY_IV_ENCR_LEN];
  uint64_t sn;

  ASSERT(VCRY_IV_ENCR_LEN >= sizeof(uint64_t));

  memcpy(nonce, vcry_decr_iv(ctx), VCRY_IV_ENCR_LEN);

#ifdef __LITTLE_ENDIAN__
  sn = BSWAP64(ctx->sn_peer);
#else
  sn = ctx->sn_peer;
#endif

  PTR64(nonce)[0] ^= sn;

  return nonce;
}

static err_t vcry_set_cipher_from_id(struct vcry_ctx_st *ctx, int id) {
  err_t ret;
  size_t key_len;
  cipher_alg_t alg;

  switch (id) {
  case VCRY_CIPHER_AES_CTR_128:
    alg = CIPHER_AES_CTR_128;
    key_len = AES_CTR_128_KEY_LEN;
    break;
  case VCRY_CIPHER_AES_CTR_192:
    alg = CIPHER_AES_CTR_192;
    key_len = AES_CTR_192_KEY_LEN;
    break;
  case VCRY_CIPHER_AES_CTR_256:
    alg = CIPHER_AES_CTR_256;
    key_len = AES_CTR_256_KEY_LEN;
    break;
  case VCRY_CIPHER_CHACHA20:
    alg = CIPHER_CHACHA20;
    key_len = CHACHA20_KEY_LEN;
    break;
  default:
    log_error(NULL, "Unknown cipher Id: %d", id);
    return VCRY_ERR_SET(ctx, ERR_BAD_ARGS);
  }

  if (!cipher_intf_alg_is_supported(&cipher_intf, alg)) {
    log_error(NULL, "Cipher algorithm not supported");
    return VCRY_ERR_SET(ctx, ERR_NOT_SUPPORTED);
  }

  if ((ret = cipher_intf_alloc(&cipher_intf, &ctx->cipher, key_len, 0, alg)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  VCRY_FLAG_SET(vcry_fl_cipher_set);
  return ERR_SUCCESS;
}

static err_t vcry_set_cipher_from_name(struct vcry_ctx_st *ctx, const char *name) {
  int id = -0xfff;

  VCRY_ALG_LOOP(vcry_cipher_entry_arr, {
    if (!strcasecmp(name, p->name)) {
      id = p->id;
      break;
    }
  });
  return vcry_set_cipher_from_id(ctx, id);
}

static err_t vcry_set_aead_from_id(struct vcry_ctx_st *ctx, int id) {
  err_t ret;
  size_t key_len;
  cipher_alg_t alg;

  switch (id) {
  case VCRY_AEAD_AES_GCM_128:
    alg = AEAD_AES_GCM_128;
    key_len = AES_GCM_128_KEY_LEN;
    break;
  case VCRY_AEAD_AES_GCM_192:
    alg = AEAD_AES_GCM_192;
    key_len = AES_GCM_192_KEY_LEN;
    break;
  case VCRY_AEAD_AES_GCM_256:
    key_len = AES_GCM_256_KEY_LEN;
    alg = AEAD_AES_GCM_256;
    break;
  case VCRY_AEAD_CHACHA20_POLY1305:
    key_len = CHACHA20_POLY1305_KEY_LEN;
    alg = AEAD_CHACHA20_POLY1305;
    break;
  default:
    log_error(NULL, "Unknown AEAD Id: %d", id);
    return VCRY_ERR_SET(ctx, ERR_BAD_ARGS);
  }

  if (!cipher_intf_alg_is_supported(&aead_intf, alg)) {
    log_error(NULL, "AEAD algorithm not supported");
    return VCRY_ERR_SET(ctx, ERR_NOT_SUPPORTED);
  }

  if ((ret = cipher_intf_alloc(&aead_intf, &ctx->aead, key_len, AES_GCM_AUTH_TAG_LEN_LONG,
                               alg)) != ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  VCRY_FLAG_SET(vcry_fl_aead_set);
  return ERR_SUCCESS;
}

static err_t vcry_set_aead_from_name(struct vcry_ctx_st *ctx, const char *name) {
  int id = -0xfff;

  VCRY_ALG_LOOP(vcry_aead_entry_arr, {
    if (!strcasecmp(name, p->name)) {
      id = p->id;
      break;
    }
  });
  return vcry_set_aead_from_id(ctx, id);
}

static err_t vcry_set_hmac_from_id(struct vcry_ctx_st *ctx, int id) {
  err_t ret;
  size_t key_len;
  hmac_alg_t alg;

  switch (id) {
  case VCRY_HMAC_SHA256:
    key_len = HMAC_SHA256_KEY_LEN;
    alg = HMAC_SHA256;
    break;
  case VCRY_HMAC_SHA384:
    key_len = HMAC_SHA384_KEY_LEN;
    alg = HMAC_SHA384;
    break;
  case VCRY_HMAC_SHA512:
    key_len = HMAC_SHA512_KEY_LEN;
    alg = HMAC_SHA512;
    break;
  case VCRY_HMAC_SHA3_256:
    key_len = HMAC_SHA3_256_KEY_LEN;
    alg = HMAC_SHA3_256;
    break;
  case VCRY_HMAC_SHA3_384:
    key_len = HMAC_SHA3_384_KEY_LEN;
    alg = HMAC_SHA3_384;
    break;
  case VCRY_HMAC_SHA3_512:
    key_len = HMAC_SHA3_512_KEY_LEN;
    alg = HMAC_SHA3_512;
    break;
  default:
    log_error(NULL, "Unknown HMAC Id: %d", id);
    return VCRY_ERR_SET(ctx, ERR_BAD_ARGS);
  }

  if (!hmac_intf_alg_is_supported(&hmac_intf, alg)) {
    log_error(NULL, "HMAC algorithm not supported");
    return VCRY_ERR_SET(ctx, ERR_NOT_SUPPORTED);
  }

  if ((ret = hmac_intf_alloc(&hmac_intf, &ctx->mac, key_len, key_len, alg)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  VCRY_FLAG_SET(vcry_fl_mac_set);
  return ERR_SUCCESS;
}

static err_t vcry_set_hmac_from_name(struct vcry_ctx_st *ctx, const char *name) {
  int id = -0xfff;

  VCRY_ALG_LOOP(vcry_hmac_entry_arr, {
    if (!strcasecmp(name, p->name)) {
      id = p->id;
      break;
    }
  });
  return vcry_set_hmac_from_id(ctx, id);
}

static err_t vcry_set_ecdh_from_id(struct vcry_ctx_st *ctx, int id) {
  err_t ret;
  kex_curve_t curve;

  switch (id) {
  case VCRY_KEX_ECDH_SECP256K1:
    curve = KEX_CURVE_secp256k1;
    break;
  case VCRY_KEX_ECDH_SECP384R1:
    curve = KEX_CURVE_secp384r1;
    break;
  case VCRY_KEX_ECDH_SECP521R1:
    curve = KEX_CURVE_secp521r1;
    break;
  case VCRY_KEX_ECDH_PRIME239V3:
    curve = KEX_CURVE_prime239v3;
    break;
  case VCRY_KEX_ECDH_PRIME256V1:
    curve = KEX_CURVE_prime256v1;
  case VCRY_KEX_ECDH_X25519:
    curve = KEX_CURVE_X25519;
    break;
  case VCRY_KEX_ECDH_X448:
    curve = KEX_CURVE_X448;
    break;
  default:
    log_error(NULL, "Unknown KEX curve Id: %d", id);
    return VCRY_ERR_SET(ctx, ERR_BAD_ARGS);
  }

  if (!kex_intf_curve_is_supported(&kex_ecc_intf, curve)) {
    log_error(NULL, "Curve not supported");
    return VCRY_ERR_SET(ctx, ERR_NOT_SUPPORTED);
  }

  if ((ret = kex_intf_alloc(&kex_ecc_intf, &ctx->kex, curve)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  VCRY_FLAG_SET(vcry_fl_kex_set);
  return ERR_SUCCESS;
}

static err_t vcry_set_ecdh_from_name(struct vcry_ctx_st *ctx, const char *name) {
  int id = -0xfff;

  VCRY_ALG_LOOP(vcry_ecdh_entry_arr, {
    if (!strcasecmp(name, p->name)) {
      id = p->id;
      break;
    }
  });
  return vcry_set_ecdh_from_id(ctx, id);
}

static err_t vcry_set_kem_from_id(struct vcry_ctx_st *ctx, int id) {
  err_t ret;
  kem_alg_t alg;

  switch (id) {
  case VCRY_KEM_KYBER512:
    alg = KEM_Kyber_512;
    break;
  case VCRY_KEM_KYBER768:
    alg = KEM_Kyber_768;
    break;
  case VCRY_KEM_KYBER1024:
    alg = KEM_Kyber_1024;
    break;
  default:
    log_error(NULL, "Unknown KEM Id: %d", id);
    return VCRY_ERR_SET(ctx, ERR_BAD_ARGS);
  }

  if (!kem_intf_alg_is_supported(&kem_kyber_intf, alg)) {
    log_error(NULL, "KEM algorithm not supported");
    return VCRY_ERR_SET(ctx, ERR_NOT_SUPPORTED);
  }

  if ((ret = kem_intf_alloc(&kem_kyber_intf, &ctx->kem, alg)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  VCRY_FLAG_SET(vcry_fl_kem_set);
  return ERR_SUCCESS;
}

static err_t vcry_set_kem_from_name(struct vcry_ctx_st *ctx, const char *name) {
  int id = -0xfff;

  VCRY_ALG_LOOP(vcry_kem_entry_arr, {
    if (!strcasecmp(name, p->name)) {
      id = p->id;
      break;
    }
  });
  return vcry_set_kem_from_id(ctx, id);
}

static err_t vcry_set_kdf_from_id(struct vcry_ctx_st *ctx, int id) {
  err_t ret;
  kdf_alg_t alg;

  switch (id) {
  case VCRY_KDF_PBKDF2:
    alg = KDF_ALG_PBKDF2;
    break;
  case VCRY_KDF_SCRYPT:
    alg = KDF_ALG_scrypt;
    break;
  case VCRY_KDF_ARGON2:
    alg = KDF_ALG_argon2;
    break;
  default:
    log_error(NULL, "Unknown KDF Id: %d", id);
    return VCRY_ERR_SET(ctx, ERR_BAD_ARGS);
  }

  if (!kdf_intf_alg_is_supported(&kdf_intf, alg)) {
    log_error(NULL, "KDF algorithm not supported");
    return VCRY_ERR_SET(ctx, ERR_NOT_SUPPORTED);
  }

  if ((ret = kdf_intf_alloc(&kdf_intf, &ctx->kdf, alg)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  VCRY_FLAG_SET(vcry_fl_kdf_set);
  return ERR_SUCCESS;
}

static err_t vcry_set_kdf_from_name(struct vcry_ctx_st *ctx, const char *name) {
  int id = -0xfff;

  VCRY_ALG_LOOP(vcry_kdf_entry_arr, {
    if (!strcasecmp(name, p->name)) {
      id = p->id;
      break;
    }
  });
  return vcry_set_kdf_from_id(ctx, id);
}

/**
 * Create a new VCRY handle.
 */
vcry_ctx_t *vcry_new(void) {
  vcry_ctx_t *ctx;

  ctx = zt_calloc(1, sizeof(struct vcry_ctx_st));
  return ctx;
}

/**
 * Create a duplicate of the given VCRY handle. The new handle shares
 * no resources with the original and must be independently released.
 */
vcry_ctx_t *vcry_duplicate(vcry_ctx_t *ctx) {
  vcry_ctx_t *new;

  new = zt_calloc(1, sizeof(struct vcry_ctx_st));
  if (!new)
    return NULL;

  memcpy(new, ctx, sizeof(struct vcry_ctx_st));

  return new;
}

/**
 * Securely wipe and release all resources associated with this VCRY handle.
 */
void vcry_release(vcry_ctx_t *ctx) {
  uint8_t *pqpub;
  size_t pqpub_len;

  if (ctx) {
    kex_free_peer_data(ctx->kex, &ctx->peer_ec_share);
    kem_mem_free(&kem_kyber_intf, ctx->ss, ctx->ss_len);

    if (VCRY_FLAG_GET(vcry_fl_cipher_set))
      cipher_dealloc(ctx->cipher);

    if (VCRY_FLAG_GET(vcry_fl_aead_set))
      cipher_dealloc(ctx->aead);

    if (VCRY_FLAG_GET(vcry_fl_mac_set))
      hmac_dealloc(ctx->mac);

    if (VCRY_FLAG_GET(vcry_fl_kex_set))
      kex_dealloc(ctx->kex);

    if (VCRY_FLAG_GET(vcry_fl_kem_set))
      kem_dealloc(ctx->kem);

    if (VCRY_FLAG_GET(vcry_fl_kdf_set))
      kdf_dealloc(ctx->kdf);

    if (VCRY_HSHAKE_ROLE(ctx) == vcry_hshake_role_initiator) {
      kem_mem_free(&kem_kyber_intf, ctx->pqk, ctx->pqk_len);
    } else if (VCRY_HSHAKE_ROLE(ctx) == vcry_hshake_role_responder) {
      memzero(ctx->peer_pqk, ctx->pqk_len);
      zt_free(ctx->peer_pqk);
    }

    memzero(ctx->authpass, ctx->authpass_len);
    zt_free(ctx->authpass);

    memzero(ctx, sizeof(struct vcry_ctx_st));
    zt_free(ctx);
  }
}

void vcry_set_role_initiator(vcry_ctx_t *ctx) {
  if (ctx)
    ctx->role = vcry_hshake_role_initiator;
}

void vcry_set_role_responder(vcry_ctx_t *ctx) {
  if (ctx)
    ctx->role = vcry_hshake_role_responder;
}

err_t vcry_get_last_err(vcry_ctx_t *ctx) {
  if (!ctx)
    return ERR_NULL_PTR;
  return ctx->err_set;
}

void vcry_clear_last_err(vcry_ctx_t *ctx) {
  if (ctx)
    VCRY_ERR_SET(ctx, ERR_SUCCESS);
}

err_t vcry_set_authpass(vcry_ctx_t *ctx, const uint8_t *authpass, size_t authpass_len) {
  uint8_t *old_authpass;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!authpass)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  old_authpass = ctx->authpass;
  if (old_authpass) {
    memzero(old_authpass, ctx->authpass_len);
    zt_free(old_authpass);
  }
  ctx->authpass = zt_memdup(authpass, authpass_len);
  if (!ctx->authpass)
    return VCRY_ERR_SET(ctx, ERR_MEM_FAIL);
  ctx->authpass_len = authpass_len;
  return ERR_SUCCESS;
}

err_t vcry_set_crypto_params(vcry_ctx_t *ctx, int cipher_id, int aead_id, int hmac_id,
                             int kex_id, int kem_id, int kdf_id) {
  err_t ret;

  if (!ctx)
    return ERR_NULL_PTR;

  if ((ret = vcry_set_cipher_from_id(ctx, cipher_id)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_aead_from_id(ctx, aead_id)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_hmac_from_id(ctx, hmac_id)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_ecdh_from_id(ctx, kex_id)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_kem_from_id(ctx, kem_id)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_kdf_from_id(ctx, kdf_id)) != ERR_SUCCESS)
    return ret;
  return ERR_SUCCESS;
}

err_t vcry_set_crypto_params_from_names(vcry_ctx_t *ctx, const char *cipher_name,
                                        const char *aead_name, const char *hmac_name,
                                        const char *kex_name, const char *kem_name,
                                        const char *kdf_name) {
  err_t ret;

  if (!ctx)
    return ERR_NULL_PTR;

  if ((ret = vcry_set_cipher_from_name(ctx, cipher_name)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_aead_from_name(ctx, aead_name)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_hmac_from_name(ctx, hmac_name)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_ecdh_from_name(ctx, kex_name)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_kem_from_name(ctx, kem_name)) != ERR_SUCCESS)
    return ret;
  if ((ret = vcry_set_kdf_from_name(ctx, kdf_name)) != ERR_SUCCESS)
    return ret;
  return ERR_SUCCESS;
}

size_t vcry_get_aead_tag_len(vcry_ctx_t *ctx) {
  if (unlikely(VCRY_FLAG_GET(vcry_fl_aead_set) != vcry_fl_aead_set))
    return 0;

  return cipher_tag_len(ctx->aead);
}

size_t vcry_get_hmac_digest_len(vcry_ctx_t *ctx) {
  if (unlikely(VCRY_FLAG_GET(vcry_fl_mac_set) != vcry_fl_mac_set))
    return 0;

  return hmac_digest_len(ctx->mac);
}

/**
 * Initialize the handshake process by generating the following components:
 * 1. The encrypted PQ-KEM public seed (rho) used to generate matrix (A):
 *    PQK_enc = t_vec || Cipher-Enc(rho, K_pass, salt=salt2)
 * 2. The DHE public key: DHEK_A
 * 3. Initiator random value: salt = salt1 || salt2 || salt3
 *
 * Compute K_pass = KDF(pass || salt1 || "Compute master key (k_pass)")
 * where KDF is a memory-hard key derivation function (e.g., scrypt/argon2)
 *
 * The caller is responsible for freeing the `peerdata` buffer.
 *
 * NOTE: This function is called by the handshake initiator.
 *
 * Returns an `err_t` status code.
 */
err_t vcry_handshake_initiate(vcry_ctx_t *ctx, uint8_t **peerdata, size_t *peerdata_len) {
  err_t ret = ERR_SUCCESS;
  kex_peer_share_t keyshare_mine;
  uint8_t *p = NULL;
  uint64_t *p64 = NULL;
  uint8_t *pqk = NULL;
  uint8_t *pqkenc = NULL;
  uint8_t *k_pass = NULL;
  size_t plen;
  size_t pqk_len, pqkenc_len, rho_offs, tmp_len;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!peerdata || !peerdata_len)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_none)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_initiator)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  zt_systemrand_bytes(ctx->salt, VCRY_HSHAKE_SALT_LEN);

  if ((ret = kdf_init(ctx->kdf, ctx->authpass, ctx->authpass_len, ctx->salt,
                      VCRY_HSHAKE_SALT0_LEN)) != ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if (!(k_pass = zt_malloc(VCRY_MASTER_KEY_LEN)))
    return VCRY_ERR_SET(ctx, ERR_MEM_FAIL);

  /** Derive the master key from the master password (auth key) */
  VCRY_EXPECT(kdf_derive(ctx->kdf, (const uint8_t *)VCRY_HSHAKE_CONST0,
                         strlen(VCRY_HSHAKE_CONST0), k_pass, VCRY_MASTER_KEY_LEN),
              ERR_SUCCESS, clean2);

  /** Generate the PQ-KEM keypair */
  VCRY_EXPECT(kem_keygen(ctx->kem, &pqk, &pqk_len), ERR_SUCCESS, clean2);

  /** Generate the DHE private key */
  VCRY_EXPECT(kex_key_gen(ctx->kex), ERR_SUCCESS, clean2);

  /** Get the DHE public key share */
  VCRY_EXPECT(kex_get_peer_data(ctx->kex, &keyshare_mine), ERR_SUCCESS, clean2);

  /**
   * Encrypt the PQ-KEM public seed value using the master key
   */
  VCRY_EXPECT(
      cipher_init(ctx->cipher, k_pass, VCRY_MASTER_KEY_LEN, CIPHER_OPERATION_ENCRYPT),
      ERR_SUCCESS, clean1);

  VCRY_EXPECT(cipher_set_iv(ctx->cipher, ctx->salt + VCRY_HSHAKE_SALT0_LEN,
                            VCRY_HSHAKE_SALT1_LEN),
              ERR_SUCCESS, clean1);

  tmp_len = 0;
  VCRY_EXPECT(
      cipher_encrypt(ctx->cipher, NULL, KEM_KYBER_PUBLIC_SEED_SIZE, NULL, &tmp_len),
      ERR_BUFFER_TOO_SMALL, clean1);

  rho_offs = pqk_len - KEM_KYBER_PUBLIC_SEED_SIZE; // size(t_vec)
  pqkenc_len = rho_offs + tmp_len;                 // size(t_vec || Enc(rho))

  if (!(pqkenc = zt_malloc(pqkenc_len))) {
    ret = VCRY_ERR_SET(ctx, ERR_MEM_FAIL);
    goto clean1;
  }

  VCRY_EXPECT(cipher_encrypt(ctx->cipher, pqk + rho_offs, KEM_KYBER_PUBLIC_SEED_SIZE,
                             pqkenc + rho_offs, &tmp_len),
              ERR_SUCCESS, clean0);

  memcpy(pqkenc, pqk, rho_offs);

  plen = keyshare_mine.ec_pub_len + keyshare_mine.ec_curvename_len + pqkenc_len +
         VCRY_HSHAKE_SALT_LEN;
  plen += 3 * sizeof(uint64_t);

  if (!(*peerdata = zt_malloc(plen))) {
    ret = VCRY_ERR_SET(ctx, ERR_MEM_FAIL);
    goto clean0;
  }
  *peerdata_len = plen;

  /** We need to store the lengths to be able to deserialize the data */
  p64 = PTR64(*peerdata);
  p64[0] = hton64((uint64_t)keyshare_mine.ec_pub_len);
  p64[1] = hton64((uint64_t)keyshare_mine.ec_curvename_len);
  p64[2] = hton64((uint64_t)pqkenc_len);

  /** Serialize the data by copying individual members */
  p = *peerdata + (3 * sizeof(uint64_t));
  memcpy(p, keyshare_mine.ec_pub, keyshare_mine.ec_pub_len);
  p += keyshare_mine.ec_pub_len;
  memcpy(p, keyshare_mine.ec_curvename, keyshare_mine.ec_curvename_len);
  p += keyshare_mine.ec_curvename_len;
  memcpy(p, pqkenc, pqkenc_len);
  p += pqkenc_len;
  memcpy(p, ctx->salt, VCRY_HSHAKE_SALT_LEN);

  /** This memory is freed in vcry_release() */
  ctx->pqk = pqk;
  ctx->pqk_len = pqk_len;

  VCRY_STATE_CHANGE(ctx, vcry_hs_initiate);

clean0:
  memzero(pqkenc, pqkenc_len);
  zt_free(pqkenc);
clean1:
  kex_free_peer_data(ctx->kex, &keyshare_mine);
clean2:
  memzero(k_pass, VCRY_MASTER_KEY_LEN);
  zt_free(k_pass);
  return ret;
}

/**
 * Responds to a handshake initiation message by performing the following:
 *
 * 1. Extract and decrypt the public seed from the encrypted PQ-KEM key:
 *    PQK = PQK_enc[:size(PQK)-32] ||
 *          Cipher-Dec(PQKEM_enc[size(PQK)-32:], K_pass, salt=salt2)
 * 2. Encapsulate the PQ-KEM shared secret (SS, CT) = encaps(PQK)
 * 3. Save peer's DHE public key and generate own DHE keypair and attach the
 *    public key to the response.
 *
 * The caller is responsible for freeing the `peerdata_mine` buffer.
 *
 * NOTE: This function is called by the handshake responder.
 *
 * Returns an `err_t` status code.
 */
err_t vcry_handshake_respond(vcry_ctx_t *ctx, const uint8_t *peerdata_theirs,
                             size_t peerdata_theirs_len, uint8_t **peerdata_mine,
                             size_t *peerdata_mine_len) {
  err_t ret = ERR_SUCCESS;
  kex_peer_share_t keyshare_mine;
  uint8_t *p = NULL;
  uint64_t *p64 = NULL;
  uint8_t *k_pass = NULL;
  uint8_t *peer_pqkenc = NULL;
  uint8_t *peer_pqk = NULL;
  uint8_t *ct = NULL;
  size_t p_len;
  size_t peer_pqkenc_len, peer_pqk_len, peer_ec_pub_len, peer_ec_curvename_len, rho_offs,
      tmp_len;
  size_t ct_len;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!peerdata_theirs || !peerdata_mine || !peerdata_mine_len)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_none)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_responder)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (peerdata_theirs_len < (3 * sizeof(uint64_t)))
    return VCRY_ERR_SET(ctx, ERR_INVALID_DATUM);

  /** Deserialize the peer's data */
  p64 = PTR64(peerdata_theirs);
  peer_ec_pub_len = ntoh64(p64[0]);
  peer_ec_curvename_len = ntoh64(p64[1]);
  peer_pqkenc_len = ntoh64(p64[2]);

  if (peerdata_theirs_len < (3 * sizeof(uint64_t)) + peer_ec_pub_len +
                                peer_ec_curvename_len + peer_pqkenc_len +
                                VCRY_HSHAKE_SALT_LEN) {
    return VCRY_ERR_SET(ctx, ERR_INVALID_DATUM);
  }

  p = PTR8(peerdata_theirs + (3 * sizeof(uint64_t)));
  /** Must be freed using kex_free_peer_data() while releasing the handle */
  if ((ret = kex_new_peer_data(ctx->kex, &ctx->peer_ec_share, p, peer_ec_pub_len,
                               p + peer_ec_pub_len, peer_ec_curvename_len)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }
  peer_pqkenc = (p += peer_ec_pub_len + peer_ec_curvename_len);

  /** Set the session salt */
  p += peer_pqkenc_len;
  memcpy(ctx->salt, p, VCRY_HSHAKE_SALT_LEN);

  /** Compute K_pass */
  if ((ret = kdf_init(ctx->kdf, ctx->authpass, ctx->authpass_len, ctx->salt,
                      VCRY_HSHAKE_SALT0_LEN)) != ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if (!(k_pass = zt_malloc(VCRY_MASTER_KEY_LEN)))
    return VCRY_ERR_SET(ctx, ERR_MEM_FAIL);

  VCRY_EXPECT(kdf_derive(ctx->kdf, (const uint8_t *)VCRY_HSHAKE_CONST0,
                         strlen(VCRY_HSHAKE_CONST0), k_pass, VCRY_MASTER_KEY_LEN),
              ERR_SUCCESS, clean1);

  /**
   * Decrypt the PQ-KEM public key using the master key
   */
  VCRY_EXPECT(
      cipher_init(ctx->cipher, k_pass, VCRY_MASTER_KEY_LEN, CIPHER_OPERATION_DECRYPT),
      ERR_SUCCESS, clean1);

  VCRY_EXPECT(cipher_set_iv(ctx->cipher, ctx->salt + VCRY_HSHAKE_SALT0_LEN,
                            VCRY_HSHAKE_SALT1_LEN),
              ERR_SUCCESS, clean1);

  peer_pqk_len = peer_pqkenc_len - cipher_tag_len(ctx->cipher); // size(t_vec || rho)
  rho_offs = peer_pqk_len - KEM_KYBER_PUBLIC_SEED_SIZE;         // size(t_vec)

  if (!(peer_pqk = zt_malloc(peer_pqk_len))) {
    ret = VCRY_ERR_SET(ctx, ERR_MEM_FAIL);
    goto clean1;
  }

  tmp_len = SIZE_MAX; // we just have to pass the minimum size check
  VCRY_EXPECT(cipher_decrypt(ctx->cipher, peer_pqkenc + rho_offs,
                             KEM_KYBER_PUBLIC_SEED_SIZE, peer_pqk + rho_offs, &tmp_len),
              ERR_SUCCESS, clean1);

  memcpy(peer_pqk, peer_pqkenc, rho_offs);

  /**
   * Encapsulate the shared secret with the peer's public key; this will
   * also place the generated shared secret into the local store
   *
   * Note: We MUST free the memory allocated within this function using
   * kem_mem_free() after we are done with it. Since the shared secret is
   * directly stored in the VCRY context, we will free with the mandatory
   * closing call to vcry_release()
   */
  VCRY_EXPECT(kem_encapsulate(ctx->kem, peer_pqk, peer_pqkenc_len, &ct, &ct_len, &ctx->ss,
                              &ctx->ss_len),
              ERR_SUCCESS, clean1);

  /** Generate the DHE keypair */
  VCRY_EXPECT(kex_key_gen(ctx->kex), ERR_SUCCESS, clean0);

  /** Get the DHE public key share */
  VCRY_EXPECT(kex_get_peer_data(ctx->kex, &keyshare_mine), ERR_SUCCESS, clean0);

  /**
   * Serialize the DHE public key share and attach it to the response
   */
  p_len = keyshare_mine.ec_pub_len + keyshare_mine.ec_curvename_len + ct_len;
  p_len += 3 * sizeof(uint64_t);

  if (!(*peerdata_mine = zt_malloc(p_len))) {
    ret = VCRY_ERR_SET(ctx, ERR_MEM_FAIL);
    goto clean0;
  }
  *peerdata_mine_len = p_len;

  p64 = PTR64(*peerdata_mine);
  p64[0] = hton64((uint64_t)keyshare_mine.ec_pub_len);
  p64[1] = hton64((uint64_t)keyshare_mine.ec_curvename_len);
  p64[2] = hton64((uint64_t)ct_len);

  p = *peerdata_mine + (3 * sizeof(uint64_t));
  memcpy(p, keyshare_mine.ec_pub, keyshare_mine.ec_pub_len);
  p += keyshare_mine.ec_pub_len;
  memcpy(p, keyshare_mine.ec_curvename, keyshare_mine.ec_curvename_len);
  p += keyshare_mine.ec_curvename_len;
  memcpy(p, ct, ct_len);

  /** This memory is freed in vcry_release() */
  ctx->peer_pqk = peer_pqk;
  ctx->pqk_len = peer_pqk_len;

  kex_free_peer_data(ctx->kex, &keyshare_mine);

  VCRY_STATE_CHANGE(ctx, vcry_hs_response);

clean0:
  kem_mem_free(&kem_kyber_intf, ct, ct_len);
clean1:
  memzero(k_pass, VCRY_MASTER_KEY_LEN);
  zt_free(k_pass);
  return ret;
}

/**
 * Completes the handshake process by decapsulating the PQ-KEM shared secret
 * SS = decaps(CT, PQPK)
 *
 * This stage synchronizes the client and server and both parties have
 * everything they need to generate the session key.
 *
 * Note: This function is called by the initiator of the handshake process.
 *
 * NOTE: This function is called by the handshake initiator.
 */
err_t vcry_handshake_complete(vcry_ctx_t *ctx, const uint8_t *peerdata,
                              size_t peerdata_len) {
  err_t ret;
  uint8_t *p = NULL;
  uint64_t *p64 = NULL;
  uint8_t *peer_ct = NULL;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!peerdata)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_initiate)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_initiator)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (peerdata_len < (3 * sizeof(uint64_t)))
    return VCRY_ERR_SET(ctx, ERR_INVALID_DATUM);

  p64 = PTR64(peerdata);
  size_t peer_ec_pub_len = ntoh64(p64[0]);
  size_t peer_ec_curvename_len = ntoh64(p64[1]);
  size_t ct_len = ntoh64(p64[2]);

  if (peerdata_len <
      (3 * sizeof(uint64_t)) + peer_ec_pub_len + peer_ec_curvename_len + ct_len) {
    return VCRY_ERR_SET(ctx, ERR_INVALID_DATUM);
  }

  p = PTR8(peerdata + (3 * sizeof(uint64_t)));

  /** Must be freed using kex_free_peer_data() while releasing the handle */
  if ((ret = kex_new_peer_data(ctx->kex, &ctx->peer_ec_share, p, peer_ec_pub_len,
                               p + peer_ec_pub_len, peer_ec_curvename_len)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  peer_ct = p + peer_ec_pub_len + peer_ec_curvename_len;

  /**
   * Decapsulate the shared secret.
   *
   * Note: This memory is freed in the closing call to vcry_release()
   */
  if ((ret = kem_decapsulate(ctx->kem, peer_ct, ct_len, &ctx->ss, &ctx->ss_len)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  VCRY_STATE_CHANGE(ctx, vcry_hs_complete);
  return ERR_SUCCESS;
}

/**
 * Compute the session key:
 * skey = KDF(SS || DHE_SS || PQK || DHEK_A || DHEK_B || salt3 || "Compute
 *            session key (skey)")
 *
 * where DH_SS is the shared secret derived from the DHE key exchange, SS is
 * the shared secret derived from the PQ-KEM key encapsultion, PQK is the PQ-KEM
 * public key, and DHEK_A and DHEK_B are the DHE public keys of Alice and Bob.
 *
 * NOTE: This function is called by both the initiator and responder.
 */
err_t vcry_derive_session_key(vcry_ctx_t *ctx) {
  err_t ret = ERR_SUCCESS;
  uint8_t *shared_secret;
  uint8_t *pqpub;
  uint8_t *buf, *p, *tmp, *dhek_a, *dhek_b;
  size_t shared_secret_len = 0, buf_len = 0, tmp_len = 0, dhek_a_len, dhek_b_len;

  if (!ctx)
    return ERR_NULL_PTR;

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  /**
   * This call is symmetric across both roles,
   * so we check the correct state for each role
   */
  if (VCRY_HSHAKE_ROLE(ctx) == vcry_hshake_role_initiator) {
    if (VCRY_STATE(ctx) != vcry_hs_complete)
      return VCRY_ERR_SET(ctx, ERR_INVALID);
  } else if (VCRY_HSHAKE_ROLE(ctx) == vcry_hshake_role_responder) {
    if (VCRY_STATE(ctx) != vcry_hs_response)
      return VCRY_ERR_SET(ctx, ERR_INVALID);
  } else {
    return VCRY_ERR_SET(ctx, ERR_INVALID);
  }

  if ((ret = kex_derive_shared_key(ctx->kex, &ctx->peer_ec_share, &shared_secret,
                                   &shared_secret_len)) != ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  /** Get own DHE raw public key and store the length in buf_len */
  VCRY_EXPECT(kex_get_public_key_bytes(ctx->kex, &tmp, &tmp_len), ERR_SUCCESS, clean2);

  /**
   * Arrange dhek_a and dhek_b so they point to the initiator's
   * and responder's DHE public keys respectively, also set pqpub
   * to the PQ-KEM public key of the initiator
   */
  if (VCRY_HSHAKE_ROLE(ctx) == vcry_hshake_role_initiator) {
    dhek_a = tmp;
    dhek_a_len = tmp_len;
    dhek_b = ctx->peer_ec_share.ec_pub;
    dhek_b_len = ctx->peer_ec_share.ec_pub_len;
    pqpub = ctx->pqk;
  } else {
    dhek_a = ctx->peer_ec_share.ec_pub;
    dhek_a_len = ctx->peer_ec_share.ec_pub_len;
    dhek_b = tmp;
    dhek_b_len = tmp_len;
    pqpub = ctx->peer_pqk;
  }

  buf_len = ctx->ss_len + shared_secret_len + ctx->pqk_len + dhek_a_len + dhek_b_len;
  if (!(buf = zt_malloc(buf_len))) {
    ret = VCRY_ERR_SET(ctx, ERR_MEM_FAIL);
    goto clean1;
  }

  p = buf;
  memcpy(p, ctx->ss, ctx->ss_len);
  p += ctx->ss_len;
  memcpy(p, shared_secret, shared_secret_len);
  p += shared_secret_len;
  memcpy(p, pqpub, ctx->pqk_len);
  p += ctx->pqk_len;
  memcpy(p, dhek_a, dhek_a_len);
  p += dhek_a_len;
  memcpy(p, dhek_b, dhek_b_len);

  VCRY_EXPECT(kdf_init(ctx->kdf, buf, buf_len,
                       ctx->salt + VCRY_HSHAKE_SALT0_LEN + VCRY_HSHAKE_SALT1_LEN,
                       VCRY_HSHAKE_SALT2_LEN),
              ERR_SUCCESS, clean0);

  VCRY_EXPECT(kdf_derive(ctx->kdf, (const uint8_t *)VCRY_HSHAKE_CONST1,
                         strlen(VCRY_HSHAKE_CONST1), ctx->skey, VCRY_SESSION_KEY_LEN),
              ERR_SUCCESS, clean0);

  VCRY_STATE_CHANGE(ctx, vcry_hs_verify_initiate);

clean0:
  memzero(buf, buf_len);
  zt_free(buf);
clean1:
  memzero(tmp, tmp_len);
  zt_free(tmp);
clean2:
  memzero(shared_secret, shared_secret_len);
  zt_free(shared_secret);
  return ret;
}

#define SWAP(a, b)                                                                       \
  do {                                                                                   \
    typeof(a) _tmp = (a);                                                                \
    (a) = (b);                                                                           \
    (b) = _tmp;                                                                          \
  } while (0)

/**
 * Compute the initiator's verification message:
 * Proof_A = HMAC(K_mac_ini, MIN(ID_A, ID_B) || MAX(ID_A, ID_B) ||
 *                "First proof message (Proof_A)")
 *
 * The caller is responsible for freeing the `verify_msg` buffer.
 *
 * NOTE: This function performs a non-constant-time comparison of
 * ID_A and ID_B so these strings must not contain sensitive data.
 *
 * NOTE: This function is called by the handshake initiator.
 *
 * Returns an `err_t` status code.
 */
err_t vcry_initiator_verify_initiate(vcry_ctx_t *ctx, uint8_t **verify_msg,
                                     size_t *verify_msg_len, const uint8_t *id_a,
                                     const uint8_t *id_b, size_t len_a, size_t len_b) {
  err_t ret;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!verify_msg || !verify_msg_len)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_verify_initiate)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_initiator)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  /** Rearrange so that id_a <= id_b */
  if (memcmp(id_a, id_b, MIN(len_a, len_b)) > 0) {
    SWAP(id_a, id_b);
    SWAP(len_a, len_b);
  }

  if ((*verify_msg = zt_malloc(VCRY_VERIFY_MSG_LEN)) == NULL)
    return VCRY_ERR_SET(ctx, ERR_MEM_FAIL);

  if ((ret = hmac_init(ctx->mac, vcry_self_mac_key(ctx), VCRY_K_MAC_LEN)) !=
      ERR_SUCCESS) {
    zt_free(*verify_msg);
    return VCRY_ERR_SET(ctx, ret);
  }

  if (((ret = hmac_update(ctx->mac, id_a, len_a)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, id_b, len_b)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, (const uint8_t *)VCRY_VERIFY_CONST0,
                          strlen(VCRY_VERIFY_CONST0))) != ERR_SUCCESS)) {
    zt_free(*verify_msg);
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = hmac_compute(ctx->mac, NULL, 0, *verify_msg, VCRY_VERIFY_MSG_LEN)) !=
      ERR_SUCCESS) {
    zt_free(*verify_msg);
    return VCRY_ERR_SET(ctx, ret);
  }

  *verify_msg_len = VCRY_VERIFY_MSG_LEN;
  VCRY_STATE_CHANGE(ctx, vcry_hs_verify_complete);
  return ERR_SUCCESS;
}

/**
 * Compute the responder's verification message:
 * Proof_B = HMAC(K_mac_res, MAX(ID_A, ID_B) || MIN(ID_A, ID_B) ||
 *                "Second proof message (Proof_B)")
 *
 * The caller is responsible for freeing the `verify_msg` buffer.
 *
 * NOTE: This function performs a non-constant-time comparison of
 * ID_A and ID_B so these strings must not contain sensitive data.
 *
 * NOTE: This function is called by the handshake responder.
 *
 * Returns an `err_t` status code.
 */
err_t vcry_responder_verify_initiate(vcry_ctx_t *ctx, uint8_t **verify_msg,
                                     size_t *verify_msg_len, const uint8_t *id_a,
                                     const uint8_t *id_b, size_t len_a, size_t len_b) {
  err_t ret;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!verify_msg || !verify_msg_len)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_verify_initiate)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_responder)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  /** Rearrange so that id_a >= id_b */
  if (memcmp(id_a, id_b, MIN(len_a, len_b)) < 0) {
    SWAP(id_a, id_b);
    SWAP(len_a, len_b);
  }

  if ((*verify_msg = zt_malloc(VCRY_VERIFY_MSG_LEN)) == NULL)
    return VCRY_ERR_SET(ctx, ERR_MEM_FAIL);

  if ((ret = hmac_init(ctx->mac, vcry_self_mac_key(ctx), VCRY_K_MAC_LEN)) !=
      ERR_SUCCESS) {
    zt_free(*verify_msg);
    return VCRY_ERR_SET(ctx, ret);
  }

  if (((ret = hmac_update(ctx->mac, id_a, len_a)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, id_b, len_b)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, (const uint8_t *)VCRY_VERIFY_CONST1,
                          strlen(VCRY_VERIFY_CONST1))) != ERR_SUCCESS)) {
    zt_free(*verify_msg);
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = hmac_compute(ctx->mac, NULL, 0, *verify_msg, VCRY_VERIFY_MSG_LEN)) !=
      ERR_SUCCESS) {
    zt_free(*verify_msg);
    return VCRY_ERR_SET(ctx, ret);
  }

  *verify_msg_len = VCRY_VERIFY_MSG_LEN;
  VCRY_STATE_CHANGE(ctx, vcry_hs_verify_complete);
  return ERR_SUCCESS;
}

/**
 * Verify the responder's verification message:
 * Verify(ProofB, (HMAC(K_mac_res, MAX(ID_A, ID_B) || MIN(ID_A, ID_B) ||
 *                "Second proof message (Proof_B)")))
 *
 * NOTE: This function is called by the handshake initiator.
 *
 * Returns an `err_t` status code.
 */
err_t vcry_initiator_verify_complete(vcry_ctx_t *ctx,
                                     const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN],
                                     const uint8_t *id_a, const uint8_t *id_b,
                                     size_t len_a, size_t len_b) {
  err_t ret;
  uint8_t verify_msg_cmp[VCRY_VERIFY_MSG_LEN];

  if (!ctx)
    return ERR_NULL_PTR;

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_verify_complete)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_initiator)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  /** Rearrange so that id_a >= id_b */
  if (memcmp(id_a, id_b, MIN(len_a, len_b)) < 0) {
    SWAP(id_a, id_b);
    SWAP(len_a, len_b);
  }

  if ((ret = hmac_init(ctx->mac, vcry_peer_mac_key(ctx), VCRY_K_MAC_LEN)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if (((ret = hmac_update(ctx->mac, id_a, len_a)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, id_b, len_b)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, (const uint8_t *)VCRY_VERIFY_CONST1,
                          strlen(VCRY_VERIFY_CONST1))) != ERR_SUCCESS)) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = hmac_compute(ctx->mac, NULL, 0, verify_msg_cmp, VCRY_VERIFY_MSG_LEN)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if (zt_memcmp(verify_msg, verify_msg_cmp, VCRY_VERIFY_MSG_LEN))
    return VCRY_ERR_SET(ctx, ERR_AUTH_FAIL);

  VCRY_STATE_CHANGE(ctx, vcry_hs_done);
  return ERR_SUCCESS;
}

/**
 * Verify the initiator's verification message:
 * Verify(ProofA, (HMAC(K_mac_ini, MIN(ID_A, ID_B) || MAX(ID_A, ID_B) ||
 *                "First proof message (Proof_A)")))
 *
 * NOTE: This function is called by the handshake responder.
 *
 * Returns an `err_t` status code.
 */
err_t vcry_responder_verify_complete(vcry_ctx_t *ctx,
                                     const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN],
                                     const uint8_t *id_a, const uint8_t *id_b,
                                     size_t len_a, size_t len_b) {
  err_t ret;
  uint8_t verify_msg_cmp[VCRY_VERIFY_MSG_LEN];

  if (!ctx)
    return ERR_NULL_PTR;

  if (VCRY_FLAG_GET(vcry_fl_all_set) != vcry_fl_all_set)
    return VCRY_ERR_SET(ctx, ERR_NOT_INIT);

  if (VCRY_STATE(ctx) != vcry_hs_verify_complete)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (VCRY_HSHAKE_ROLE(ctx) != vcry_hshake_role_responder)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  /** Rearrange so that id_a <= id_b */
  if (memcmp(id_a, id_b, MIN(len_a, len_b)) > 0) {
    SWAP(id_a, id_b);
    SWAP(len_a, len_b);
  }

  if ((ret = hmac_init(ctx->mac, vcry_peer_mac_key(ctx), VCRY_K_MAC_LEN)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if (((ret = hmac_update(ctx->mac, id_a, len_a)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, id_b, len_b)) != ERR_SUCCESS) ||
      ((ret = hmac_update(ctx->mac, (const uint8_t *)VCRY_VERIFY_CONST0,
                          strlen(VCRY_VERIFY_CONST0))) != ERR_SUCCESS)) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = hmac_compute(ctx->mac, NULL, 0, verify_msg_cmp, VCRY_VERIFY_MSG_LEN)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if (zt_memcmp(verify_msg, verify_msg_cmp, VCRY_VERIFY_MSG_LEN))
    return VCRY_ERR_SET(ctx, ERR_AUTH_FAIL);

  VCRY_STATE_CHANGE(ctx, vcry_hs_done);
  return ERR_SUCCESS;
}

/**
 * Encrypt data in \p in of size \p in_len using the selected AEAD cipher
 * algorithm with the key material derived for this session, and store the
 * result in \p out.
 * \p out_len must contain the length of the buffer pointed to by \p out,
 * sufficient to store the encrypted data and the authentication tag.
 *
 * \p in and \p out can overlap.
 *
 * A successful encryption will result in \p out_len being set to the total
 * length of the encrypted and authenticated payload.
 *
 * The client must make sure the output buffer is large enough to hold the
 * encrypted data as well as the authentication tag. The length of the tag
 * can be queried by calling `vcry_get_aead_tag_len()`.
 *
 * Performs
 * out[in_len] = AEAD-Enc(in[in_len], k=K_encr_self, iv=nonce, aad=ad[ad_len])
 * and returns out[in_len] || tag[Tag_len]
 *
 * Here, `nonce` = `sequence_number_self` XOR `IV_peer` and `sequence_number_self` is the
 * client's 64-bit sequence number, read in Big-Endian byte order and left-padded with
 * zeros to match the VCRY_IV_ENCR_LEN.
 *
 * NOTE: This function may only be called after the handshake is complete.
 *
 * Returns an `err_t` status code.
 *
 * If the buffer pointed to by \p out is too small to store the encrypted data
 * and the tag, the function returns an `ERR_BUFFER_TOO_SMALL`.
 */
err_t vcry_aead_encrypt(vcry_ctx_t *ctx, uint8_t *in, size_t in_len, const uint8_t *ad,
                        size_t ad_len, uint8_t *out, size_t *out_len) {
  err_t ret;
  size_t tag_len;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!in || !out || !out_len)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_STATE(ctx) != vcry_hs_done)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (ctx->sn_self == UINT64_MAX)
    return VCRY_ERR_SET(ctx, ERR_OPERATION_LIMIT_REACHED);

  tag_len = cipher_tag_len(ctx->aead);
  if (*out_len < in_len + tag_len)
    return VCRY_ERR_SET(ctx, ERR_BUFFER_TOO_SMALL);

  if ((ret = cipher_init(ctx->aead, vcry_encr_key(ctx), VCRY_K_ENCR_LEN,
                         CIPHER_OPERATION_ENCRYPT)) != ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = cipher_set_iv(ctx->aead, vcry_encr_nonce(ctx), VCRY_IV_ENCR_LEN)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = cipher_set_aad(ctx->aead, ad, ad_len)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  if ((ret = cipher_encrypt(ctx->aead, in, in_len, out, out_len)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  ctx->sn_self += 1;

  return ERR_SUCCESS;
}

/**
 * Decrypt data in \p in of size \p in_len using the selected AEAD cipher
 * algorithm with the key material derived for this session, and store the
 * result in \p out.
 * \p out_len must contain the length of the buffer pointed to by \p out,
 * sufficient to store the plaintext.
 *
 * \p in and \p out can overlap.
 *
 * A successful decryption will result in \p out_len being set to the length of
 * the plaintext data.
 *
 * Performs
 * out[in_len] = AEAD-Dec(in[in_len], k=K_encr_peer, iv=nonce, aad=ad[ad_len])
 *
 * Here, `nonce` = `sequence_number_peer` XOR `IV_peer` and `sequence_number_peer` is the
 * peer's 64-bit sequence number, read in Big-Endian byte order and left-padded with zeros
 * to match the VCRY_IV_ENCR_LEN.
 *
 * NOTE: This function may only be called after the handshake is complete.
 *
 * Returns an `err_t` status code.
 *
 * If the buffer pointed to by \p out is too small to store the decrypted data,
 * the function returns an `ERR_BUFFER_TOO_SMALL`.
 */
err_t vcry_aead_decrypt(vcry_ctx_t *ctx, uint8_t *in, size_t in_len, const uint8_t *ad,
                        size_t ad_len, uint8_t *out, size_t *out_len) {
  err_t ret;
  size_t tag_len;

  if (!ctx)
    return ERR_NULL_PTR;

  if (!in || !out || !out_len)
    return VCRY_ERR_SET(ctx, ERR_NULL_PTR);

  if (VCRY_STATE(ctx) != vcry_hs_done)
    return VCRY_ERR_SET(ctx, ERR_INVALID);

  if (ctx->sn_peer == UINT64_MAX)
    return VCRY_ERR_SET(ctx, ERR_OPERATION_LIMIT_REACHED);

  tag_len = cipher_tag_len(ctx->aead);

  /* Invalid message */
  if (in_len < tag_len)
    return VCRY_ERR_SET(ctx, ERR_INVALID_DATUM);

  if (*out_len < in_len - tag_len)
    return VCRY_ERR_SET(ctx, ERR_BUFFER_TOO_SMALL);

  if ((ret = cipher_init(ctx->aead, vcry_decr_key(ctx), VCRY_K_ENCR_LEN,
                         CIPHER_OPERATION_DECRYPT)) != ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = cipher_set_iv(ctx->aead, vcry_decr_nonce(ctx), VCRY_IV_ENCR_LEN)) !=
      ERR_SUCCESS) {
    return VCRY_ERR_SET(ctx, ret);
  }

  if ((ret = cipher_set_aad(ctx->aead, ad, ad_len)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  if ((ret = cipher_decrypt(ctx->aead, in, in_len, out, out_len)) != ERR_SUCCESS)
    return VCRY_ERR_SET(ctx, ret);

  ctx->sn_peer += 1;

  return ERR_SUCCESS;
}
