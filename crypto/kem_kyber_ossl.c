/**
 * kem_kyber_ossl.c
 *
 * OpenSSL implementation of the KEM-Kyber interface
 *
 * vibhav950 on GitHub
 */

#include "common/defines.h"
#include "common/log.h"
#include "kem.h"
#include "kem_kyber_defs.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

typedef struct kem_ossl_ctx_st {
  EVP_PKEY_CTX *pkey_ctx;
  EVP_PKEY *pkey_priv;
  int nid;
} kem_ossl_ctx;

#define KEM_FLAG_SET(kem, flag) ((void)((kem)->flags |= flag))
#define KEM_FLAG_GET(kem, flag) ((kem)->flags & flag)

#define OSSL_CHECK(rv)                                                                   \
  do {                                                                                   \
    if ((rv) <= 0) {                                                                     \
      ret = ERR_INTERNAL;                                                                \
      goto cleanup;                                                                      \
    }                                                                                    \
  } while (0)

/**
 *
 */
static err_t ossl_kem_alloc(kem_t **kem, kem_alg_t alg) {
  extern const kem_intf_t kem_kyber_intf;
  kem_ossl_ctx *ossl_ctx;
  EVP_PKEY_CTX *pctx;
  EVP_PKEY *pkey;
  int kem_nid;

  log_debug(NULL, "alg=%s", kem_alg_to_string(alg));

  switch (alg) {
  case KEM_Kyber_512:
    kem_nid = NID_ML_KEM_512;
    break;
  case KEM_Kyber_768:
    kem_nid = NID_ML_KEM_768;
    break;
  case KEM_Kyber_1024:
    kem_nid = NID_ML_KEM_1024;
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (!(*kem = zt_calloc(1, sizeof(kem_t))))
    return ERR_MEM_FAIL;

  if (!(ossl_ctx = zt_calloc(1, sizeof(kem_ossl_ctx)))) {
    zt_free(*kem);
    *kem = NULL;
    return ERR_MEM_FAIL;
  }

  if (!(pctx = EVP_PKEY_CTX_new_id(kem_nid, NULL))) {
    zt_free(ossl_ctx);
    zt_free(*kem);
    *kem = NULL;
    return ERR_INTERNAL;
  }

  ossl_ctx->nid = kem_nid;
  ossl_ctx->pkey_ctx = pctx;

  (*kem)->intf = &kem_kyber_intf;
  (*kem)->ctx = ossl_ctx;
  (*kem)->alg = alg;
  KEM_FLAG_SET(*kem, KEM_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 *
 */
static void ossl_kem_dealloc(kem_t *kem) {
  log_debug(NULL, "-");

  if (KEM_FLAG_GET(kem, KEM_FLAG_ALLOC)) {
    kem_ossl_ctx *ctx = (kem_ossl_ctx *)kem->ctx;

    if (ctx) {
      EVP_PKEY_CTX_free(ctx->pkey_ctx);
      memzero(ctx, sizeof(kem_ossl_ctx));
      zt_free(ctx);
    }
  }
  if (KEM_FLAG_GET(kem, KEM_FLAG_KEYGEN))
    OPENSSL_secure_clear_free(kem->privkey, kem->privkey_len);

  memzero(kem, sizeof(kem_t));
  zt_free(kem);
}

/**
 *
 */
static void ossl_kem_mem_free(void *ptr, size_t len) {
  OPENSSL_secure_clear_free(ptr, len);
}

/**
 *
 */
static err_t ossl_kem_keypair_gen(kem_t *kem, uint8_t **pubkey, size_t *pubkey_len) {
  err_t ret = ERR_SUCCESS;
  kem_ossl_ctx *ossl_ctx;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL;
  uint8_t *pub = NULL;
  size_t pub_len;

  log_debug(NULL, "-");

  if (!pubkey || !pubkey_len)
    return ERR_NULL_PTR;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  ossl_ctx = (kem_ossl_ctx *)kem->ctx;
  pctx = ossl_ctx->pkey_ctx;

  OSSL_CHECK(EVP_PKEY_keygen_init(pctx));
  OSSL_CHECK(EVP_PKEY_keygen(pctx, &pkey));

  /* Query the buffer size for the public key */
  OSSL_CHECK(
      EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len));

  if (!(pub = OPENSSL_malloc(pub_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }

  OSSL_CHECK(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len,
                                             &pub_len));

  *pubkey = pub;
  *pubkey_len = pub_len;

  ossl_ctx->pkey_priv = pkey;
  KEM_FLAG_SET(kem, KEM_FLAG_KEYGEN);

cleanup:
  if (ret != ERR_SUCCESS) {
    OPENSSL_free(pub);
    EVP_PKEY_free(pkey);
  }
  return ret;
}

/**
 *
 */
static err_t ossl_kem_encapsulate(kem_t *kem, const uint8_t *peer_pubkey,
                                  size_t peer_pubkey_len, uint8_t **ct, size_t *ct_len,
                                  uint8_t **ss, size_t *ss_len) {
  err_t ret = ERR_SUCCESS;
  kem_ossl_ctx *ossl_ctx;
  kem_alg_t alg;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *param = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  uint8_t *secret = NULL, *out = NULL;
  size_t secret_len, out_len;

  log_debug(NULL, "peer_pubkey_len=%zu", peer_pubkey_len);

  if (!peer_pubkey || !ct || !ct_len || !ss || !ss_len)
    return ERR_NULL_PTR;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  ossl_ctx = (kem_ossl_ctx *)kem->ctx;
  alg = kem->alg;

  switch (alg) {
  case KEM_Kyber_512:
    if (peer_pubkey_len != KEM_KYBER_512_PUBKEY_SIZE)
      return ERR_BAD_ARGS;
    break;
  case KEM_Kyber_768:
    if (peer_pubkey_len != KEM_KYBER_768_PUBKEY_SIZE)
      return ERR_BAD_ARGS;
    break;
  case KEM_Kyber_1024:
    if (peer_pubkey_len != KEM_KYBER_1024_PUBKEY_SIZE)
      return ERR_BAD_ARGS;
    break;
  }

  /**
   * Reconstruct the peer's EVP_PKEY encapsulation (public) key
   */
  if (!(param_bld = OSSL_PARAM_BLD_new())) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }
  OSSL_CHECK(OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                              peer_pubkey, peer_pubkey_len));
  if (!(param = OSSL_PARAM_BLD_to_param(param_bld))) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_PKEY_fromdata_init(ossl_ctx->pkey_ctx));
  OSSL_CHECK(EVP_PKEY_fromdata(ossl_ctx->pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, param));

  pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
  if (!pctx) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }

  /**
   * Encapsulate the shared secret
   */
  if (EVP_PKEY_encapsulate_init(pctx, NULL) <= 0) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }

  OSSL_CHECK(EVP_PKEY_encapsulate(pctx, NULL, &out_len, NULL, &secret_len));

  out = OPENSSL_malloc(out_len);
  secret = OPENSSL_malloc(secret_len);
  if (!out || !secret) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }

  OSSL_CHECK(EVP_PKEY_encapsulate(pctx, out, &out_len, secret, &secret_len));

  *ct = out;
  *ct_len = out_len;
  *ss = secret;
  *ss_len = secret_len;

cleanup:
  if (ret != ERR_SUCCESS) {
    OPENSSL_free(out);
    OPENSSL_free(secret);
  }
  OSSL_PARAM_free(param);
  OSSL_PARAM_BLD_free(param_bld);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pctx);
  return ret;
}

/**
 *
 */
static err_t ossl_kem_decapsulate(kem_t *kem, const uint8_t *ct, size_t ct_len,
                                  uint8_t **ss, size_t *ss_len) {
  err_t ret = ERR_SUCCESS;
  kem_ossl_ctx *ossl_ctx;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  uint8_t *secret = NULL;
  size_t secret_len;

  log_debug(NULL, "ct_len=%zu", ct_len);

  if (!ct || !ss || !ss_len)
    return ERR_NULL_PTR;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = (kem_ossl_ctx *)kem->ctx;

  pkey = ossl_ctx->pkey_priv;

  if (!(pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL))) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }

  /**
   * Decapsulate the shared secret
   */
  if (EVP_PKEY_decapsulate_init(pctx, NULL) <= 0) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }

  OSSL_CHECK(EVP_PKEY_decapsulate(pctx, NULL, &secret_len, ct, ct_len));

  if (!(secret = OPENSSL_malloc(secret_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }

  OSSL_CHECK(EVP_PKEY_decapsulate(pctx, secret, &secret_len, ct, ct_len));

  *ss = secret;
  *ss_len = secret_len;

cleanup:
  if (ret != ERR_SUCCESS)
    OPENSSL_free(secret);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pctx);
  return ret;
}

const kem_intf_t kem_kyber_intf = {
    .alloc = ossl_kem_alloc,
    .dealloc = ossl_kem_dealloc,
    .mem_free = ossl_kem_mem_free,
    .keygen = ossl_kem_keypair_gen,
    .encapsulate = ossl_kem_encapsulate,
    .decapsulate = ossl_kem_decapsulate,
};