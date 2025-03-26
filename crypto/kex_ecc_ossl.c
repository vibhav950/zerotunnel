/**
 * @file kex_ecc_ossl.c
 * Key exchange using Elliptic Curve Cryptography (ECC) with OpenSSL
 */

// DO NOT REMOVE/MOVE THIS
#if !defined(__ZTLIB_ENVIRON_SAFE_MEM) || !__ZTLIB_ENVIRON_SAFE_MEM
#error "__ZTLIB_ENVIRON_SAFE_MEM must be defined and set to 1"
#endif

#include "common/defines.h"
#include "common/memzero.h"
#include "kex.h"
#include "kex_ecc.h"

#include <openssl/core_names.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#define OSSL_CHECK(rv)                                                         \
  do {                                                                         \
    if (!(rv)) {                                                               \
      ret = ERR_INTERNAL;                                                      \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

#define KEX_FLAG_SET(kex, flag) (void)((kex)->flags |= flag)
#define KEX_FLAG_GET(kex, flag) ((kex)->flags & flag)

/**
 *
 */
static error_t ossl_kex_ecc_alloc(kex_t **kex, kex_curve_t curve) {
  error_t ret = ERR_SUCCESS;
  extern const kex_intf_t kex_ecc_intf;
  kex_ossl_ctx *ossl_ctx = NULL;
  EVP_PKEY_CTX *paramgen_ctx = NULL;
  EVP_PKEY *paramgen = NULL;
  int ec_nid, id;

  PRINTDEBUG("curve=%s", kex_curve_name(curve));

  switch (curve) {
  case KEX_CURVE_secp256k1:
    ec_nid = NID_secp256k1;
    break;
  case KEX_CURVE_secp384r1:
    ec_nid = NID_secp384r1;
    break;
  case KEX_CURVE_secp521r1:
    ec_nid = NID_secp521r1;
    break;
  case KEX_CURVE_prime239v3:
    ec_nid = NID_X9_62_prime239v3;
    break;
  case KEX_CURVE_prime256v1:
    ec_nid = NID_X9_62_prime256v1;
    break;
  case KEX_CURVE_X25519:
    ec_nid = NID_X25519;
    break;
  case KEX_CURVE_X448:
    ec_nid = NID_X448;
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (!(*kex = (kex_t *)zt_calloc(1, sizeof(kex_t))))
    return ERR_MEM_FAIL;

  if (!(ossl_ctx = (kex_ossl_ctx *)zt_calloc(1, sizeof(kex_ossl_ctx)))) {
    zt_free(*kex);
    *kex = NULL;
    return ERR_MEM_FAIL;
  }

  switch (ec_nid) {
  case NID_X25519:
    id = EVP_PKEY_X25519;
    break;
  case NID_X448:
    id = EVP_PKEY_X448;
    break;
  default:
    /* Standard EC curves */
    id = EVP_PKEY_EC;
  }

  OSSL_CHECK(paramgen_ctx = EVP_PKEY_CTX_new_id(id, NULL));
  OSSL_CHECK(EVP_PKEY_paramgen_init(paramgen_ctx));
  OSSL_CHECK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramgen_ctx, ec_nid));
  OSSL_CHECK(EVP_PKEY_paramgen(paramgen_ctx, &paramgen));

  ossl_ctx->ec_params = paramgen;
  ossl_ctx->nid = ec_nid;

  (*kex)->intf = &kex_ecc_intf;
  (*kex)->ctx = ossl_ctx;
  (*kex)->curve = curve;
  KEX_FLAG_SET(*kex, KEX_FLAG_ALLOC);

cleanup:
  EVP_PKEY_CTX_free(paramgen_ctx);
  return ret;
}

/**
 *
 */
static void ossl_kex_ecc_dealloc(kex_t *kex) {
  PRINTDEBUG("");

  if (KEX_FLAG_GET(kex, KEX_FLAG_ALLOC)) {
    kex_ossl_ctx *ctx = (kex_ossl_ctx *)kex->ctx;

    if (ctx) {
      EVP_PKEY_free(ctx->ec_key);
      EVP_PKEY_free(ctx->ec_params);
      /* Prevent state leaks */
      memzero(ctx, sizeof(kex_ossl_ctx));
      zt_free(ctx);
    }
  }
  memzero(kex, sizeof(kex_t));
  zt_free(kex);
  kex = NULL;
}

/**
 *
 */
static error_t ossl_kex_ecc_key_gen(kex_t *kex) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  EVP_PKEY_CTX *keygen_ctx = NULL;
  EVP_PKEY *ec_key = NULL;

  PRINTDEBUG("");

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  ossl_ctx = kex->ctx;

  OSSL_CHECK(keygen_ctx = EVP_PKEY_CTX_new(ossl_ctx->ec_params, NULL));
  OSSL_CHECK(EVP_PKEY_keygen_init(keygen_ctx));
  OSSL_CHECK(EVP_PKEY_keygen(keygen_ctx, &ec_key));
  ossl_ctx->ec_key = ec_key;
  KEX_FLAG_SET(kex, KEX_FLAG_KEYGEN);

cleanup:
  EVP_PKEY_CTX_free(keygen_ctx);
  return ret;
}

/**
 *
 */
static error_t ossl_kex_ecc_get_peer_data(kex_t *kex,
                                          kex_peer_share_t *peer_data) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  unsigned char *pubkey = NULL;
  char *curvename = NULL;
  size_t pubkey_len = 0, curvename_len = 0;
  int ec_nid;

  PRINTDEBUG("");

  if (!peer_data)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;
  ec_nid = ossl_ctx->nid;

  /**
   * Since X25519 and X448 aren't standard EC curves, OpenSSL
   * offers a different interface for extracting the raw keys
   */
  if (ec_nid == NID_X25519 || ec_nid == NID_X448) {
    /* Query buffer size */
    OSSL_CHECK(
        EVP_PKEY_get_raw_public_key(ossl_ctx->ec_key, NULL, &pubkey_len));

    if (!(pubkey = zt_calloc(1, pubkey_len))) {
      ret = ERR_MEM_FAIL;
      goto cleanup;
    }

    /* Get public key */
    OSSL_CHECK(
        EVP_PKEY_get_raw_public_key(ossl_ctx->ec_key, pubkey, &pubkey_len));
  } else {
    /* Query the buffer size */
    OSSL_CHECK(EVP_PKEY_get_octet_string_param(
        ossl_ctx->ec_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubkey_len));

    /* Allocate the buffer for the public key */
    if (!(pubkey = zt_calloc(1, pubkey_len))) {
      ret = ERR_MEM_FAIL;
      goto cleanup;
    }

    /**
     * Get the public key
     */
    OSSL_CHECK(EVP_PKEY_get_octet_string_param(ossl_ctx->ec_key,
                                               OSSL_PKEY_PARAM_PUB_KEY, pubkey,
                                               pubkey_len, &pubkey_len));

    OSSL_CHECK(EVP_PKEY_get_utf8_string_param(
        ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &curvename_len));

    ++curvename_len; /* Null terminator */
    if (!(curvename = zt_calloc(1, curvename_len))) {
      ret = ERR_MEM_FAIL;
      goto cleanup;
    }

    /**
     * Get the group name
     */
    OSSL_CHECK(EVP_PKEY_get_utf8_string_param(
        ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, curvename, curvename_len,
        &curvename_len));
  }

  peer_data->ec_pub = pubkey;
  peer_data->ec_pub_len = pubkey_len;
  peer_data->ec_curvename = curvename;
  peer_data->ec_curvename_len = curvename_len;

cleanup:
  if (ret) {
    zt_free(pubkey);
    zt_free(curvename);
    pubkey = curvename = NULL;
  }

  return ret;
}

static error_t ossl_kex_ecc_new_peer_data(kex_peer_share_t *peer_data,
                                          const uint8_t *ec_pub,
                                          size_t ec_pub_len,
                                          const uint8_t *ec_curvename,
                                          size_t ec_curvename_len) {
  PRINTDEBUG("");

  if (!peer_data)
    return ERR_NULL_PTR;

  peer_data->ec_pub = zt_memdup(ec_pub, ec_pub_len);
  peer_data->ec_pub_len = ec_pub_len;
  peer_data->ec_curvename = zt_memdup(ec_curvename, ec_curvename_len);
  peer_data->ec_curvename_len = ec_curvename_len;

  return ERR_SUCCESS;
}

static void ossl_kex_ecc_free_peer_data(kex_peer_share_t *peer_data) {
  PRINTDEBUG("");

  if (!peer_data)
    return;

  memzero(peer_data->ec_pub, peer_data->ec_pub_len);
  memzero(peer_data->ec_curvename, peer_data->ec_curvename_len);
  zt_free(peer_data->ec_pub);
  zt_free(peer_data->ec_curvename);
}

/**
 *
 */
static error_t ossl_kex_ecc_derive_shared_key(kex_t *kex,
                                              kex_peer_share_t *peer_data,
                                              unsigned char **shared_key,
                                              size_t *shared_key_len) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  EVP_PKEY *peer_key = NULL;
  EVP_PKEY_CTX *derive_ctx = NULL, *peer_key_ctx = NULL;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *param = NULL;
  int ec_nid;

  PRINTDEBUG("");

  if (!peer_data || !shared_key || !shared_key_len)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;
  ec_nid = ossl_ctx->nid;

  /**
   * Reconstruct the peer's EVP_PKEY public key
   */
  if (ec_nid == NID_X25519 || ec_nid == NID_X448) {
    peer_key = EVP_PKEY_new_raw_public_key(
        ossl_ctx->nid, NULL, peer_data->ec_pub, peer_data->ec_pub_len);

    if (!peer_key) {
      ret = ERR_INTERNAL;
      goto cleanup;
    }
  } else {
    OSSL_CHECK(param_bld = OSSL_PARAM_BLD_new());
    OSSL_CHECK(OSSL_PARAM_BLD_push_octet_string(
        param_bld, OSSL_PKEY_PARAM_PUB_KEY, peer_data->ec_pub,
        peer_data->ec_pub_len));
    OSSL_CHECK(OSSL_PARAM_BLD_push_utf8_string(
        param_bld, OSSL_PKEY_PARAM_GROUP_NAME, peer_data->ec_curvename,
        peer_data->ec_curvename_len));
    OSSL_CHECK(param = OSSL_PARAM_BLD_to_param(param_bld));
    OSSL_CHECK(peer_key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
    OSSL_CHECK(EVP_PKEY_fromdata_init(peer_key_ctx));
    OSSL_CHECK(
        EVP_PKEY_fromdata(peer_key_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY, param));
  }

  /**
   * Derive the shared secret
   */
  OSSL_CHECK(derive_ctx = EVP_PKEY_CTX_new(ossl_ctx->ec_key, NULL));
  OSSL_CHECK(EVP_PKEY_derive_init(derive_ctx));
  OSSL_CHECK(EVP_PKEY_derive_set_peer(derive_ctx, peer_key));

  /* Query buffer size for shared secret */
  *shared_key_len = 0;
  OSSL_CHECK(EVP_PKEY_derive(derive_ctx, NULL, shared_key_len));

  if (!(*shared_key = zt_calloc(1, *shared_key_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_PKEY_derive(derive_ctx, *shared_key, shared_key_len));

cleanup:
  OSSL_PARAM_free(param);
  OSSL_PARAM_BLD_free(param_bld);
  EVP_PKEY_CTX_free(peer_key_ctx);
  EVP_PKEY_free(peer_key);
  EVP_PKEY_CTX_free(derive_ctx);
  return ret;
}

/**
 *
 */
static error_t ossl_kex_ecc_get_public_key_bytes(kex_t *kex, uint8_t **pubkey,
                                                 size_t *pubkey_len) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  size_t required;
  int ec_nid;

  PRINTDEBUG("");

  if (!pubkey || !pubkey_len)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;
  ec_nid = ossl_ctx->nid;

  /** Get the required buffer length */
  required = 0;
  if (ec_nid == NID_X25519 || ec_nid == NID_X448) {
    OSSL_CHECK(EVP_PKEY_get_raw_public_key(ossl_ctx->ec_key, NULL, &required));
  } else {
    OSSL_CHECK(EVP_PKEY_get_octet_string_param(
        ossl_ctx->ec_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &required));
  }

  if (!(*pubkey = zt_malloc(required)))
    return ERR_MEM_FAIL;
  *pubkey_len = required;

  if (ec_nid == NID_X25519 || ec_nid == NID_X448) {
    OSSL_CHECK(
        EVP_PKEY_get_raw_public_key(ossl_ctx->ec_key, *pubkey, pubkey_len));
  } else {
    OSSL_CHECK(EVP_PKEY_get_octet_string_param(ossl_ctx->ec_key,
                                               OSSL_PKEY_PARAM_PUB_KEY, *pubkey,
                                               required, pubkey_len));
  }

cleanup:
  return ret;
}

const kex_intf_t kex_ecc_intf = {
    .alloc = ossl_kex_ecc_alloc,
    .dealloc = ossl_kex_ecc_dealloc,
    .key_gen = ossl_kex_ecc_key_gen,
    .get_peer_data = ossl_kex_ecc_get_peer_data,
    .new_peer_data = ossl_kex_ecc_new_peer_data,
    .free_peer_data = ossl_kex_ecc_free_peer_data,
    .derive_shared_key = ossl_kex_ecc_derive_shared_key,
    .get_public_key_bytes = ossl_kex_ecc_get_public_key_bytes,
    .supported_curves = KEX_CURVE_secp256k1 | KEX_CURVE_secp384r1 |
                        KEX_CURVE_secp521r1 | KEX_CURVE_prime239v3 |
                        KEX_CURVE_prime256v1 | KEX_CURVE_X25519 |
                        KEX_CURVE_X448};
