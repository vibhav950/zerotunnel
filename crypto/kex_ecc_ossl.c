#include "common/defs.h"
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
error_t ossl_kex_ecc_alloc(kex_t **kex, kex_curve_t curve) {
  error_t ret = ERR_SUCCESS;
  extern const kex_intf_t kex_ecc_intf;
  kex_ossl_ctx *ossl_ctx = NULL;
  EVP_PKEY_CTX *paramgen_ctx = NULL;
  EVP_PKEY *paramgen = NULL;
  int ec_nid = -1;

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
  default:
    return ERR_BAD_ARGS;
  }

  if (!(*kex = (kex_t *)xcalloc(1, sizeof(kex_t))))
    return ERR_MEM_FAIL;

  if (!(ossl_ctx = (kex_ossl_ctx *)xcalloc(1, sizeof(kex_ossl_ctx)))) {
    xfree(*kex);
    *kex = NULL;
    return ERR_MEM_FAIL;
  }

  OSSL_CHECK(paramgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
  OSSL_CHECK(EVP_PKEY_paramgen_init(paramgen_ctx));
  OSSL_CHECK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramgen_ctx, ec_nid));
  OSSL_CHECK(EVP_PKEY_paramgen(paramgen_ctx, &paramgen));

  ossl_ctx->ec_params = paramgen;

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
error_t ossl_kex_ecc_dealloc(kex_t *kex) {
  PRINTDEBUG("");

  if (KEX_FLAG_GET(kex, KEX_FLAG_ALLOC)) {
    kex_ossl_ctx *ctx = (kex_ossl_ctx *)kex->ctx;

    if (ctx) {
      EVP_PKEY_free(ctx->ec_key);
      EVP_PKEY_free(ctx->ec_params);
      /* Prevent state leaks */
      memzero(ctx, sizeof(kex_ossl_ctx));
      xfree(ctx);
    }
  }
  memzero(kex, sizeof(kex_t));
  xfree(kex);
  kex = NULL;

  return ERR_SUCCESS;
}

/**
 *
 */
error_t ossl_kex_ecc_key_gen(kex_t *kex) {
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
error_t ossl_kex_ecc_get_peer_data(kex_t *kex, kex_peer_share_t *peer_data,
                                   const unsigned char *authkey,
                                   size_t authkey_len) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  EVP_PKEY *mac_key = NULL;
  unsigned char *pubkey = NULL, *mac = NULL;
  char *curvename = NULL;
  size_t pubkey_len = 0, curvename_len = 0, mac_len = 0;
  const EVP_MD *md = EVP_sha3_256();
  EVP_MD_CTX *md_ctx = NULL;

  PRINTDEBUG("");

  if (!peer_data)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;

  /* Query the buffer size */
  OSSL_CHECK(EVP_PKEY_get_octet_string_param(
      ossl_ctx->ec_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubkey_len));

  /* Allocate the buffer for the public key */
  if (!(pubkey = xcalloc(1, pubkey_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }

  /**
   * Get the public key
   */
  OSSL_CHECK(EVP_PKEY_get_octet_string_param(ossl_ctx->ec_key,
                                             OSSL_PKEY_PARAM_PUB_KEY, pubkey,
                                             pubkey_len, &pubkey_len));

  /* Query the buffer size */
  OSSL_CHECK(EVP_PKEY_get_utf8_string_param(
      ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &curvename_len));

  ++curvename_len; /* Null terminator */
  if (!(curvename = xcalloc(1, curvename_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }

  /**
   * Get the group name
   */
  OSSL_CHECK(EVP_PKEY_get_utf8_string_param(
      ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, curvename, curvename_len,
      &curvename_len));

  /**
   * Compute a HMAC over the public key
   */
  OSSL_CHECK(md_ctx = EVP_MD_CTX_new());
  OSSL_CHECK(mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, authkey,
                                            authkey_len));
  OSSL_CHECK(EVP_DigestSignInit(md_ctx, NULL, md, NULL, mac_key));
  OSSL_CHECK(EVP_DigestSignUpdate(md_ctx, pubkey, pubkey_len));
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, NULL, &mac_len));

  if (!(mac = xcalloc(1, mac_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, mac, &mac_len));

  peer_data->ec_pub = pubkey;
  peer_data->ec_pub_len = pubkey_len;
  peer_data->ec_curvename = curvename;
  peer_data->ec_curvename_len = curvename_len;
  peer_data->mac = mac;
  peer_data->mac_len = mac_len;

cleanup:
  EVP_PKEY_free(mac_key);
  EVP_MD_CTX_free(md_ctx);
  return ret;
}

void ossl_kex_ecc_free_peer_data(kex_peer_share_t *peer_data) {
  if (!peer_data)
    return;

  memzero(peer_data->ec_pub, peer_data->ec_pub_len);
  memzero(peer_data->ec_curvename, peer_data->ec_curvename_len);
  memzero(peer_data->mac, peer_data->mac_len);
  xfree(peer_data->ec_pub);
  xfree(peer_data->ec_curvename);
  xfree(peer_data->mac);
}

/**
 *
 */
error_t ossl_kex_ecc_derive_shared_key(kex_t *kex, kex_peer_share_t *peer_data,
                                       const unsigned char *authkey,
                                       size_t authkey_len,
                                       unsigned char **shared_key,
                                       size_t *shared_key_len) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  EVP_PKEY *peer_key = NULL, *mac_key = NULL;
  EVP_PKEY_CTX *derive_ctx = NULL, *peer_key_ctx = NULL;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *param = NULL;
  unsigned char *mac = NULL;
  size_t mac_len = 0;
  const EVP_MD *md = EVP_sha3_256();
  EVP_MD_CTX *md_ctx = NULL;

  PRINTDEBUG("");

  if (!peer_data || !shared_key || !shared_key_len)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;

  /**
   * Reconstruct the peer's EVP_PKEY public key
   */
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

  /**
   * Compute the HMAC over the public key and compare the HMAC with
   * the value received from the peer
   */
  OSSL_CHECK(md_ctx = EVP_MD_CTX_new());
  OSSL_CHECK(mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, authkey,
                                            authkey_len));
  OSSL_CHECK(EVP_DigestSignInit(md_ctx, NULL, md, NULL, mac_key));
  OSSL_CHECK(
      EVP_DigestSignUpdate(md_ctx, peer_data->ec_pub, peer_data->ec_pub_len));

  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, NULL, &mac_len));

  if (!(mac = xcalloc(1, mac_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, mac, &mac_len));

  /* Compare values */
  if (mac_len != peer_data->mac_len ||
      CRYPTO_memcmp(mac, peer_data->mac, mac_len)) {
    ret = ERR_AUTH_FAIL;
    goto cleanup;
  }

  /**
   * Now that the public key is authenticated, derive the shared secret
   */
  OSSL_CHECK(derive_ctx = EVP_PKEY_CTX_new(ossl_ctx->ec_key, NULL));
  OSSL_CHECK(EVP_PKEY_derive_init(derive_ctx));
  OSSL_CHECK(EVP_PKEY_derive_set_peer(derive_ctx, peer_key));

  /* Query buffer size for shared secret */
  *shared_key_len = 0;
  OSSL_CHECK(EVP_PKEY_derive(derive_ctx, NULL, shared_key_len));

  if (!(*shared_key = xcalloc(1, *shared_key_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_PKEY_derive(derive_ctx, *shared_key, shared_key_len));

cleanup:
  OSSL_PARAM_free(param);
  OSSL_PARAM_BLD_free(param_bld);
  EVP_PKEY_CTX_free(peer_key_ctx);
  EVP_PKEY_free(peer_key);
  EVP_PKEY_free(mac_key);
  EVP_PKEY_CTX_free(derive_ctx);
  memzero(mac, mac_len);
  xfree(mac);
  EVP_MD_CTX_free(md_ctx);
  return ret;
}

const kex_intf_t kex_ecc_intf = {
    .alloc = ossl_kex_ecc_alloc,
    .dealloc = ossl_kex_ecc_dealloc,
    .key_gen = ossl_kex_ecc_key_gen,
    .get_peer_data = ossl_kex_ecc_get_peer_data,
    .free_peer_data = ossl_kex_ecc_free_peer_data,
    .derive_shared_key = ossl_kex_ecc_derive_shared_key,
    .supported_curves = KEX_CURVE_secp256k1 | KEX_CURVE_secp384r1 |
                        KEX_CURVE_secp521r1 | KEX_CURVE_prime239v3 |
                        KEX_CURVE_prime256v1};
