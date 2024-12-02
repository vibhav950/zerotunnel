#include "kex_ecc_ossl.h"
#include "common/defs.h"
#include "common/memzero.h"
#include "kex.h"

#include <openssl/core_names.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

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

  if (!*kex)
    return ERR_NULL_PTR;

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

  if (!(*kex = (kex_t *)calloc(1, sizeof(kex_t))))
    return ERR_MEM_FAIL;

  if (!(ossl_ctx = (kex_ossl_ctx *)calloc(1, sizeof(kex_ossl_ctx)))) {
    free(*kex);
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
error_t ossl_kex_ecc_free(kex_t *kex) {
  if (!kex)
    return ERR_SUCCESS;

  if (KEX_FLAG_GET(kex, KEX_FLAG_ALLOC)) {
    kex_ossl_ctx *ctx = (kex_ossl_ctx *)kex->ctx;

    if (ctx) {
      EVP_PKEY_free(ctx->ec_key);
      EVP_PKEY_free(ctx->ec_params);
      /* Prevent state leaks */
      memzero(ctx, sizeof(kex_ossl_ctx));
      free(ctx);
    }
  }
  memzero(kex, sizeof(kex_t));
  free(kex);
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
  ;

  PRINTDEBUG("");

  if (!kex)
    return ERR_NULL_PTR;

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
error_t ossl_kex_ecc_get_peer_data(kex_t *kex, kex_peer_share_t *peer_data) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  EVP_PKEY *mac_key = NULL;
  unsigned char *pubkey = NULL, *groupname = NULL, *mac = NULL;
  size_t pubkey_len = 0, groupname_len = 0, mac_len = 0;
  const EVP_MD *md = EVP_sha3_256();
  EVP_MD_CTX *md_ctx = NULL;

  PRINTDEBUG("");

  if (!kex || !peer_data)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;

  // /* Query the buffer size */
  // pubkey_size = 0;
  // OSSL_CHECK(EVP_PKEY_get_octet_string_param(
  //     ossl_ctx->ec_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubkey_size));

  // /* Allocate the buffer for the public key */
  // if (!(pubkey = calloc(1, pubkey_size))) {
  //   ret = ERR_MEM_FAIL;
  //   goto cleanup;
  // }

  // /* Get the public key */
  // OSSL_CHECK(EVP_PKEY_get_octet_string_param(ossl_ctx->ec_key,
  //                                            OSSL_PKEY_PARAM_PUB_KEY, pubkey,
  //                                            pubkey_size, &pubkey_size));

  // groupname_size = 0;
  // OSSL_CHECK(EVP_PKEY_get_octet_string_param(
  //     ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0,
  //     &groupname_size));

  // if (!(groupname = calloc(1, groupname_size))) {
  //   ret = ERR_MEM_FAIL;
  //   goto cleanup;
  // }

  // OSSL_CHECK(EVP_PKEY_get_octet_string_param(
  //     ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, groupname,
  //     groupname_size, &groupname_size));

  // ===================================================================

  /**
   * Get the public key
   */
  OSSL_CHECK(EVP_PKEY_get_raw_public_key(ossl_ctx->ec_key, NULL, &pubkey_len));

  if (!(pubkey = calloc(1, pubkey_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(
      EVP_PKEY_get_raw_public_key(ossl_ctx->ec_key, pubkey, &pubkey_len));

  /**
   * Get the group name
   */
  OSSL_CHECK(EVP_PKEY_get_octet_string_param(
      ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &groupname_len));

  if (!(groupname = calloc(1, groupname_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_PKEY_get_octet_string_param(
      ossl_ctx->ec_key, OSSL_PKEY_PARAM_GROUP_NAME, groupname, groupname_len,
      &groupname_len));

  // ===================================================================

  /**
   * Compute a HMAC over the public key
   */
  OSSL_CHECK(md_ctx = EVP_MD_CTX_new());
  OSSL_CHECK(mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, kex->authkey,
                                            strlen(kex->authkey)));
  OSSL_CHECK(EVP_DigestSignInit(md_ctx, NULL, md, NULL, mac_key));
  OSSL_CHECK(EVP_DigestSignUpdate(md_ctx, pubkey, pubkey_len));
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, NULL, &mac_len));

  if (!(mac = calloc(1, mac_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, mac, &mac_len));

  /**
   *  Sign the HMAC with the private key
   */
  OSSL_CHECK(EVP_MD_CTX_reset(md_ctx));
  OSSL_CHECK(EVP_DigestSignInit(md_ctx, NULL, md, NULL, ossl_ctx->ec_key));
  OSSL_CHECK(EVP_DigestSignUpdate(md_ctx, mac, mac_len));
  peer_data->sig_len = 0;
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, NULL, &peer_data->sig_len));

  if (!(peer_data->sig = calloc(1, peer_data->sig_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }
  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, peer_data->sig, &peer_data->sig_len));

  peer_data->ec_pub = pubkey;
  peer_data->ec_pub_len = pubkey_len;
  peer_data->ec_group = groupname;
  peer_data->ec_group_len = groupname_len;
  peer_data->mac = mac;
  peer_data->mac_len = mac_len;

cleanup:
  EVP_PKEY_free(mac_key);
  EVP_MD_CTX_free(md_ctx);
  return ret;
}

/**
 *
 */
error_t ossl_kex_ecc_derive_shared_key(kex_t *kex, kex_peer_share_t *peer_data,
                                       unsigned char **shared_key,
                                       size_t *shared_key_len) {
  error_t ret = ERR_SUCCESS;
  kex_ossl_ctx *ossl_ctx;
  EVP_PKEY *peer_key = NULL, *mac_key = NULL;
  EVP_PKEY_CTX *derive_ctx = NULL;
  unsigned char *mac = NULL;
  size_t mac_len = 0;
  const EVP_MD *md = EVP_sha3_256();
  EVP_MD_CTX *md_ctx = NULL;

  PRINTDEBUG("");

  if (!kex || !peer_data || !shared_key || !shared_key_len)
    return ERR_NULL_PTR;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEX_FLAG_GET(kex, KEX_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  ossl_ctx = kex->ctx;

  if (!(peer_key = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_EC, NULL, peer_data->ec_pub, peer_data->ec_pub_len))) {
    ret = ERR_INTERNAL;
    goto cleanup;
  }

  /**
   * Compute the HMAC over the public key and compare the HMAC with
   * the value received from the peer
   */
  OSSL_CHECK(md_ctx = EVP_MD_CTX_new());
  OSSL_CHECK(mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, kex->authkey,
                                            strlen(kex->authkey)));
  OSSL_CHECK(EVP_DigestSignInit(md_ctx, NULL, md, NULL, mac_key));
  OSSL_CHECK(
      EVP_DigestSignUpdate(md_ctx, peer_data->ec_pub, peer_data->ec_pub_len));

  OSSL_CHECK(EVP_DigestSignFinal(md_ctx, NULL, &mac_len));

  if (!(mac = calloc(1, mac_len))) {
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

  OSSL_CHECK(EVP_MD_CTX_reset(md_ctx));
  OSSL_CHECK(EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, ossl_ctx->ec_key));
  OSSL_CHECK(
      EVP_DigestVerifyUpdate(md_ctx, peer_data->mac, peer_data->mac_len));

  /* Verify the signature */
  if (!EVP_DigestVerifyFinal(md_ctx, peer_data->sig, peer_data->sig_len)) {
    ret = ERR_AUTH_FAIL;
    goto cleanup;
  }

  /**
   * Now that the public key is authenticated, derive the shared secret
   */
  OSSL_CHECK(derive_ctx = EVP_PKEY_CTX_new(ossl_ctx->ec_key, NULL));
  OSSL_CHECK(EVP_PKEY_derive_init(derive_ctx));
  OSSL_CHECK(EVP_PKEY_CTX_set_group_name(derive_ctx, peer_data->ec_group));
  OSSL_CHECK(EVP_PKEY_derive_set_peer(derive_ctx, peer_key));

  /* Query buffer size for shared secret */
  *shared_key_len = 0;
  OSSL_CHECK(EVP_PKEY_derive(derive_ctx, NULL, shared_key_len));

  if (!(shared_key = calloc(1, *shared_key_len))) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
  }

  OSSL_CHECK(EVP_PKEY_derive(derive_ctx, *shared_key, shared_key_len));

cleanup:
  EVP_PKEY_free(peer_key);
  EVP_PKEY_free(mac_key);
  EVP_PKEY_CTX_free(derive_ctx);
  memzero(mac, mac_len);
  free(mac);
  EVP_MD_CTX_free(md_ctx);
  return ret;
}

const kex_intf_t kex_ecc_intf = {
    .alloc = ossl_kex_ecc_alloc,
    .dealloc = ossl_kex_ecc_free,
    .key_gen = ossl_kex_ecc_key_gen,
    .get_peer_data = ossl_kex_ecc_get_peer_data,
    .derive_shared_key = ossl_kex_ecc_derive_shared_key,
    .supported_curves = KEX_CURVE_secp256k1 | KEX_CURVE_secp384r1 |
                        KEX_CURVE_secp521r1 | KEX_CURVE_prime239v3 |
                        KEX_CURVE_prime256v1};
