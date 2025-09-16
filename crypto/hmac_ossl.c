/**
 * hmac_ossl.c
 *
 * OpenSSL implementation of the keyed-hash Message Authentication Code (HMAC).
 *
 * vibhav950 on GitHub
 */

#include "common/defines.h"
#include "common/log.h"
#include "hmac.h"
#include "hmac_defs.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct hmac_ossl_ctx_st {
  const EVP_MD *md;
  EVP_MD_CTX *md_ctx;
} hmac_ossl_ctx;

// clang-format off
#define CHECK(cond) { if (!(cond)) return ERR_BAD_ARGS; }

#define HMAC_FLAG_SET(h, flag) (void)((h)->flags |= flag)
#define HMAC_FLAG_GET(h, flag) ((h)->flags & flag)
// clang-format on

/**
 *
 */
static err_t ossl_hmac_alloc(hmac_t **h, size_t key_len, size_t out_len, hmac_alg_t alg) {
  extern const hmac_intf_t hmac_intf;
  hmac_ossl_ctx *hmac;
  const EVP_MD *md;

  log_debug(NULL, "key_len=%zu, out_len=%zu alg=%s", key_len, out_len,
            hmac_alg_to_string(alg));

  if (key_len != out_len)
    return ERR_BAD_ARGS;

  switch (alg) {
  case HMAC_SHA256:
    CHECK(out_len == HMAC_SHA256_MAX_OUT_LEN);
    md = EVP_sha256();
    break;
  case HMAC_SHA384:
    CHECK(out_len == HMAC_SHA384_MAX_OUT_LEN);
    md = EVP_sha384();
    break;
  case HMAC_SHA512:
    CHECK(out_len == HMAC_SHA512_MAX_OUT_LEN);
    md = EVP_sha512();
    break;
  case HMAC_SHA3_256:
    CHECK(out_len == HMAC_SHA3_256_MAX_OUT_LEN);
    md = EVP_sha3_256();
    break;
  case HMAC_SHA3_384:
    CHECK(out_len == HMAC_SHA3_384_MAX_OUT_LEN);
    md = EVP_sha3_384();
    break;
  case HMAC_SHA3_512:
    CHECK(out_len == HMAC_SHA3_512_MAX_OUT_LEN);
    md = EVP_sha3_512();
    break;
  default:
    return ERR_BAD_ARGS;
  }

  *h = (hmac_t *)zt_calloc(1, sizeof(hmac_t));
  if (!*h)
    return ERR_MEM_FAIL;

  hmac = (hmac_ossl_ctx *)zt_calloc(1, sizeof(hmac_ossl_ctx));
  if (!hmac) {
    zt_free(*h);
    *h = NULL;
    return ERR_MEM_FAIL;
  }

  hmac->md_ctx = EVP_MD_CTX_new();
  if (!hmac->md_ctx) {
    zt_free(hmac);
    zt_free(*h);
    *h = NULL;
    return ERR_INTERNAL;
  }
  hmac->md = md;

  (*h)->intf = &hmac_intf;
  (*h)->ctx = hmac;
  (*h)->key_len = key_len;
  (*h)->alg = alg;
  HMAC_FLAG_SET(*h, HMAC_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 *
 */
static void ossl_hmac_dealloc(hmac_t *h) {
  log_debug(NULL, "-");

  if (HMAC_FLAG_GET(h, HMAC_FLAG_ALLOC)) {
    hmac_ossl_ctx *hmac = h->ctx;

    if (hmac) {
      EVP_MD_CTX_free(hmac->md_ctx);
      memzero(hmac, sizeof(hmac_ossl_ctx));
      zt_free(hmac);
    }
  }
  memzero(h, sizeof(hmac_t));
  zt_free(h);
}

/**
 *
 */
static err_t ossl_hmac_init(hmac_t *h, const uint8_t *key, size_t key_len) {
  hmac_ossl_ctx *ctx;
  hmac_alg_t alg;
  EVP_PKEY *mac_key;

  log_debug(NULL, "key_len=%zu", key_len);

  if (!key)
    return ERR_NULL_PTR;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  ctx = h->ctx;
  alg = h->alg;

  switch (key_len) {
  case HMAC_SHA256_KEY_LEN:
    // case HMAC_SHA3_256_KEY_LEN:
    CHECK((alg == HMAC_SHA256) || (alg == HMAC_SHA3_256));
    break;
  case HMAC_SHA384_KEY_LEN:
    // case HMAC_SHA3_348_KEY_LEN:
    CHECK((alg == HMAC_SHA384) || (alg == HMAC_SHA3_384));
    break;
  case HMAC_SHA512_KEY_LEN:
    // case HMAC_SHA3_512_KEY_LEN:
    CHECK((alg == HMAC_SHA512) || (alg == HMAC_SHA3_512));
    break;
  default:
    return ERR_BAD_ARGS;
  }

  mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
  if (!mac_key)
    return ERR_INTERNAL;

  EVP_MD_CTX_reset(ctx->md_ctx);

  if (EVP_DigestSignInit(ctx->md_ctx, NULL, ctx->md, NULL, mac_key) != 1) {
    EVP_PKEY_free(mac_key);
    return ERR_INTERNAL;
  }
  EVP_PKEY_free(mac_key);

  HMAC_FLAG_SET(h, HMAC_FLAG_INIT);

  return ERR_SUCCESS;
}

/**
 *
 */
static err_t ossl_hmac_update(hmac_t *h, const uint8_t *msg, size_t msg_len) {
  hmac_ossl_ctx *ctx;

  log_debug(NULL, "msg_len=%zu", msg_len);

  if (msg_len && !msg)
    return ERR_NULL_PTR;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = h->ctx;

  if (EVP_DigestSignUpdate(ctx->md_ctx, msg, msg_len) != 1)
    return ERR_INTERNAL;

  return ERR_SUCCESS;
}

static err_t ossl_hmac_compute(hmac_t *h, const uint8_t *msg, size_t msg_len,
                               uint8_t *digest, size_t digest_len) {
  hmac_ossl_ctx *ctx;
  uint8_t md_value[EVP_MAX_MD_SIZE];
  size_t len;

  log_debug(NULL, "msg_len=%zu, digest_len=%zu", msg_len, digest_len);

  if (!digest)
    return ERR_NULL_PTR;

  if (msg_len && !msg)
    return ERR_NULL_PTR;

  if (digest_len > h->key_len)
    return ERR_BAD_ARGS;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = h->ctx;

  /* Process the message */
  if (msg_len) {
    if (EVP_DigestSignUpdate(ctx->md_ctx, msg, msg_len) != 1)
      return ERR_INTERNAL;
  }

  /* Compute the digest */
  len = sizeof(md_value);
  if (EVP_DigestSignFinal(ctx->md_ctx, md_value, &len) != 1)
    return ERR_INTERNAL;

  if (len < digest_len)
    return ERR_BAD_ARGS;

  /* Copy the digest to the output buffer */
  for (size_t i = 0; i < digest_len; ++i)
    digest[i] = md_value[i];

  return ERR_SUCCESS;
}

const hmac_intf_t hmac_intf = {
    .alloc = ossl_hmac_alloc,
    .dealloc = ossl_hmac_dealloc,
    .init = ossl_hmac_init,
    .update = ossl_hmac_update,
    .compute = ossl_hmac_compute,
    .supported_algs = HMAC_ALG_ALL,
};
