/**
 * hmac_ossl.c
 *
 * OpenSSL implementation of the keyed-hash Message Authentication Code (HMAC).
 *
 * vibhav950 on GitHub
 */

#include "hmac_ossl.h"
#include "hmac.h"

#include <openssl/hmac.h>

#define CHECK(cond) { if (!(cond)) return ERR_BAD_ARGS; }

#define HMAC_FLAG_SET(h, flag) (void)((h)->flags |= flag)
#define HMAC_FLAG_GET(h, flag) ((h)->flags & flag)

static const char *hmac_alg_to_string(hmac_alg_t alg) {
  switch (alg) {
  case HMAC_SHA256:
    return "HMAC_SHA256";
  case HMAC_SHA384:
    return "HMAC_SHA384";
  case HMAC_SHA512:
    return "HMAC_SHA512";
  case HMAC_SHA3_256:
    return "HMAC_SHA3_256";
  case HMAC_SHA3_384:
    return "HMAC_SHA3_384";
  case HMAC_SHA3_512:
    return "HMAC_SHA3_512";
  default:
    return "Unknown type";
  }
}

/**
 *
 */
static error_t ossl_hmac_alloc(hmac_t **h, size_t key_len, size_t out_len,
                               hmac_alg_t alg) {
  extern const hmac_intf_t hmac_ossl_intf;
  hmac_ossl_ctx *hmac;
  EVP_MD *md;

  PRINTDEBUG("key_len=%zu, out_len=%zu alg=%s", key_len, out_len, hmac_alg_to_string(alg));

  if (!*h)
    return ERR_NULL_PTR;

  if (key_len != out_len)
    return ERR_BAD_ARGS;

  switch (alg) {
  case HMAC_SHA256:
    CHECK(out_len == HMAC_SHA256_OUT_LEN);
    md = EVP_sha256();
    break;
  case HMAC_SHA384:
    CHECK(out_len == HMAC_SHA384_OUT_LEN);
    md = EVP_sha384();
    break;
  case HMAC_SHA512:
    CHECK(out_len == HMAC_SHA512_OUT_LEN);
    md = EVP_sha512();
    break;
  case HMAC_SHA3_256:
    CHECK(out_len == HMAC_SHA3_256_OUT_LEN);
    md = EVP_sha3_256();
    break;
  case HMAC_SHA3_384:
    CHECK(out_len == HMAC_SHA3_384_OUT_LEN);
    md = EVP_sha3_384();
    break;
  case HMAC_SHA3_512:
    CHECK(out_len == HMAC_SHA3_512_OUT_LEN);
    md = EVP_sha3_512();
    break;
  default:
    return ERR_BAD_ARGS;
  }

  *h = (hmac_t *)calloc(1, sizeof(hmac_t));
  if (!*h)
    return ERR_MEM_FAIL;

  hmac = (hmac_ossl_ctx *)calloc(1, sizeof(hmac_ossl_ctx));
  if (!hmac) {
    free(*h);
    *h = NULL;
    return ERR_MEM_FAIL;
  }

  hmac->ossl_ctx = HMAC_CTX_new();
  if (!hmac->ossl_ctx) {
    free(hmac);
    free(*h);
    *h = NULL;
    return ERR_INTERNAL;
  }
  hmac->ossl_md = md;
  hmac->key_len = key_len;
  hmac->alg = alg;

  (*h)->intf = &hmac_ossl_intf;
  (*h)->ctx = hmac;
  (*h)->key_len = key_len;
  (*h)->alg = alg;
  HMAC_FLAG_SET(*h, HMAC_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_hmac_free(hmac_t *h) {
  if (!h)
    return ERR_SUCCESS;

  if (HMAC_FLAG_GET(h, HMAC_FLAG_ALLOC)) {
    hmac_ossl_ctx *hmac = h->ctx;

    if (hmac) {
      HMAC_CTX_free(hmac->ossl_ctx);
      EVP_MD_free(hmac->ossl_md);
      /* Prevent state leaks */
      memzero(hmac, sizeof(hmac_ossl_ctx));
      free(hmac);
    }
  }
  memzero(h, sizeof(hmac_t));
  free(h);
  h = NULL;

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_hmac_init(hmac_t *h, const uint8_t *key, size_t key_len) {
  hmac_ossl_ctx *ctx;
  hmac_alg_t alg;

  PRINTDEBUG("key_len=%zu", key_len);

  if (!h || !key)
    return ERR_NULL_PTR;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  ctx = h->ctx;
  alg = h->alg;

  switch (key_len) {
  case HMAC_SHA256_OUT_LEN:
    // case HMAC_SHA3_256_OUT_LEN:
    CHECK((alg == HMAC_SHA256) || (alg == HMAC_SHA3_256));
    break;
  case HMAC_SHA384_OUT_LEN:
    // case HMAC_SHA3_384_OUT_LEN:
    CHECK((alg == HMAC_SHA384) || (alg == HMAC_SHA3_384));
    break;
  case HMAC_SHA512_OUT_LEN:
    // case HMAC_SHA3_512_OUT_LEN:
    CHECK((alg == HMAC_SHA512) || (alg == HMAC_SHA3_512));
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (!HMAC_Init_ex(ctx->ossl_ctx, key, key_len, ctx->ossl_md, NULL))
    return ERR_INTERNAL;

  HMAC_FLAG_SET(h, HMAC_FLAG_INIT);

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_hmac_update(hmac_t *h, const uint8_t *data,
                                size_t data_len) {
  hmac_ossl_ctx *ctx;

  PRINTDEBUG("data_len=%zu", data_len);

  if (!h)
    return ERR_NULL_PTR;

  if (data_len && !data)
    return ERR_NULL_PTR;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = h->ctx;

  if (!HMAC_Update(ctx->ossl_ctx, data, data_len))
    return ERR_INTERNAL;

  return ERR_SUCCESS;
}

static error_t ossl_hmac_compute(hmac_t *h, const uint8_t *msg, size_t msg_len,
                                 uint8_t *digest, size_t digest_len) {
  hmac_ossl_ctx *ctx;
  uint8_t md_value[EVP_MAX_MD_SIZE];
  unsigned int len;

  PRINTDEBUG("msg_len=%zu, tag_len=%zu", msg_len, digest_len);

  if (!h || !digest)
    return ERR_NULL_PTR;

  if (msg_len && !msg)
    return ERR_NULL_PTR;

  if (!HMAC_FLAG_GET(h, HMAC_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = h->ctx;

  /* Process the meessage */
  if (msg_len) {
    if (!HMAC_Update(ctx->ossl_ctx, msg, msg_len))
      return ERR_INTERNAL;
  }

  /* Compute the digest */
  if (!HMAC_Final(ctx->ossl_ctx, md_value, &len))
    return ERR_INTERNAL;

  if (len < digest_len)
    return ERR_BAD_ARGS;

  /* Copy the digest to the output buffer */
  for (size_t i = 0; i < digest_len; ++i)
    digest[i] = md_value[i];

  return ERR_SUCCESS;
}

const hmac_intf_t hmac_ossl_intf = {
    .alloc = ossl_hmac_alloc,
    .dealloc = ossl_hmac_free,
    .init = ossl_hmac_init,
    .update = ossl_hmac_update,
    .compute = ossl_hmac_compute,
    .supported_algs = HMAC_ALG_ALL,
};
