/**
 * aes_gcm_ossl.c
 *
 * AES in Galois Counter Mode (GCM) implementation using OpenSSL.
 *
 * vibhav950 on GitHub
 */

#include "aes_gcm_ossl.h"
#include "cipher.h"
#include "common/defs.h"
#include "common/memzero.h"

#include <openssl/evp.h>

#define CHECK(cond) { if (!(cond)) return ERR_BAD_ARGS; }

#define CIPHER_OPERATION_SET(c, operation) (void)((c)->oper = operation)
#define CIPHER_OPERATION_GET(c, operation) ((c)->oper == operation)

#define CIPHER_FLAG_SET(c, flag) (void)((c)->flags |= flag)
#define CIPHER_FLAG_GET(c, flag) ((c)->flags & flag)

/**
 *
 */
static error_t ossl_aes_gcm_alloc(cipher_t **c, size_t key_len, size_t tag_len,
                                  cipher_alg_t alg) {
  extern const cipher_intf_t aes_gcm_intf;
  aes_gcm_ossl_ctx *aes_gcm;
  const EVP_CIPHER *evp;

  PRINTDEBUG("key_len=%zu, tag_len=%zu", key_len, tag_len);

  if (!*c)
    return ERR_NULL_PTR;

  switch (alg) {
  case AES_GCM_128:
    CHECK(key_len == AES_GCM_128_KEY_LEN);
    evp = EVP_aes_128_gcm();
    break;
  case AES_GCM_192:
    CHECK(key_len == AES_GCM_192_KEY_LEN);
    evp = EVP_aes_192_gcm();
    break;
  case AES_GCM_256:
    CHECK(key_len == AES_GCM_256_KEY_LEN);
    evp = EVP_aes_256_gcm();
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (tag_len != AES_AUTH_TAG_LEN_LONG && tag_len != AES_AUTH_TAG_LEN_SHORT)
    return ERR_BAD_ARGS;

  *c = (cipher_t *)calloc(1, sizeof(cipher_t));
  if (!*c)
    return ERR_MEM_FAIL;

  aes_gcm = (aes_gcm_ossl_ctx *)calloc(1, sizeof(aes_gcm_ossl_ctx));
  if (!aes_gcm) {
    free(*c);
    *c = NULL;
    return ERR_MEM_FAIL;
  }

  aes_gcm->ossl_ctx = EVP_CIPHER_CTX_new();
  if (!aes_gcm->ossl_ctx) {
    free(aes_gcm);
    free(*c);
    *c = NULL;
    return ERR_INTERNAL;
  }
  aes_gcm->ossl_evp = evp;
  aes_gcm->key_len = key_len;
  aes_gcm->tag_len = tag_len;

  (*c)->intf = &aes_gcm_intf;
  (*c)->ctx = aes_gcm;
  (*c)->key_len = key_len;
  (*c)->alg = alg;
  CIPHER_FLAG_SET(*c, CIPHER_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aes_gcm_free(cipher_t *c) {
  if (!c)
    return ERR_SUCCESS;

  if (CIPHER_FLAG_GET(c, CIPHER_FLAG_ALLOC)) {
    aes_gcm_ossl_ctx *aes_gcm = (aes_gcm_ossl_ctx *)c->ctx;

    if (aes_gcm) {
      EVP_CIPHER_CTX_free(aes_gcm->ossl_ctx);
      /* Prevent state leaks */
      memzero(aes_gcm, sizeof(aes_gcm_ossl_ctx));
      free(aes_gcm);
    }
  }
  memzero(c, sizeof(cipher_t));
  free(c);
  c = NULL;

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aes_gcm_init(cipher_t *c, const uint8_t *key,
                                 size_t key_len, cipher_oper_t oper) {
  aes_gcm_ossl_ctx *ctx;
  cipher_alg_t alg;

  PRINTDEBUG("key_len=%zu", key_len);

  if (!c || !key)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  ctx = c->ctx;
  alg = c->alg;

  switch (key_len) {
  case AES_GCM_128_KEY_LEN:
    CHECK(alg == AES_GCM_128);
    break;
  case AES_GCM_192_KEY_LEN:
    CHECK(alg == AES_GCM_192);
    break;
  case AES_GCM_256_KEY_LEN:
    CHECK(alg == AES_GCM_256);
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (oper != CIPHER_OPER_ENCRYPT && oper != CIPHER_OPER_DECRYPT)
    return ERR_BAD_ARGS;

  EVP_CIPHER_CTX_reset(ctx->ossl_ctx);

  if (!EVP_CipherInit_ex(ctx->ossl_ctx, ctx->ossl_evp, NULL, key, NULL, 0))
    return ERR_INTERNAL;

  if (!EVP_CIPHER_CTX_ctrl(ctx->ossl_ctx, EVP_CTRL_GCM_SET_IVLEN,
                           AES_GCM_IV_LEN, NULL)) {
    return ERR_INTERNAL;
  }

  CIPHER_FLAG_SET(c, CIPHER_FLAG_INIT);
  CIPHER_FLAG_SET(c, CIPHER_FLAG_AEAD);
  CIPHER_OPERATION_SET(ctx, oper);

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aes_gcm_set_iv(cipher_t *c, const uint8_t *iv,
                                   size_t iv_len) {
  aes_gcm_ossl_ctx *ctx;

  PRINTDEBUG("iv_len=%zu", iv_len);

  if (!c || !iv)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;

  if (!CIPHER_OPERATION_GET(ctx, CIPHER_OPER_ENCRYPT) &&
      !CIPHER_OPERATION_GET(ctx, CIPHER_OPER_DECRYPT)) {
    return ERR_BAD_ARGS;
  }

  if (iv_len != AES_GCM_IV_LEN)
    return ERR_BAD_ARGS;

  if (!EVP_CipherInit_ex(ctx->ossl_ctx, NULL, NULL, NULL, iv,
                         CIPHER_OPERATION_GET(ctx, CIPHER_OPER_ENCRYPT))) {
    return ERR_INTERNAL;
  }

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aes_gcm_set_aad(cipher_t *c, const uint8_t *aad,
                                    size_t aad_len) {
  int rv;
  aes_gcm_ossl_ctx *ctx;

  PRINTDEBUG("aad_len=%zu", aad_len);

  if (!c || !aad)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;

  if (!CIPHER_OPERATION_GET(ctx, CIPHER_OPER_ENCRYPT))
    return ERR_BAD_ARGS;

  rv = EVP_Cipher(ctx->ossl_ctx, NULL, aad, aad_len);
  if (rv < 0 || rv != aad_len)
    return ERR_INTERNAL;

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aes_gcm_encrypt(cipher_t *c, const uint8_t *in,
                                    size_t in_len, uint8_t *out,
                                    size_t *out_len) {
  aes_gcm_ossl_ctx *ctx;

  PRINTDEBUG("in_len=%zu, *out_len=%zu", in_len, *out_len);

  if (!c || !in || !out || !out_len)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;

  if (!CIPHER_OPERATION_GET(ctx, CIPHER_OPER_ENCRYPT))
    return ERR_BAD_ARGS;

  *out_len = in_len + ctx->tag_len;
  if (*out_len < in_len + ctx->tag_len)
    return ERR_BUFFER_TOO_SMALL;

  /* Encrypt the data */
  EVP_Cipher(ctx->ossl_ctx, out, in, in_len);

  /* Calculate the tag */
  EVP_Cipher(ctx->ossl_ctx, NULL, NULL, 0);

  /* Extract the tag */
  if (!EVP_CIPHER_CTX_ctrl(ctx->ossl_ctx, EVP_CTRL_GCM_GET_TAG, ctx->tag_len,
                           out + in_len)) {
    return ERR_INTERNAL;
  }

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aes_gcm_decrypt(cipher_t *c, const uint8_t *in,
                                    size_t in_len, uint8_t *out,
                                    size_t *out_len) {
  aes_gcm_ossl_ctx *ctx;

  PRINTDEBUG("in_len=%zu, *out_len=%zu", in_len, *out_len);

  if (!c || !in || !out || !out_len)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;

  if (!CIPHER_OPERATION_GET(ctx, CIPHER_OPER_DECRYPT))
    return ERR_BAD_ARGS;

  if (in_len < ctx->tag_len)
    return ERR_BAD_ARGS;

  if (in_len - ctx->tag_len > *out_len)
    return ERR_BUFFER_TOO_SMALL;

  /*
   * Set the tag and decrypt the payload
   *
   * Explicitly cast away the const of in
   */
  if (!EVP_CIPHER_CTX_ctrl(ctx->ossl_ctx, EVP_CTRL_GCM_SET_TAG, ctx->tag_len,
                           (void *)(ptrdiff_t)(in + (in_len - ctx->tag_len)))) {
    return ERR_AUTH_FAIL;
  }
  EVP_Cipher(ctx->ossl_ctx, out, in, in_len - ctx->tag_len);

  /* Check the tag */
  if (!EVP_Cipher(ctx->ossl_ctx, NULL, NULL, 0))
    return ERR_AUTH_FAIL;

  /* Reduce the buffer size by the tag length to get the
   * length of the original payload */
  *out_len = in_len - ctx->tag_len;

  return ERR_SUCCESS;
}

const cipher_intf_t aes_gcm_intf = {
    .alloc = ossl_aes_gcm_alloc,
    .dealloc = ossl_aes_gcm_free,
    .init = ossl_aes_gcm_init,
    .set_iv = ossl_aes_gcm_set_iv,
    .set_aad = ossl_aes_gcm_set_aad,
    .encrypt = ossl_aes_gcm_encrypt,
    .decrypt = ossl_aes_gcm_decrypt,
    .supported_algs = AES_GCM_ALL /* AES_GCM_128, AES_GCM_192, AES_GCM_256 */,
};
