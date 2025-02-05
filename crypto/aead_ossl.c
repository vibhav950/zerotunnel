/**
 * aead_ossl.h
 *
 * OpenSSL implementation of AEAD ciphers
 *
 * vibhav950 on GitHub
 */

#include "aead.h"
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
static error_t ossl_aead_alloc(cipher_t **c, size_t key_len, size_t tag_len,
                               cipher_alg_t alg) {
  extern const cipher_intf_t aead_intf;
  aead_ossl_ctx *aead_ctx;
  const EVP_CIPHER *evp;

  PRINTDEBUG("key_len=%zu, tag_len=%zu", key_len, tag_len);

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
  case CHACHA20_POLY1305:
    CHECK(key_len == CHACHA20_POLY1305_KEY_LEN);
    evp = EVP_chacha20_poly1305();
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (alg == CHACHA20_POLY1305) {
    if ((tag_len != CHACHA20_POLY1305_AUTH_TAG_LEN_LONG) &&
        (tag_len != CHACHA20_POLY1305_AUTH_TAG_LEN_SHORT)) {
      return ERR_BAD_ARGS;
    }
  } else if ((tag_len != AES_GCM_AUTH_TAG_LEN_LONG) &&
             (tag_len != AES_GCM_AUTH_TAG_LEN_SHORT)) {
    return ERR_BAD_ARGS;
  }

  *c = (cipher_t *)xcalloc(1, sizeof(cipher_t));
  if (!*c)
    return ERR_MEM_FAIL;

  aead_ctx = (aead_ossl_ctx *)xcalloc(1, sizeof(aead_ossl_ctx));
  if (!aead_ctx) {
    xfree(*c);
    *c = NULL;
    return ERR_MEM_FAIL;
  }

  aead_ctx->ossl_ctx = EVP_CIPHER_CTX_new();
  if (!aead_ctx->ossl_ctx) {
    xfree(aead_ctx);
    xfree(*c);
    *c = NULL;
    return ERR_INTERNAL;
  }
  aead_ctx->ossl_evp = evp;

  (*c)->intf = &aead_intf;
  (*c)->ctx = aead_ctx;
  (*c)->key_len = key_len;
  (*c)->tag_len = tag_len;
  (*c)->alg = alg;
  CIPHER_FLAG_SET(*c, CIPHER_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 *
 */
static void ossl_aead_dealloc(cipher_t *c) {
  PRINTDEBUG("");

  if (CIPHER_FLAG_GET(c, CIPHER_FLAG_ALLOC)) {
    aead_ossl_ctx *aead = (aead_ossl_ctx *)c->ctx;

    if (aead) {
      EVP_CIPHER_CTX_free(aead->ossl_ctx);
      /* Prevent state leaks */
      memzero(aead, sizeof(aead_ossl_ctx));
      xfree(aead);
    }
  }
  memzero(c, sizeof(cipher_t));
  xfree(c);
  c = NULL;
}

/**
 *
 */
static error_t ossl_aead_init(cipher_t *c, const uint8_t *key, size_t key_len,
                              cipher_operation_t oper) {
  aead_ossl_ctx *ctx;
  cipher_alg_t alg;

  PRINTDEBUG("key_len=%zu", key_len);

  if (!key)
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
    // case CHACHA20_POLY1305_KEY_LEN:
    CHECK((alg == AES_GCM_256) || (alg == CHACHA20_POLY1305));
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (oper != CIPHER_OPERATION_ENCRYPT && oper != CIPHER_OPERATION_DECRYPT)
    return ERR_BAD_ARGS;

  EVP_CIPHER_CTX_reset(ctx->ossl_ctx);

  if (oper == CIPHER_OPERATION_ENCRYPT) {
    if (EVP_EncryptInit_ex(ctx->ossl_ctx, ctx->ossl_evp, NULL, key, NULL) != 1)
      return ERR_INTERNAL;
  } else {
    if (EVP_DecryptInit_ex(ctx->ossl_ctx, ctx->ossl_evp, NULL, key, NULL) != 1)
      return ERR_INTERNAL;
  }

  /**
   * EVP_chacha20_poly1305() always expects a fixed IV length of 128 bits
   * so we directly pass the IV of required length in ossl_aead_set_iv()
   */
  if (alg != CHACHA20_POLY1305) {
    if (EVP_CIPHER_CTX_ctrl(ctx->ossl_ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_GCM_IV_LEN, NULL) != 1) {
      return ERR_INTERNAL;
    }
  }

  CIPHER_FLAG_SET(c, CIPHER_FLAG_INIT);
  CIPHER_OPERATION_SET(c, oper);

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aead_set_iv(cipher_t *c, const uint8_t *iv, size_t iv_len) {
  aead_ossl_ctx *ctx;
  cipher_alg_t alg;

  PRINTDEBUG("iv_len=%zu", iv_len);

  if (!iv)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;
  alg = c->alg;

  if (!CIPHER_OPERATION_GET(c, CIPHER_OPERATION_ENCRYPT) &&
      !CIPHER_OPERATION_GET(c, CIPHER_OPERATION_DECRYPT)) {
    return ERR_BAD_ARGS;
  }

  if ((alg == CHACHA20_POLY1305) && (iv_len != CHACHA20_POLY1305_IV_LEN))
    return ERR_BAD_ARGS;
  else if (iv_len != AES_GCM_IV_LEN)
    return ERR_BAD_ARGS;

  if (CIPHER_OPERATION_GET(c, CIPHER_OPERATION_ENCRYPT)) {
    if (EVP_EncryptInit_ex(ctx->ossl_ctx, NULL, NULL, NULL, iv) != 1)
      return ERR_INTERNAL;
  } else {
    if (EVP_DecryptInit_ex(ctx->ossl_ctx, NULL, NULL, NULL, iv) != 1)
      return ERR_INTERNAL;
  }

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aead_set_aad(cipher_t *c, const uint8_t *aad,
                                 size_t aad_len) {
  int len;
  aead_ossl_ctx *ctx;

  PRINTDEBUG("aad_len=%zu", aad_len);

  if (aad_len && !aad)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  if (CIPHER_FLAG_GET(c, CIPHER_FLAG_AAD))
    return ERR_INVALID;

  ctx = c->ctx;

  if (aad_len) {
    if (CIPHER_OPERATION_GET(c, CIPHER_OPERATION_ENCRYPT)) {
      if (EVP_EncryptUpdate(ctx->ossl_ctx, NULL, &len, aad, aad_len) != 1)
        return ERR_INTERNAL;
    } else {
      if (EVP_DecryptUpdate(ctx->ossl_ctx, NULL, &len, aad, aad_len) != 1)
        return ERR_INTERNAL;
    }

    if (len != (int)aad_len)
      return ERR_INTERNAL;

    CIPHER_FLAG_SET(c, CIPHER_FLAG_AAD);
  }

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aead_encrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len) {
  int len;
  aead_ossl_ctx *ctx;

  PRINTDEBUG("in_len=%zu", in_len);

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  if (!out_len)
    return ERR_NULL_PTR;

  /* Allow querying the buffer size */
  if (*out_len < in_len + c->tag_len) {
    *out_len = in_len + c->tag_len;
    return ERR_BUFFER_TOO_SMALL;
  }

  if (!in || !out)
    return ERR_NULL_PTR;

  ctx = c->ctx;

  if (!CIPHER_OPERATION_GET(c, CIPHER_OPERATION_ENCRYPT))
    return ERR_BAD_ARGS;

  /* Encrypt the data */
  if (EVP_EncryptUpdate(ctx->ossl_ctx, out, &len, in, in_len) != 1)
    return ERR_INTERNAL;
  *out_len = len;

  /* Calculate the tag */
  if (EVP_EncryptFinal_ex(ctx->ossl_ctx, out + len, &len) != 1)
    return ERR_INTERNAL;
  *out_len += len;

  /* Extract the tag */
  if (EVP_CIPHER_CTX_ctrl(ctx->ossl_ctx, EVP_CTRL_AEAD_GET_TAG, c->tag_len,
                          out + *out_len) != 1) {
    return ERR_INTERNAL;
  }
  *out_len += c->tag_len;

  return ERR_SUCCESS;
}

/**
 *
 */
static error_t ossl_aead_decrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len) {
  int len;
  aead_ossl_ctx *ctx;

  PRINTDEBUG("in_len=%zu", in_len);

  if (!in || !out || !out_len)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;

  if (!CIPHER_OPERATION_GET(c, CIPHER_OPERATION_DECRYPT))
    return ERR_BAD_ARGS;

  if (in_len < c->tag_len)
    return ERR_BAD_ARGS;

  if (*out_len < in_len - c->tag_len) {
    *out_len = in_len - c->tag_len;
    return ERR_BUFFER_TOO_SMALL;
  }

  /*
   * Set the tag and decrypt the payload
   *
   * Explicitly cast away the const of in
   */
  if (EVP_CIPHER_CTX_ctrl(ctx->ossl_ctx, EVP_CTRL_AEAD_SET_TAG, c->tag_len,
                          (void *)(ptrdiff_t)(in + (in_len - c->tag_len))) !=
      1) {
    return ERR_INTERNAL;
  }

  if (EVP_DecryptUpdate(ctx->ossl_ctx, out, &len, in, in_len - c->tag_len) != 1)
    return ERR_INTERNAL;
  *out_len = len;

  /* Check the tag */
  if (EVP_DecryptFinal_ex(ctx->ossl_ctx, out + *out_len, &len) != 1)
    return ERR_AUTH_FAIL;
  *out_len += len;

  return ERR_SUCCESS;
}

const cipher_intf_t aead_intf = {
    .alloc = ossl_aead_alloc,
    .dealloc = ossl_aead_dealloc,
    .init = ossl_aead_init,
    .set_iv = ossl_aead_set_iv,
    .set_aad = ossl_aead_set_aad,
    .encrypt = ossl_aead_encrypt,
    .decrypt = ossl_aead_decrypt,
    .supported_algs =
        AEAD_ALL /* AES_GCM_128, AES_GCM_192, AES_GCM_256, CHACHA20_POLY1305 */
};
