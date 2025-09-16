/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * cipher_ossl.c - OpenSSL implementation of symmetric block ciphers
 */

#include "cipher.h"
#include "cipher_defs.h"
#include "common/defines.h"
#include "common/log.h"

#include <openssl/evp.h>

typedef struct _cipher_ossl_ctx_st {
  const EVP_CIPHER *ossl_evp;
  EVP_CIPHER_CTX *ossl_ctx;
} cipher_ossl_ctx;

// clang-format off
#define CHECK(cond) { if (!(cond)) return ERR_BAD_ARGS; }

#define CIPHER_OPERATION_SET(c, operation) (void)((c)->oper = operation)
#define CIPHER_OPERATION_GET(c, operation) ((c)->oper == operation)

#define CIPHER_FLAG_SET(c, flag) (void)((c)->flags |= flag)
#define CIPHER_FLAG_GET(c, flag) ((c)->flags & flag)
// clang-format on

/**
 * Allocate and initialize an cipher context for the specified algorithm and key length.
 *
 * @param[out] c      Pointer to the allocated cipher context
 * @param[in]  key_len Length of the encryption/decryption key
 * @param[in]  tag_len Tag length (unused)
 * @param[in]  alg     Cipher algorithm
 * @return ERR_SUCCESS on success, error code otherwise
 */
static err_t ossl_cipher_alloc(cipher_t **c, size_t key_len,
                               size_t tag_len ATTRIBUTE_UNUSED, cipher_alg_t alg) {
  extern const cipher_intf_t cipher_intf;
  cipher_ossl_ctx *cipher_ctx;
  const EVP_CIPHER *evp;

  log_debug(NULL, "key_len=%zu, alg=%s", key_len, cipher_alg_to_string(alg));

  switch (alg) {
  case CIPHER_AES_CTR_128:
    CHECK(key_len == AES_CTR_128_KEY_LEN);
    evp = EVP_aes_128_ctr();
    break;
  case CIPHER_AES_CTR_192:
    CHECK(key_len == AES_CTR_192_KEY_LEN);
    evp = EVP_aes_192_ctr();
    break;
  case CIPHER_AES_CTR_256:
    CHECK(key_len == AES_CTR_256_KEY_LEN);
    evp = EVP_aes_256_ctr();
    break;
  case CIPHER_CHACHA20:
    CHECK(key_len == CHACHA20_KEY_LEN);
    evp = EVP_chacha20();
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (!(*c = zt_malloc(sizeof(cipher_t))))
    return ERR_MEM_FAIL;

  if (!(cipher_ctx = (cipher_ossl_ctx *)zt_malloc(sizeof(cipher_ossl_ctx)))) {
    zt_free(*c);
    *c = NULL;
    return ERR_MEM_FAIL;
  }

  if (!(cipher_ctx->ossl_ctx = EVP_CIPHER_CTX_new())) {
    zt_free(cipher_ctx);
    zt_free(*c);
    *c = NULL;
    return ERR_INTERNAL;
  }
  cipher_ctx->ossl_evp = evp;

  (*c)->intf = &cipher_intf;
  (*c)->ctx = cipher_ctx;
  (*c)->key_len = key_len;
  (*c)->tag_len = 0;
  (*c)->alg = alg;
  CIPHER_FLAG_SET(*c, CIPHER_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 * Deallocate and securely erase an cipher context.
 *
 * @param[in] c Cipher context to deallocate
 * @return Void
 */
static void ossl_cipher_dealloc(cipher_t *c) {
  log_debug(NULL, "-");

  if (CIPHER_FLAG_GET(c, CIPHER_FLAG_ALLOC)) {
    cipher_ossl_ctx *cipher = (cipher_ossl_ctx *)c->ctx;

    if (cipher) {
      EVP_CIPHER_CTX_free(cipher->ossl_ctx);
      memzero(cipher, sizeof(cipher_ossl_ctx));
      zt_free(cipher);
    }
  }
  memzero(c, sizeof(cipher_t));
  zt_free(c);
}

/**
 * Initialize the cipher context with the provided key and operation mode.
 *
 * @param[in] c        Cipher context
 * @param[in] key      Key buffer
 * @param[in] key_len  Length of the key
 * @param[in] oper     Operation (encrypt or decrypt)
 * @return ERR_SUCCESS on success, error code otherwise
 */
static err_t ossl_cipher_init(cipher_t *c, const uint8_t *key, size_t key_len,
                              cipher_operation_t oper) {
  cipher_ossl_ctx *ctx;
  cipher_alg_t alg;

  log_debug(NULL, "key_len=%zu", key_len);

  if (!key)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_ALLOC))
    return ERR_NOT_INIT;

  ctx = c->ctx;
  alg = c->alg;

  switch (key_len) {
  case AES_CTR_128_KEY_LEN:
    CHECK(alg == CIPHER_AES_CTR_128);
    break;
  case AES_CTR_192_KEY_LEN:
    CHECK(alg == CIPHER_AES_CTR_192);
    break;
  case AES_CTR_256_KEY_LEN:
    // case CHACHA20_KEY_LEN:
    CHECK((alg == CIPHER_AES_CTR_256) || (alg == CIPHER_CHACHA20));
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (oper != CIPHER_OPERATION_ENCRYPT && oper != CIPHER_OPERATION_DECRYPT)
    return ERR_BAD_ARGS;

  if (oper == CIPHER_OPERATION_ENCRYPT) {
    if (EVP_EncryptInit_ex(ctx->ossl_ctx, ctx->ossl_evp, NULL, key, NULL) != 1)
      return ERR_INTERNAL;
  } else {
    if (EVP_DecryptInit_ex(ctx->ossl_ctx, ctx->ossl_evp, NULL, key, NULL) != 1)
      return ERR_INTERNAL;
  }

  CIPHER_FLAG_SET(c, CIPHER_FLAG_INIT);
  CIPHER_OPERATION_SET(c, oper);

  return ERR_SUCCESS;
}

/**
 * Set the initialization vector (IV) for the cipher context.
 *
 * @param[in] c      Cipher context
 * @param[in] iv     IV buffer
 * @param[in] iv_len Length of the IV
 * @return ERR_SUCCESS on success, error code otherwise
 */
static err_t ossl_cipher_set_iv(cipher_t *c, const uint8_t *iv, size_t iv_len) {
  cipher_ossl_ctx *ctx;
  cipher_alg_t alg;

  log_debug(NULL, "iv_len=%zu", iv_len);

  if (!iv)
    return ERR_NULL_PTR;

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  ctx = c->ctx;
  alg = c->alg;

  if ((alg == CIPHER_CHACHA20) && (iv_len != CHACHA20_IV_LEN))
    return ERR_BAD_ARGS;
  else if (iv_len != AES_CTR_IV_LEN)
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
 * Set the Additional Authenticated Data (AAD) for the cipher context.
 * @warning Not supported for such ciphers.
 *
 * @param[in] c      Cipher context (unused)
 * @param[in] aad    AAD buffer (unused)
 * @param[in] aad_len Length of the AAD (unused)
 * @return ERR_INVALID always (not supported)
 */
static err_t ossl_cipher_set_aad(cipher_t *c ATTRIBUTE_UNUSED,
                                 const uint8_t *aad ATTRIBUTE_UNUSED,
                                 size_t aad_len ATTRIBUTE_UNUSED) {
  log_debug(NULL, "aad_len=%zu", aad_len);

  return ERR_INVALID;
}

/**
 * Encrypt data.
 *
 * @param[in]  c       Cipher context
 * @param[in]  in      Input buffer to encrypt
 * @param[in]  in_len  Length of input buffer
 * @param[out] out     Output buffer for encrypted data
 * @param[in,out] out_len On input: size of output buffer; on output: actual bytes written
 * @return ERR_SUCCESS on success, error code otherwise
 */
static err_t ossl_cipher_encrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len) {
  int len;
  cipher_ossl_ctx *ctx;

  log_debug(NULL, "in_len=%zu", in_len);

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  if (!CIPHER_OPERATION_GET(c, CIPHER_OPERATION_ENCRYPT))
    return ERR_BAD_ARGS;

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

  if (EVP_EncryptUpdate(ctx->ossl_ctx, out, &len, in, in_len) != 1)
    return ERR_INTERNAL;
  *out_len = len;

  return ERR_SUCCESS;
}

/**
 * Decrypt data.
 *
 * @param[in]  c       Cipher context
 * @param[in]  in      Input buffer to decrypt
 * @param[in]  in_len  Length of input buffer
 * @param[out] out     Output buffer for decrypted data
 * @param[in,out] out_len On input: size of output buffer; on output: actual bytes written
 * @return ERR_SUCCESS on success, error code otherwise
 */
static err_t ossl_cipher_decrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len) {
  int len;
  cipher_ossl_ctx *ctx;

  log_debug(NULL, "in_len=%zu", in_len);

  if (!CIPHER_FLAG_GET(c, CIPHER_FLAG_INIT))
    return ERR_NOT_INIT;

  if (!CIPHER_OPERATION_GET(c, CIPHER_OPERATION_DECRYPT))
    return ERR_BAD_ARGS;

  if (!out_len)
    return ERR_NULL_PTR;

  if (in_len < c->tag_len)
    return ERR_BAD_ARGS;

  if (*out_len < in_len - c->tag_len) {
    *out_len = in_len - c->tag_len;
    return ERR_BUFFER_TOO_SMALL;
  }

  if (!in || !out)
    return ERR_NULL_PTR;

  ctx = c->ctx;

  if (EVP_DecryptUpdate(ctx->ossl_ctx, out, &len, in, in_len) != 1)
    return ERR_INTERNAL;
  *out_len = len;

  return ERR_SUCCESS;
}

const cipher_intf_t cipher_intf = {
    .alloc = ossl_cipher_alloc,
    .dealloc = ossl_cipher_dealloc,
    .init = ossl_cipher_init,
    .set_iv = ossl_cipher_set_iv,
    .set_aad = ossl_cipher_set_aad,
    .encrypt = ossl_cipher_encrypt,
    .decrypt = ossl_cipher_decrypt,
    .supported_algs =
        CIPHER_AES_CTR_128 | CIPHER_AES_CTR_192 | CIPHER_AES_CTR_256 | CIPHER_CHACHA20,
};
