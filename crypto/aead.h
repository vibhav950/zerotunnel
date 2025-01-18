#ifndef __AEAD_H__
#define __AEAD_H__

#include "cipher.h"

#define AES_GCM_128_KEY_LEN 16U
#define AES_GCM_192_KEY_LEN 24U
#define AES_GCM_256_KEY_LEN 32U
#define CHACHA20_POLY1305_KEY_LEN 32U

#define AES_GCM_IV_LEN 12U
#define CHACHA20_POLY1305_IV_LEN 12U

#define AES_GCM_AUTH_TAG_LEN_LONG 16U
#define AES_GCM_AUTH_TAG_LEN_SHORT 8U
#define CHACHA20_POLY1305_AUTH_TAG_LEN_LONG 16U
#define CHACHA20_POLY1305_AUTH_TAG_LEN_SHORT 12U

#if (1) // def OPENSSL

#include <openssl/aes.h>
#include <openssl/evp.h>

typedef struct aead_ossl_ctx_st {
  EVP_CIPHER_CTX *ossl_ctx;
  const EVP_CIPHER *ossl_evp;
  size_t key_len;
  size_t tag_len;
  cipher_operation_t oper;
} aead_ossl_ctx;

#endif /* OPENSSL */

#endif /* __AEAD_H__ */
