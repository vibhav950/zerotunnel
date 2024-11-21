#ifndef __AES_GCM_OSSL_H
#define __AES_GCM_OSSL_H

#include "cipher.h"

#if (__has_include(<openssl/evp.h>))
#include <openssl/evp.h>
#else
#error "OpenSSL not found"
#endif

typedef struct aes_gcm_ossl_ctx_st {
    EVP_CIPHER_CTX *ossl_ctx;
    EVP_CIPHER *ossl_evp;
    size_t key_len;
    size_t tag_len;
    cipher_oper_t oper;
} aes_gcm_ossl_ctx;

#define AES_GCM_128_KEY_LEN 16U
#define AES_GCM_192_KEY_LEN 24U
#define AES_GCM_256_KEY_LEN 32U

#define AES_GCM_IV_LEN 12U

#define AES_AUTH_TAG_LEN_LONG 16U
#define AES_AUTH_TAG_LEN_SHORT 8U

#endif /* __AES_GCM_OSSL_H */