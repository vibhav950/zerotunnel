#ifndef __AES_GCM_OSSL_H__
#define __AES_GCM_OSSL_H__

#include "cipher.h"

#define AES_GCM_128_KEY_LEN 16U
#define AES_GCM_192_KEY_LEN 24U
#define AES_GCM_256_KEY_LEN 32U

#define AES_GCM_IV_LEN 12U

#define AES_AUTH_TAG_LEN_LONG 16U
#define AES_AUTH_TAG_LEN_SHORT 8U

#if (1)

#include <openssl/evp.h>
#include <openssl/aes.h>

typedef struct aes_gcm_ossl_ctx_st {
    EVP_CIPHER_CTX *ossl_ctx;
    const EVP_CIPHER *ossl_evp;
    size_t key_len;
    size_t tag_len;
    cipher_operation_t oper;
} aes_gcm_ossl_ctx;

#endif /* OPENSSL */

#endif /* __AES_GCM_OSSL_H__ */
