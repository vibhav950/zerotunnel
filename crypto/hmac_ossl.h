#ifndef __HMAC_OSSL_H__
#define __HMAC_OSSL_H__

#include "hmac.h"

#if (__has_include(<openssl/hmac.h>))
#include <openssl/evp.h>
#include <openssl/hmac.h>
#else
#error "OpenSSL not found"
#endif

typedef struct hmac_ossl_ctx_st {
    HMAC_CTX *ossl_ctx;
    EVP_MD *ossl_md;
    size_t key_len;
    hmac_alg_t alg;
} hmac_ossl_ctx;

/** HMAC digest lengths */
#define HMAC_SHA256_OUT_LEN 32U
#define HMAC_SHA384_OUT_LEN 48U
#define HMAC_SHA512_OUT_LEN 64U
#define HMAC_SHA3_256_OUT_LEN 32U
#define HMAC_SHA3_384_OUT_LEN 48U
#define HMAC_SHA3_512_OUT_LEN 64U

/** HMAC key length
 *
 * we use a key_len equal to the out_len
 */
#define HMAC_SHA256_KEY_LEN HMAC_SHA256_OUT_LEN
#define HMAC_SHA384_KEY_LEN HMAC_SHA384_OUT_LEN
#define HMAC_SHA512_KEY_LEN HMAC_SHA512_OUT_LEN
#define HMAC_SHA3_256_KEY_LEN HMAC_SHA3_256_OUT_LEN
#define HMAC_SHA3_384_KEY_LEN HMAC_SHA3_384_OUT_LEN
#define HMAC_SHA3_512_KEY_LEN HMAC_SHA3_512_OUT_LEN

#endif /* __HMAC_OSSL_H__ */
