#ifndef __KEX_ECC_OSSL_H__
#define __KEX_ECC_OSSL_H__

#include "kex.h"

#if (__has_include(<openssl/evp.h>))
#include <openssl/evp.h>
#else
#error "OpenSSL not found"
#endif

typedef struct kex_ossl_ctx_st {
    EVP_PKEY *ec_params;
    EVP_PKEY *ec_key;
} kex_ossl_ctx;

#endif /* __KEX_ECC_OSSL_H__ */
