#ifndef __KEX_ECC_OSSL_H__
#define __KEX_ECC_OSSL_H__

#include "kex.h"

#define OPENSSL
#if defined(OPENSSL)

#include <openssl/evp.h>

typedef struct kex_ossl_ctx_st {
    EVP_PKEY *ec_params;
    EVP_PKEY *ec_key;
} kex_ossl_ctx;

#endif /* OPENSSL */

#endif /* __KEX_ECC_OSSL_H__ */
