#ifndef __HMAC_OSSL_H__
#define __HMAC_OSSL_H__

#include "hmac.h"

/**
 * HMAC key lengths
 */

#define HMAC_SHA256_KEY_LEN           32U
#define HMAC_SHA384_KEY_LEN           48U
#define HMAC_SHA512_KEY_LEN           64U
#define HMAC_SHA3_256_KEY_LEN         32U
#define HMAC_SHA3_384_KEY_LEN         48U
#define HMAC_SHA3_512_KEY_LEN         64U
#define HMAC_MAX_KEY_LEN              64U

/**
 * HMAC digest/output lengths
 *
 * Note: HMAC_*_MAX_OUT_LEN == HMAC_*_KEY_LEN
 */

#define HMAC_SHA256_MAX_OUT_LEN       HMAC_SHA256_KEY_LEN
#define HMAC_SHA384_MAX_OUT_LEN       HMAC_SHA384_KEY_LEN
#define HMAC_SHA512_MAX_OUT_LEN       HMAC_SHA512_KEY_LEN
#define HMAC_SHA3_256_MAX_OUT_LEN     HMAC_SHA3_256_KEY_LEN
#define HMAC_SHA3_384_MAX_OUT_LEN     HMAC_SHA3_384_KEY_LEN
#define HMAC_SHA3_512_MAX_OUT_LEN     HMAC_SHA3_512_KEY_LEN
#define HMAC_MAX_OUT_LEN              HMAC_MAX_KEY_LEN

#if defined(OPENSSL)

#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct hmac_ossl_ctx_st {
  const EVP_MD *md;
  EVP_MD_CTX *md_ctx;
} hmac_ossl_ctx;

#endif /* OPENSSL */

#endif /* __HMAC_OSSL_H__ */
