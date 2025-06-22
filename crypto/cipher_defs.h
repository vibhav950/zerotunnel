#ifndef __CIPHER_DEFS__
#define __CIPHER_DEFS__

#define AES_CTR_128_KEY_LEN 16U
#define AES_CTR_192_KEY_LEN 24U
#define AES_CTR_256_KEY_LEN 32U
#define CHACHA20_KEY_LEN 32U

#define AES_GCM_128_KEY_LEN 16U
#define AES_GCM_192_KEY_LEN 24U
#define AES_GCM_256_KEY_LEN 32U
#define CHACHA20_POLY1305_KEY_LEN 32U

#define AES_CTR_IV_LEN 16U
#define CHACHA20_IV_LEN 16U
#define AES_GCM_IV_LEN 12U
#define CHACHA20_POLY1305_IV_LEN 12U

#define AES_GCM_AUTH_TAG_LEN_LONG 16U
#define AES_GCM_AUTH_TAG_LEN_SHORT 8U
#define CHACHA20_POLY1305_AUTH_TAG_LEN_LONG 16U
#define CHACHA20_POLY1305_AUTH_TAG_LEN_SHORT 12U

#if (1) // def OPENSSL

#include <openssl/evp.h>

struct _cipher_ossl_ctx_st {
  const EVP_CIPHER *ossl_evp;
  EVP_CIPHER_CTX *ossl_ctx;
};

typedef struct _cipher_ossl_ctx_st cipher_ossl_ctx, aead_ossl_ctx;

#endif /* OPENSSL */

#endif /* __CIPHER_DEFS__ */
