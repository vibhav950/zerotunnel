#ifndef __CIPHER_DEFS__
#define __CIPHER_DEFS__

// clang-format off

/* ========= Cipher key lengths ========= */

#define AES_CTR_128_KEY_LEN                  16U
#define AES_CTR_192_KEY_LEN                  24U
#define AES_CTR_256_KEY_LEN                  32U
#define CHACHA20_KEY_LEN                     32U

/* ========= AEAD key lengths ========= */

#define AES_GCM_128_KEY_LEN                  16U
#define AES_GCM_192_KEY_LEN                  24U
#define AES_GCM_256_KEY_LEN                  32U
#define CHACHA20_POLY1305_KEY_LEN            32U

/* ========= IV/Nonce lengths ========= */

#define AES_CTR_IV_LEN                       16U
#define CHACHA20_IV_LEN                      16U
#define AES_GCM_IV_LEN                       12U
#define CHACHA20_POLY1305_IV_LEN             12U

/* ========= AEAD authentication tag lengths ========= */

#define AES_GCM_AUTH_TAG_LEN_LONG            16U
#define AES_GCM_AUTH_TAG_LEN_SHORT            8U
#define CHACHA20_POLY1305_AUTH_TAG_LEN_LONG  16U
#define CHACHA20_POLY1305_AUTH_TAG_LEN_SHORT 12U

#endif /* __CIPHER_DEFS__ */
