#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "common/defs.h"

typedef enum {
  CIPHER_FLAG_ALLOC = (1U << 0),
  CIPHER_FLAG_INIT = (1U << 1),
  CIPHER_FLAG_AAD = (1U << 2),
} cipher_flag_t;

/**
 * This enum MUST NOT be changed, since implementation
 * exists only for the algorithms present in this list
 */
typedef enum {
  CIPHER_AES_GCM_128 = (1U << 0),
  CIPHER_AES_GCM_192 = (1U << 1),
  CIPHER_AES_GCM_256 = (1U << 2),
  CIPHER_CHACHA20_POLY1305 = (1U << 3),
  AEAD_ALL = CIPHER_AES_GCM_128 | CIPHER_AES_GCM_192 | CIPHER_AES_GCM_256 | CIPHER_CHACHA20_POLY1305,
} cipher_alg_t;

typedef enum cipher_operation_st {
  CIPHER_OPERATION_DECRYPT = 1,
  CIPHER_OPERATION_ENCRYPT = 2,
} cipher_operation_t;

/** A pointer type for @p cipher_st, which is defined later */
typedef struct cipher_st *cipher_ptr_t;

typedef error_t (*cipher_alloc_func_t)(cipher_ptr_t *c, size_t key_len,
                                       size_t tag_len, cipher_alg_t alg);

typedef void (*cipher_dealloc_func_t)(cipher_ptr_t c);

typedef error_t (*cipher_init_func_t)(cipher_ptr_t c, const uint8_t *key,
                                      size_t key_len, cipher_operation_t oper);

typedef error_t (*cipher_set_iv_func_t)(cipher_ptr_t c, const uint8_t *iv,
                                        size_t iv_len);

typedef error_t (*cipher_set_aad_func_t)(cipher_ptr_t c, const uint8_t *aad,
                                         size_t aad_len);

typedef error_t (*cipher_encrypt_func_t)(cipher_ptr_t c, const uint8_t *in,
                                         size_t in_len, uint8_t *out,
                                         size_t *out_len);

typedef error_t (*cipher_decrypt_func_t)(cipher_ptr_t c, const uint8_t *in,
                                         size_t in_len, uint8_t *out,
                                         size_t *out_len);

typedef struct cipher_intf_st {
  cipher_alloc_func_t alloc;
  cipher_dealloc_func_t dealloc;
  cipher_init_func_t init;
  cipher_set_iv_func_t set_iv;
  cipher_set_aad_func_t set_aad;
  cipher_encrypt_func_t encrypt;
  cipher_decrypt_func_t decrypt;
  cipher_alg_t supported_algs;
} cipher_intf_t;

typedef struct cipher_st {
  const cipher_intf_t *intf;
  void *ctx;
  size_t key_len;
  size_t tag_len;
  cipher_operation_t oper;
  cipher_alg_t alg;
  cipher_flag_t flags;
} cipher_t;

const char *cipher_alg_to_string(cipher_alg_t alg);

int cipher_intf_alg_is_supported(const cipher_intf_t *intf, cipher_alg_t alg);

int cipher_flag_get(cipher_t *c, cipher_flag_t flag);

error_t cipher_intf_alloc(const cipher_intf_t *intf, cipher_t **c,
                          size_t key_len, size_t tag_len, cipher_alg_t alg);

void cipher_dealloc(cipher_t *c);

error_t cipher_init(cipher_t *c, const uint8_t *key, size_t key_len,
                    cipher_operation_t oper);

error_t cipher_set_iv(cipher_t *c, const uint8_t *iv, size_t iv_len);

error_t cipher_set_aad(cipher_t *c, const uint8_t *aad, size_t aad_len);

error_t cipher_encrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len);

error_t cipher_decrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len);

#endif /* __CIPHER_H__ */
