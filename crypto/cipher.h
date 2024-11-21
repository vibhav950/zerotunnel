#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "common/defs.h"

typedef enum {
  CIPHER_FLAG_ALLOC = (1U << 0),
  CIPHER_FLAG_INIT = (1U << 1),
  CIPHER_FLAG_AEAD = (1U << 2),
} cipher_flag_t;

typedef enum {
  AES_GCM_128 = (1U << 0),
  AES_GCM_192 = (1U << 1),
  AES_GCM_256 = (1U << 2),
  AES_GCM_ALL = AES_GCM_128 | AES_GCM_192 | AES_GCM_256,
} cipher_alg_t;

typedef enum cipher_oper_st {
  CIPHER_OPER_DECRYPT = 1,
  CIPHER_OPER_ENCRYPT = 2,
} cipher_oper_t;

/** A pointer type for @p cipher_st, which is defined later */
typedef struct cipher_st *cipher_ptr_t;

typedef error_t (*cipher_alloc_func_t)(cipher_ptr_t **c, size_t key_len,
                                       size_t tag_len);

typedef error_t (*cipher_free_func_t)(cipher_ptr_t ctx);

typedef error_t (*cipher_init_func_t)(cipher_ptr_t c, const uint8_t *key,
                                      size_t key_len, cipher_oper_t oper);

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
  cipher_free_func_t dealloc;
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
  cipher_alg_t alg;
  cipher_flag_t flags;
} cipher_t;

extern int cipher_alg_is_supported(cipher_t *c, cipher_alg_t alg);
extern int cipher_flag_get(cipher_t *c, cipher_flag_t flag);

#endif /* __CIPHER_H__ */
