#ifndef __HMAC_H__
#define __HMAC_H__

#include "common/defs.h"

typedef enum {
  HMAC_FLAG_ALLOC = (1U << 0),
  HMAC_FLAG_INIT = (1U << 1),
} hmac_flag_t;

/**
 * This enum MUST NOT be changed, since implementation
 * exists only for the algorithms present in this list
 */
typedef enum {
  HMAC_SHA256 = (1U << 0),
  HMAC_SHA384 = (1U << 1),
  HMAC_SHA512 = (1U << 2),
  HMAC_SHA3_256 = (1U << 3),
  HMAC_SHA3_384 = (1U << 4),
  HMAC_SHA3_512 = (1U << 5),
  HMAC_ALG_ALL = HMAC_SHA256 | HMAC_SHA384 | HMAC_SHA512 | HMAC_SHA3_256 |
                 HMAC_SHA3_384 | HMAC_SHA3_512,
} hmac_alg_t;

/** A pointer type for @p hmac_st, which is defined later */
typedef struct hmac_st *hmac_ptr_t;

typedef error_t (*hmac_alloc_func_t)(hmac_ptr_t *h, size_t key_len,
                                     size_t out_len, hmac_alg_t alg);

typedef void (*hmac_dealloc_func_t)(hmac_ptr_t ctx);

typedef error_t (*hmac_init_func_t)(hmac_ptr_t h, const uint8_t *key,
                                    size_t key_len);

typedef error_t (*hmac_update_func_t)(hmac_ptr_t h, const uint8_t *data,
                                      size_t data_len);

typedef error_t (*hmac_compute_func_t)(hmac_ptr_t h, const uint8_t *msg,
                                       size_t msg_len, uint8_t *digest,
                                       size_t digest_len);

typedef struct hmac_intf_st {
  hmac_alloc_func_t alloc;
  hmac_dealloc_func_t dealloc;
  hmac_init_func_t init;
  hmac_update_func_t update;
  hmac_compute_func_t compute;
  hmac_alg_t supported_algs;
} hmac_intf_t;

typedef struct hmac_st {
  const hmac_intf_t *intf;
  void *ctx;
  hmac_ptr_t h;
  size_t key_len;
  hmac_alg_t alg;
  unsigned int flags;
} hmac_t;

const char *hmac_alg_to_string(hmac_alg_t alg);

int hmac_intf_alg_is_supported(const hmac_intf_t *intf, hmac_alg_t alg);

int hmac_flag_get(hmac_t *h, hmac_flag_t flag);

error_t hmac_intf_alloc(const hmac_intf_t *intf, hmac_t **h, size_t key_len,
                        size_t out_len, hmac_alg_t alg);

void hmac_dealloc(hmac_t *h);

error_t hmac_init(hmac_t *h, const uint8_t *key, size_t key_len);

error_t hmac_update(hmac_t *h, const uint8_t *msg, size_t msg_len);

error_t hmac_compute(hmac_t *h, const uint8_t *msg, size_t msg_len,
                     uint8_t *digest, size_t digest_len);

#endif /* __HMAC_H__ */
