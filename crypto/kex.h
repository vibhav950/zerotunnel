#ifndef __KEX_H__
#define __KEX_H__

#include "common/defs.h"

typedef enum {
  KEX_FLAG_ALLOC = (1U << 0),
  KEX_FLAG_KEYGEN = (1U << 1),
} kex_flag_t;

/** */
typedef enum {
  KEX_CURVE_secp256k1 = (1U << 0),
  KEX_CURVE_secp384r1 = (1U << 1),
  KEX_CURVE_secp521r1 = (1U << 2),
  KEX_CURVE_prime239v3 = (1U << 3),
  KEX_CURVE_prime256v1 = (1U << 4),
  KEX_CURVE_X25519 = (1U << 5),
  KEX_CURVE_X448 = (1U << 6),
} kex_curve_t;

/* kex_* pointers that are required but not yet defined */
typedef struct kex_st *kex_ptr_t;
typedef struct kex_peer_share_st *kex_peer_share_ptr_t;

typedef error_t (*kex_alloc_func_t)(kex_ptr_t *kex, kex_curve_t curve);

typedef void (*kex_dealloc_func_t)(kex_ptr_t kex);

typedef error_t (*kex_key_gen_func_t)(kex_ptr_t kex);

typedef error_t (*kex_get_peer_data_func_t)(kex_ptr_t kex,
                                            kex_peer_share_ptr_t peer_data);

typedef error_t (*kex_new_peer_data_func_t)(kex_peer_share_ptr_t peer_data,
                                            const uint8_t *ec_pub,
                                            size_t ec_pub_len,
                                            const uint8_t *ec_curvename,
                                            size_t ec_curvename_len);

typedef void (*kex_free_peer_data_func_t)(kex_peer_share_ptr_t peer_data);

typedef error_t (*kex_derive_shared_key_func_t)(kex_ptr_t kex,
                                                kex_peer_share_ptr_t peer_data,
                                                unsigned char **shared_key,
                                                size_t *shared_key_len);

typedef struct kex_intf_st {
  kex_alloc_func_t alloc;
  kex_dealloc_func_t dealloc;
  kex_key_gen_func_t key_gen;
  kex_get_peer_data_func_t get_peer_data;
  kex_new_peer_data_func_t new_peer_data;
  kex_free_peer_data_func_t free_peer_data;
  kex_derive_shared_key_func_t derive_shared_key;
  kex_curve_t supported_curves;
} kex_intf_t;

typedef struct kex_peer_share_st {
  void *ec_pub;
  size_t ec_pub_len;
  void *ec_curvename;
  size_t ec_curvename_len;
} kex_peer_share_t;

typedef struct kex_st {
  const kex_intf_t *intf;
  kex_curve_t curve;
  void *ctx;
  kex_flag_t flags;
} kex_t;

const char *kex_curve_name(kex_curve_t id);

int kex_intf_curve_is_supported(const kex_intf_t *intf, kex_curve_t curve);

int kex_flag_get(kex_t *kex, kex_flag_t flag);

error_t kex_intf_alloc(const kex_intf_t *intf, kex_t **kex, kex_curve_t curve);

void kex_dealloc(kex_t *kex);

error_t kex_key_gen(kex_t *kex);

error_t kex_get_peer_data(kex_t *kex, kex_peer_share_t *peer_data);

error_t kex_new_peer_data(kex_t *kex, kex_peer_share_t *peer_data,
                          const uint8_t *ec_pub, size_t ec_pub_len,
                          const uint8_t *ec_curvename, size_t ec_curvename_len);

void kex_free_peer_data(kex_t *kex, kex_peer_share_t *peer_data);

error_t kex_derive_shared_key(kex_t *kex, kex_peer_share_t *peer_data,
                              unsigned char **shared_key,
                              size_t *shared_key_len);

#endif /* __KEX_H__ */
