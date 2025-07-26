#ifndef __KDF_H__
#define __KDF_H__

#include "common/defines.h"

// clang-format off

typedef enum {
  KDF_FLAG_ALLOC       = (1U << 0),
  KDF_FLAG_INIT        = (1U << 1),
} kdf_flag_t;

enum {
  KDF_ALG_scrypt = (1U << 0),
  KDF_ALG_PBKDF2 = (1U << 1),
  KDF_ALG_argon2 = (1U << 2),
};

// clang-format on

/** Fixed-size KDF identifier */
typedef uint8_t kdf_alg_t;

/* Forward declaration */
typedef struct kdf_st *kdf_ptr_t;

typedef err_t (*kdf_alloc_func_t)(kdf_ptr_t *kdf, kdf_alg_t alg);

typedef void (*kdf_dealloc_func_t)(kdf_ptr_t kdf);

typedef err_t (*kdf_init_func_t)(kdf_ptr_t kdf, const uint8_t *password,
                                 size_t password_len, const uint8_t *salt,
                                 size_t salt_len);

typedef err_t (*kdf_derive_func_t)(kdf_ptr_t kdf,
                                   const uint8_t *additional_data,
                                   size_t additional_data_len, uint8_t *key,
                                   size_t key_len);

typedef struct kdf_intf_st {
  kdf_alloc_func_t alloc;
  kdf_dealloc_func_t dealloc;
  kdf_init_func_t init;
  kdf_derive_func_t derive;
  kdf_alg_t supported_algs;
} kdf_intf_t;

typedef struct kdf_st {
  const kdf_intf_t *intf;
  void *ctx;
  uint8_t *pw;
  size_t pwlen;
  uint8_t *salt;
  size_t saltlen;
  kdf_alg_t alg;
  kdf_flag_t flags;
} kdf_t;

const char *kdf_alg_to_string(kdf_alg_t alg);

int kdf_intf_alg_is_supported(const kdf_intf_t *intf, kdf_alg_t alg);

int kdf_flag_get(kdf_t *kdf, kdf_flag_t flag);

err_t kdf_intf_alloc(const kdf_intf_t *intf, kdf_t **kdf, kdf_alg_t alg);

void kdf_dealloc(kdf_t *kdf);

err_t kdf_init(kdf_t *kdf, const uint8_t *password, size_t password_len,
               const uint8_t *salt, size_t salt_len);

err_t kdf_derive(kdf_t *kdf, const uint8_t *additional_data,
                 size_t additional_data_len, uint8_t *key, size_t key_len);

#endif /* __KDF_H__ */
