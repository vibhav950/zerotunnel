#include "kdf.h"
#include "common/defines.h"

const char *kdf_alg_to_string(kdf_alg_t alg) {
  switch (alg) {
  case KDF_ALG_PBKDF2:
    return "PBKDF2";
  case KDF_ALG_scrypt:
    return "scrypt";
  case KDF_ALG_argon2:
    return "argon2";
  default:
    return "unknown type";
  }
}

int kdf_intf_alg_is_supported(const kdf_intf_t *intf, kdf_alg_t alg) {
  return (intf) && (intf->supported_algs & alg);
}

int kdf_flag_get(kdf_t *kdf, kdf_flag_t flag) {
  return (kdf) && (kdf->flags & flag);
}

err_t kdf_intf_alloc(const kdf_intf_t *intf, kdf_t **kdf, kdf_alg_t alg) {
  if (!intf || !intf->alloc || !kdf)
    return ERR_NULL_PTR;

  return (intf)->alloc(kdf, alg);
}

void kdf_dealloc(kdf_t *kdf) {
  if (!kdf || !kdf->intf)
    return;

  ((kdf)->intf)->dealloc(kdf);
}

err_t kdf_init(kdf_t *kdf, const uint8_t *password, size_t password_len,
               const uint8_t *salt, size_t salt_len, const uint8_t ctr128[16]) {
  if (!kdf || !kdf->intf)
    return ERR_NULL_PTR;

  return ((kdf)->intf)
      ->init(kdf, password, password_len, salt, salt_len, ctr128);
}

err_t kdf_derive(kdf_t *kdf, const uint8_t *additional_data,
                 size_t additional_data_len, uint8_t *key, size_t key_len) {
  if (!kdf || !kdf->intf)
    return ERR_NULL_PTR;

  return ((kdf)->intf)
      ->derive(kdf, additional_data, additional_data_len, key, key_len);
}
