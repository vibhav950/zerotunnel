/**
 * @file kdf_gtls.c
 *
 * @brief KDF implementation using GnuTLS
 *
 * @author vibhav950 on GitHub
 */

#include "common/defines.h"
#include "common/log.h"
#include "kdf.h"
#include "kdf_defs.h"

#include <gnutls/crypto.h>

typedef struct kdf_gtls_ctx_st {
  gnutls_mac_algorithm_t mac_alg;
} kdf_gtls_ctx;

#define KDF_FLAG_SET(kdf, flag) (void)((kdf)->flags |= flag)
#define KDF_FLAG_GET(kdf, flag) ((kdf)->flags & flag)
#define KDF_FLAG_UNSET(kdf, flag) (void)((kdf)->flags &= ~flag)

/**  */
static err_t gtls_kdf_alloc(kdf_t **kdf, kdf_alg_t alg) {
  extern const kdf_intf_t kdf_intf;
  kdf_gtls_ctx *kdf_ctx;
  gnutls_mac_algorithm_t mac_alg;

  log_debug(NULL, "alg=%s", kdf_alg_to_string(alg));

  switch (alg) {
  case KDF_ALG_PBKDF2:
    mac_alg = GNUTLS_MAC_SHA512;
    break;
  default:
    return ERR_BAD_ARGS;
  }

  *kdf = (kdf_t *)zt_calloc(1, sizeof(kdf_t));
  if (!*kdf)
    return ERR_MEM_FAIL;

  kdf_ctx = (kdf_gtls_ctx *)zt_calloc(1, sizeof(kdf_gtls_ctx));
  if (!kdf_ctx) {
    zt_free(*kdf);
    *kdf = NULL;
    return ERR_MEM_FAIL;
  }
  kdf_ctx->mac_alg = mac_alg;

  (*kdf)->intf = &kdf_intf;
  (*kdf)->alg = alg;
  (*kdf)->ctx = kdf_ctx;
  KDF_FLAG_SET(*kdf, KDF_FLAG_ALLOC);

  return ERR_SUCCESS;
}

static void gtls_kdf_free(kdf_t *kdf) {
  kdf_gtls_ctx *kdf_ctx;

  if (KDF_FLAG_GET(kdf, KDF_FLAG_ALLOC)) {
    kdf_ctx = (kdf_gtls_ctx *)kdf->ctx;

    if (kdf_ctx) {
      /** Prevent state leaks */
      memzero(kdf_ctx, sizeof(kdf_gtls_ctx));
      zt_free(kdf_ctx);
    }
  }
  memzero(kdf->pw, kdf->pwlen);
  memzero(kdf->salt, kdf->saltlen);
  zt_free(kdf->pw);
  zt_free(kdf->salt);
  memzero(kdf, sizeof(kdf_t));
  zt_free(kdf);
  kdf = NULL;
}

/**  */
static err_t gtls_kdf_init(kdf_t *kdf, const uint8_t *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len) {
  uint8_t *pw, *slt;

  log_debug(NULL, "password_len=%zu, salt_len=%zu", password_len, salt_len);

  if (!password || !salt)
    return ERR_NULL_PTR;

  if (!password_len || (password_len > KDF_MAX_PASSWORD_LEN) || !salt_len ||
      (salt_len > KDF_MAX_SALT_LEN)) {
    return ERR_BAD_ARGS;
  }

  if (!KDF_FLAG_GET(kdf, KDF_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!(pw = (uint8_t *)zt_memdup(password, password_len)))
    return ERR_MEM_FAIL;

  if (!(slt = (uint8_t *)zt_memdup(salt, salt_len))) {
    zt_free(pw);
    return ERR_MEM_FAIL;
  }

  if (kdf->pw) {
    memzero(kdf->pw, kdf->pwlen);
    zt_free(kdf->pw);
  }

  if (kdf->salt) {
    memzero(kdf->salt, kdf->saltlen);
    zt_free(kdf->salt);
  }

  kdf->pw = pw;
  kdf->pwlen = password_len;
  kdf->salt = slt;
  kdf->saltlen = salt_len;
  KDF_FLAG_SET(kdf, KDF_FLAG_INIT);

  return ERR_SUCCESS;
}

/**  */
static err_t gtls_kdf_derive(kdf_t *kdf, const uint8_t *additional_data,
                             size_t additional_data_len, uint8_t *key, size_t key_len) {
  kdf_gtls_ctx *kdf_ctx;
  gnutls_mac_algorithm_t mac_alg;
  gnutls_datum_t dkey, dsalt;
  uint8_t *buf;
  size_t buf_len;
  err_t ret = ERR_SUCCESS;

  log_debug(NULL, "additional_data_len=%zu", additional_data_len);

  if (!key)
    return ERR_NULL_PTR;

  /** Additional data can be null but not null with non-zero length */
  if (!additional_data && additional_data_len)
    return ERR_NULL_PTR;

  if (key_len > KDF_MAX_KEYSTREAM_LEN)
    return ERR_BAD_ARGS;

  if (!KDF_FLAG_GET(kdf, KDF_FLAG_INIT))
    return ERR_NOT_INIT;

  kdf_ctx = (kdf_gtls_ctx *)kdf->ctx;
  mac_alg = kdf_ctx->mac_alg;

  buf_len = kdf->saltlen + additional_data_len;
  if (!(buf = zt_malloc(buf_len)))
    return ERR_MEM_FAIL;

  memcpy(buf, kdf->salt, kdf->saltlen);
  memcpy(buf + kdf->saltlen, additional_data, additional_data_len);
  dsalt.data = buf;
  dsalt.size = buf_len;

  dkey.data = kdf->pw;
  dkey.size = kdf->pwlen;

  if (gnutls_pbkdf2(mac_alg, &dkey, &dsalt, KDF_PBKDF2_CFABLE_ITER, key, key_len) < 0) {
    ret = ERR_INTERNAL;
  }

  memzero(buf, buf_len);
  zt_free(buf);
  return ret;
}

const kdf_intf_t kdf_intf = {
    .alloc = gtls_kdf_alloc,
    .dealloc = gtls_kdf_free,
    .init = gtls_kdf_init,
    .derive = gtls_kdf_derive,
    .supported_algs = KDF_ALG_PBKDF2,
};
