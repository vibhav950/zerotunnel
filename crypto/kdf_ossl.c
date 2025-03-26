/**
 * kdf_ossl.c
 *
 * KDF implementation using OpenSSL
 *
 * vibhav950 on GitHub
 */

// DO NOT REMOVE/MOVE THIS
#if !defined(__ZTLIB_ENVIRON_SAFE_MEM) || !__ZTLIB_ENVIRON_SAFE_MEM
#error "__ZTLIB_ENVIRON_SAFE_MEM must be defined and set to 1"
#endif

#include "common/defines.h"
#include "common/memzero.h"
#include "kdf.h"
#include "kdf_defs.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/thread.h>

#define KDF_FLAG_SET(kdf, flag) (void)((kdf)->flags |= flag)
#define KDF_FLAG_GET(kdf, flag) ((kdf)->flags & flag)
#define KDF_FLAG_UNSET(kdf, flag) (void)((kdf)->flags &= ~flag)

/**  */
static error_t ossl_kdf_alloc(kdf_t **kdf, kdf_alg_t alg) {
  extern const kdf_intf_t kdf_intf;
  kdf_ossl_ctx *kdf_ctx;
  EVP_KDF *pkdf;

  PRINTDEBUG("alg=%s", kdf_alg_to_string(alg));

  switch (alg) {
  case KDF_ALG_scrypt:
    pkdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    break;
  case KDF_ALG_PBKDF2:
    pkdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    break;
  case KDF_ALG_argon2:
    pkdf = EVP_KDF_fetch(NULL, "argon2id", NULL);
    break;
  default:
    return ERR_BAD_ARGS;
  }
  if (!pkdf)
    return ERR_INTERNAL;

  *kdf = (kdf_t *)zt_calloc(1, sizeof(kdf_t));
  if (!*kdf)
    return ERR_MEM_FAIL;

  kdf_ctx = (kdf_ossl_ctx *)zt_calloc(1, sizeof(kdf_ossl_ctx));
  if (!kdf_ctx) {
    zt_free(*kdf);
    *kdf = NULL;
    return ERR_MEM_FAIL;
  }

  kdf_ctx->kctx = EVP_KDF_CTX_new(pkdf);
  if (!kdf_ctx->kctx) {
    zt_free(kdf_ctx);
    zt_free(*kdf);
    *kdf = NULL;
    EVP_KDF_free(pkdf);
    return ERR_INTERNAL;
  }
  kdf_ctx->kdf = pkdf;

  (*kdf)->intf = &kdf_intf;
  (*kdf)->alg = alg;
  (*kdf)->ctx = kdf_ctx;
  KDF_FLAG_SET(*kdf, KDF_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**  */
static void ossl_kdf_dealloc(kdf_t *kdf) {
  PRINTDEBUG("");

  if (KDF_FLAG_GET(kdf, KDF_FLAG_ALLOC)) {
    kdf_ossl_ctx *kdf_ctx = kdf->ctx;

    if (kdf_ctx) {
      EVP_KDF_CTX_free(kdf_ctx->kctx);
      EVP_KDF_free(kdf_ctx->kdf);
      /* Prevent state leaks */
      memzero(kdf_ctx, sizeof(kdf_ossl_ctx));
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

/** Helper function for Scrypt KDF */
static int _kdf_hlp_scrypt(kdf_ossl_ctx *kdf_ctx, const uint8_t *pw,
                           size_t pw_len, const uint8_t *salt, size_t salt_len,
                           uint8_t *key, size_t key_len) {
  OSSL_PARAM params[7], *p = params;
  unsigned int scrypt_n, scrypt_r, scrypt_p, scrypt_maxmem;

  ASSERT(kdf_ctx);
  ASSERT(pw);
  ASSERT(pw_len);
  ASSERT(salt);
  ASSERT(salt_len);
  ASSERT(key);
  ASSERT(key_len);

  scrypt_n = KDF_SCRYPT_CFABLE_N;
  scrypt_r = KDF_SCRYPT_CFABLE_R;
  scrypt_p = MAX(MIN(KDF_SCRYPT_CFABLE_P, zt_cpu_get_processor_count()), 1);
  scrypt_maxmem = KDF_SCRYPT_CFABLE_MAXMEM;
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pw, pw_len);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_N, &scrypt_n);
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_R, &scrypt_r);
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_P, &scrypt_p);
  *p++ =
      OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &scrypt_maxmem);
  *p = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kdf_ctx->kctx, key, key_len, params) != 1)
    return -1;
  return 0;
}

/** Helper function for Argon2 KDF */
static int _kdf_hlp_argon2(kdf_ossl_ctx *kdf_ctx, const uint8_t *pw,
                           size_t pw_len, const uint8_t *salt, size_t salt_len,
                           uint8_t *key, size_t key_len) {
  OSSL_PARAM params[7], *p = params;
  uint32_t memory_cost, iteration_cost, lanes;
  unsigned int threads;

  ASSERT(kdf_ctx);
  ASSERT(pw);
  ASSERT(pw_len);
  ASSERT(salt);
  ASSERT(salt_len);
  ASSERT(key);
  ASSERT(key_len);

  if (OSSL_set_max_threads(NULL, KDF_ARGON2_CFABLE_THREADS) != 1)
    threads = 1; /* Bummer, can't do anything about it :/ */
  else
    threads = KDF_ARGON2_CFABLE_THREADS;
  memory_cost = KDF_ARGON2_CFABLE_MEM;
  iteration_cost = KDF_ARGON2_CFABLE_ITER;
  lanes = KDF_ARGON2_CFABLE_LANES;

  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pw, pw_len);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
  *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iteration_cost);
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
  *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
  *p++ =
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_cost);
  *p++ = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kdf_ctx->kctx, key, key_len, params) != 1)
    return -1;
  return 0;
}

/** Helper function for PBKDF2 KDF */
static int _kdf_hlp_pbkdf2(kdf_ossl_ctx *kdf_ctx, const uint8_t *pw,
                           size_t pw_len, const uint8_t *salt, size_t salt_len,
                           uint8_t *key, size_t key_len) {
  OSSL_PARAM params[5], *p = params;
  unsigned int iter;

  ASSERT(kdf_ctx);
  ASSERT(pw);
  ASSERT(pw_len);
  ASSERT(salt);
  ASSERT(salt_len);
  ASSERT(key);
  ASSERT(key_len);

  iter = KDF_PBKDF2_CFABLE_ITER;
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pw, pw_len);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha512, 0);
  *p = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kdf_ctx->kctx, key, key_len, params) != 1)
    return -1;
  return 0;
}

/**  */
static error_t ossl_kdf_init(kdf_t *kdf, const uint8_t *password,
                             size_t password_len, const uint8_t *salt,
                             size_t salt_len, const uint8_t ctr128[16]) {
  kdf_ossl_ctx *kdf_ctx;
  uint8_t *pw, *slt;
  uint32_t *ctr32;

  PRINTDEBUG("password_len=%zu, salt_len=%zu", password_len, salt_len);

  if (!password || !salt)
    return ERR_NULL_PTR;

  if (!password_len || (password_len > KDF_MAX_PASSWORD_LEN) || !salt_len ||
      (salt_len > KDF_MAX_SALT_LEN)) {
    return ERR_BAD_ARGS;
  }

  if (!KDF_FLAG_GET(kdf, KDF_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  kdf_ctx = kdf->ctx;

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
  ctr32 = (uint32_t *)ctr128;
  KDF_CTR_SET(kdf, ctr32[0], ctr32[1], ctr32[2], ctr32[3]);
  KDF_FLAG_SET(kdf, KDF_FLAG_INIT);
  KDF_FLAG_UNSET(kdf, KDF_FLAG_NEED_REINIT);
  kdf->count = 0; /* Reset this re-initialization counter */

  EVP_KDF_CTX_reset(kdf_ctx->kctx);

  return ERR_SUCCESS;
}

/**  */
static error_t ossl_kdf_derive(kdf_t *kdf, const uint8_t *additional_data,
                               size_t additional_data_len, uint8_t *key,
                               size_t key_len) {
  int rv;
  error_t ret = ERR_SUCCESS;
  kdf_ossl_ctx *kdf_ctx;
  kdf_alg_t alg;
  uint8_t *buf, *pbuf;
  size_t buf_len;

  PRINTDEBUG("additional_data_len=%zu", additional_data_len);

  if (!key)
    return ERR_NULL_PTR;

  /** Additional data can be null but not null with non-zero length */
  if (!additional_data && additional_data_len)
    return ERR_NULL_PTR;

  if (key_len > KDF_MAX_KEYSTREAM_LEN)
    return ERR_BAD_ARGS;

  if (!KDF_FLAG_GET(kdf, KDF_FLAG_INIT))
    return ERR_NOT_INIT;

  if (kdf->count >= KDF_MAX_REINIT_BYTES) {
    KDF_FLAG_SET(kdf, KDF_FLAG_NEED_REINIT);
    return ERR_AGAIN;
  }

  kdf_ctx = kdf->ctx;
  alg = kdf->alg;

  buf_len = kdf->saltlen + 16 + additional_data_len;
  if (!(buf = zt_malloc(buf_len)))
    return ERR_MEM_FAIL;

  pbuf = buf;
  zt_memcpy(pbuf, kdf->salt, kdf->saltlen);
  pbuf += kdf->saltlen;
  zt_memcpy(pbuf, kdf->ctr.bytes, 16);
  pbuf += 16;
  if (additional_data_len)
    zt_memcpy(pbuf, additional_data, additional_data_len);

  switch (alg) {
  case KDF_ALG_scrypt:
    rv = _kdf_hlp_scrypt(kdf_ctx, kdf->pw, kdf->pwlen, buf, buf_len, key,
                         key_len);
    break;
  case KDF_ALG_argon2:
    rv = _kdf_hlp_argon2(kdf_ctx, kdf->pw, kdf->pwlen, buf, buf_len, key,
                         key_len);
    break;
  case KDF_ALG_PBKDF2:
    rv = _kdf_hlp_pbkdf2(kdf_ctx, kdf->pw, kdf->pwlen, buf, buf_len, key,
                         key_len);
    break;
  }
  if (rv)
    ret = ERR_INTERNAL;

  /** Increment the counters */
  KDF_CTR_INCR32(kdf, 1);
  kdf->count += key_len;

  /** Cleanup */
  memzero(buf, buf_len);
  zt_free(buf);
  return ret;
}

const kdf_intf_t kdf_intf = {
    .alloc = ossl_kdf_alloc,
    .dealloc = ossl_kdf_dealloc,
    .init = ossl_kdf_init,
    .derive = ossl_kdf_derive,
    .supported_algs = KDF_ALG_scrypt | KDF_ALG_PBKDF2 | KDF_ALG_argon2,
};
