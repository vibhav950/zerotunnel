/**
 * ML-KEM (Kyber) using liboqs.
 */

#include "common/defines.h"
#include "common/log.h"
#include "kem.h"
#include "kem_kyber_defs.h"

#include <oqs/oqs.h>

#define KEM_FLAG_SET(kem, flag) ((void)((kem)->flags |= flag))
#define KEM_FLAG_GET(kem, flag) ((kem)->flags & flag)

/**
 * NOTES
 *
 * The memory allocated for the public key, ciphertext, and shared secret in the
 * liboqs_kem_* functions must be freed by calling liboqs_kem_mem_free after
 * use.
 *
 * Agreement on the KEM algorithm (512, 768, 1024) must be taken care of by the
 * higher level protocol (i.e., the caller). The KEM algorithm must be
 * consistent on both parties for a session instance, either by negotiation or
 * by configuration.
 */

/**
 *
 */
static err_t liboqs_kem_alloc(kem_t **kem, kem_alg_t alg) {
  extern const kem_intf_t kem_kyber_intf;
  kem_oqs_ctx *oqs_ctx;
  OQS_KEM *oqs_kem;
  uint8_t *privkey;

  log_debug(NULL, "alg=%s", kem_alg_to_string(alg));

  switch (alg) {
  case KEM_Kyber_512:
    oqs_kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    break;
  case KEM_Kyber_768:
    oqs_kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    break;
  case KEM_Kyber_1024:
    oqs_kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    break;
  default:
    return ERR_BAD_ARGS;
  }
  if (!oqs_kem)
    return ERR_INTERNAL;

  if (!(*kem = zt_calloc(1, sizeof(kem_t))))
    return ERR_MEM_FAIL;

  if (!(oqs_ctx = zt_calloc(1, sizeof(kem_oqs_ctx)))) {
    zt_free(*kem);
    *kem = NULL;
    return ERR_MEM_FAIL;
  }
  oqs_ctx->kem = oqs_kem;

  (*kem)->intf = &kem_kyber_intf;
  (*kem)->ctx = oqs_ctx;
  (*kem)->alg = alg;
  KEM_FLAG_SET(*kem, KEM_FLAG_ALLOC);

  return ERR_SUCCESS;
}

/**
 *
 */
static void liboqs_kem_dealloc(kem_t *kem) {
  log_debug(NULL, "");

  if (KEM_FLAG_GET(kem, KEM_FLAG_ALLOC)) {
    kem_oqs_ctx *oqs_ctx = (kem_oqs_ctx *)kem->ctx;

    if (oqs_ctx) {
      OQS_KEM_free(oqs_ctx->kem);
      memzero(oqs_ctx, sizeof(kem_oqs_ctx));
      zt_free(oqs_ctx);
    }
  }

  if (KEM_FLAG_GET(kem, KEM_FLAG_KEYGEN))
    OQS_MEM_secure_free(kem->privkey, kem->privkey_len);

  memzero(kem, sizeof(kem_t));
  zt_free(kem);
}

/**
 *
 */
static void liboqs_kem_mem_free(void *ptr, size_t len) {
  log_debug(NULL, "");

  OQS_MEM_secure_free(ptr, len);
}

/**
 *
 */
static err_t liboqs_kem_keypair_gen(kem_t *kem, uint8_t **pubkey,
                                    size_t *pubkey_len) {
  kem_oqs_ctx *oqs_ctx;
  OQS_KEM *oqs_kem;
  uint8_t *privkey;

  log_debug(NULL, "");

  if (!pubkey || !pubkey_len)
    return ERR_NULL_PTR;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  oqs_ctx = (kem_oqs_ctx *)kem->ctx;
  oqs_kem = oqs_ctx->kem;

  *pubkey_len = 0;
  if (!(*pubkey = OQS_MEM_malloc(oqs_kem->length_public_key)))
    return ERR_MEM_FAIL;
  *pubkey_len = oqs_kem->length_public_key;

  if (!(privkey = OQS_MEM_malloc(oqs_kem->length_secret_key))) {
    OQS_MEM_secure_free(*pubkey, *pubkey_len);
    *pubkey = NULL;
    *pubkey_len = 0;
    return ERR_MEM_FAIL;
  }

  if (OQS_KEM_keypair(oqs_kem, *pubkey, privkey) != OQS_SUCCESS) {
    OQS_MEM_secure_free(*pubkey, *pubkey_len);
    OQS_MEM_secure_free(privkey, oqs_kem->length_secret_key);
    *pubkey = NULL;
    *pubkey_len = 0;
    return ERR_INTERNAL;
  }
  kem->privkey = privkey;
  kem->privkey_len = oqs_kem->length_secret_key;
  KEM_FLAG_SET(kem, KEM_FLAG_KEYGEN);

  return ERR_SUCCESS;
}

/**
 *
 */
static err_t liboqs_kem_encapsulate(kem_t *kem, const uint8_t *peer_pubkey,
                                    size_t peer_pubkey_len, uint8_t **ct,
                                    size_t *ct_len, uint8_t **ss,
                                    size_t *ss_len) {
  kem_oqs_ctx *oqs_ctx;
  OQS_KEM *oqs_kem;
  kem_alg_t alg;

  log_debug(NULL, "peer_pubkey_len=%zu", peer_pubkey_len);

  if (!peer_pubkey || !ct || !ct_len || !ss || !ss_len)
    return ERR_NULL_PTR;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  oqs_ctx = (kem_oqs_ctx *)kem->ctx;
  alg = kem->alg;
  oqs_kem = oqs_ctx->kem;

  switch (alg) {
  case KEM_Kyber_512:
    if (peer_pubkey_len != KEM_KYBER_512_PUBKEY_SIZE)
      return ERR_BAD_ARGS;
    break;
  case KEM_Kyber_768:
    if (peer_pubkey_len != KEM_KYBER_768_PUBKEY_SIZE)
      return ERR_BAD_ARGS;
    break;
  case KEM_Kyber_1024:
    if (peer_pubkey_len != KEM_KYBER_1024_PUBKEY_SIZE)
      return ERR_BAD_ARGS;
    break;
  }

  *ct_len = 0;
  if (!(*ct = OQS_MEM_malloc(oqs_kem->length_ciphertext)))
    return ERR_MEM_FAIL;
  *ct_len = oqs_kem->length_ciphertext;

  *ss_len = 0;
  if (!(*ss = OQS_MEM_malloc(oqs_kem->length_shared_secret))) {
    OQS_MEM_secure_free(*ct, *ct_len);
    *ct = NULL;
    *ct_len = 0;
    return ERR_MEM_FAIL;
  }
  *ss_len = oqs_kem->length_shared_secret;

  if (OQS_KEM_encaps(oqs_kem, *ct, *ss, peer_pubkey) != OQS_SUCCESS) {
    OQS_MEM_secure_free(*ct, *ct_len);
    OQS_MEM_secure_free(*ss, *ss_len);
    *ct = *ss = NULL;
    *ct_len = *ss_len = 0;
    return ERR_INTERNAL;
  }

  return ERR_SUCCESS;
}

/**
 *
 */
static err_t liboqs_kem_decapsulate(kem_t *kem, const uint8_t *ct,
                                    size_t ct_len, uint8_t **ss,
                                    size_t *ss_len) {
  kem_oqs_ctx *oqs_ctx;
  OQS_KEM *oqs_kem;

  log_debug(NULL, "ct_len=%zu", ct_len);

  if (!ct || !ss || !ss_len)
    return ERR_NULL_PTR;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_ALLOC))
    return ERR_NOT_ALLOC;

  if (!KEM_FLAG_GET(kem, KEM_FLAG_KEYGEN))
    return ERR_NOT_INIT;

  oqs_ctx = (kem_oqs_ctx *)kem->ctx;
  oqs_kem = oqs_ctx->kem;

  *ss_len = 0;
  if (!(*ss = OQS_MEM_malloc(oqs_kem->length_shared_secret)))
    return ERR_MEM_FAIL;
  *ss_len = oqs_kem->length_shared_secret;

  if (OQS_KEM_decaps(oqs_kem, *ss, ct, kem->privkey) != OQS_SUCCESS) {
    OQS_MEM_secure_free(*ss, *ss_len);
    *ss = NULL;
    *ss_len = 0;
    return ERR_INTERNAL;
  }

  return ERR_SUCCESS;
}

const kem_intf_t kem_kyber_intf = {
    .alloc = liboqs_kem_alloc,
    .dealloc = liboqs_kem_dealloc,
    .mem_free = liboqs_kem_mem_free,
    .keygen = liboqs_kem_keypair_gen,
    .encapsulate = liboqs_kem_encapsulate,
    .decapsulate = liboqs_kem_decapsulate,
    .supported_algs = KEM_Kyber_512 | KEM_Kyber_768 | KEM_Kyber_1024,
};
