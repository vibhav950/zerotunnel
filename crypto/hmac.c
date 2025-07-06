#include "hmac.h"

const char *hmac_alg_to_string(hmac_alg_t alg) {
  switch (alg) {
  case HMAC_SHA256:
    return "HMAC-SHA256";
  case HMAC_SHA384:
    return "HMAC-SHA384";
  case HMAC_SHA512:
    return "HMAC-SHA512";
  case HMAC_SHA3_256:
    return "HMAC-SHA3-256";
  case HMAC_SHA3_384:
    return "HMAC-SHA3-384";
  case HMAC_SHA3_512:
    return "HMAC-SHA3-512";
  default:
    return "unknown type";
  }
}

int hmac_intf_alg_is_supported(const hmac_intf_t *intf, hmac_alg_t alg) {
  return (intf) && (intf->supported_algs & alg);
}

int hmac_flag_get(hmac_t *h, hmac_flag_t flag) {
  return (h) && (h->flags & flag);
}

size_t hmac_digest_len(hmac_t *h) { return (h) ? h->key_len : 0; }

err_t hmac_intf_alloc(const hmac_intf_t *intf, hmac_t **h, size_t key_len,
                      size_t out_len, hmac_alg_t alg) {
  if (!intf || !intf->alloc || !h)
    return ERR_NULL_PTR;

  return (intf)->alloc(h, key_len, out_len, alg);
}

void hmac_dealloc(hmac_t *h) {
  if (!h || !h->intf)
    return;

  ((h)->intf)->dealloc(h);
}

err_t hmac_init(hmac_t *h, const uint8_t *key, size_t key_len) {
  if (!h || !h->intf)
    return ERR_NULL_PTR;

  return ((h)->intf)->init(h, key, key_len);
}

err_t hmac_update(hmac_t *h, const uint8_t *msg, size_t msg_len) {
  if (!h || !h->intf)
    return ERR_NULL_PTR;

  return ((h)->intf)->update(h, msg, msg_len);
}

err_t hmac_compute(hmac_t *h, const uint8_t *msg, size_t msg_len,
                   uint8_t *digest, size_t digest_len) {
  if (!h || !h->intf)
    return ERR_NULL_PTR;

  return ((h)->intf)->compute(h, msg, msg_len, digest, digest_len);
}
