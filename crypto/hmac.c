#include "hmac.h"

int hmac_intf_alg_is_supported(const hmac_intf_t *intf, hmac_alg_t alg) {
  return (intf) && (intf->supported_algs & alg);
}

int hmac_flag_get(hmac_t *h, hmac_flag_t flag) {
  return (h) && (h->flags & flag);
}

error_t hmac_intf_alloc(const hmac_intf_t *intf, hmac_t **h, size_t key_len,
                        size_t out_len, hmac_alg_t alg) {
  if (!intf || !intf->alloc || !*h)
    return ERR_NULL_PTR;

  return (intf)->alloc(h, key_len, out_len, alg);
}

void hmac_dealloc(hmac_t *h) {
  if (!h || !h->intf)
    return;

  ((h)->intf)->dealloc(h);
}

error_t hmac_init(hmac_t *h, const uint8_t *key, size_t key_len) {
  if (!h || !h->intf)
    return ERR_NULL_PTR;

  return ((h)->intf)->init(h, key, key_len);
}

error_t hmac_update(hmac_t *h, const uint8_t *msg, size_t msg_len) {
  if (!h || !h->intf)
    return ERR_NULL_PTR;

  return ((h)->intf)->update(h, msg, msg_len);
}

error_t hmac_compute(hmac_t *h, const uint8_t *msg, size_t msg_len,
                     uint8_t *digest, size_t digest_len) {
  if (!h || !h->intf)
    return ERR_NULL_PTR;

  return ((h)->intf)->compute(h, msg, msg_len, digest, digest_len);
}
