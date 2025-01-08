#include "kex.h"

const char *kex_curve_name(int id) {
  switch (id) {
  case KEX_CURVE_secp256k1:
    return "secp256k1";
  case KEX_CURVE_secp384r1:
    return "secp384r1";
  case KEX_CURVE_secp521r1:
    return "secp521r1";
  case KEX_CURVE_prime239v3:
    return "prime239v3";
  case KEX_CURVE_prime256v1:
    return "prime256v1";
  default:
    return "unknown";
  }
}

int kex_intf_curve_is_supported(const kex_intf_t *intf, kex_curve_t curve) {
  return (intf) && (intf->supported_curves & curve);
}

int kex_flag_get(kex_t *kex, kex_flag_t flag) {
  return (kex) && (kex->flags & flag);
}

error_t kex_intf_alloc(const kex_intf_t *intf, kex_t **kex, kex_curve_t curve) {
  if (!intf || !intf->alloc || !*kex)
    return ERR_NULL_PTR;

  return (intf)->alloc(kex, curve);
}

error_t kex_dealloc(kex_t *kex) {
  if (!kex || !kex->intf)
    return ERR_NULL_PTR;

  return ((kex)->intf)->dealloc(kex);
}

error_t kex_key_gen(kex_t *kex) {
  if (!kex || !kex->intf)
    return ERR_NULL_PTR;

  return ((kex)->intf)->key_gen(kex);
}

error_t kex_get_peer_data(kex_t *kex, kex_peer_share_t *peer_data,
                          const unsigned char *authkey, size_t authkey_len) {
  if (!kex || !kex->intf)
    return ERR_NULL_PTR;

  return ((kex)->intf)->get_peer_data(kex, peer_data, authkey, authkey_len);
}

void kex_free_peer_data(kex_t *kex, kex_peer_share_t *peer_data) {
  if (!kex || !kex->intf)
    return;

  ((kex)->intf)->free_peer_data(peer_data);
}

error_t kex_derive_shared_key(kex_t *kex, kex_peer_share_t *peer_data,
                              const unsigned char *authkey, size_t authkey_len,
                              unsigned char **shared_key,
                              size_t *shared_key_len) {
  if (!kex || !kex->intf)
    return ERR_NULL_PTR;

  return ((kex)->intf)->derive_shared_key(kex, peer_data, authkey, authkey_len, shared_key, shared_key_len);
}
