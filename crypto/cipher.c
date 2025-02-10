#include "cipher.h"
#include "common/zerotunnel.h"

const char *cipher_alg_to_string(cipher_alg_t alg) {
  switch (alg) {
  case CIPHER_AES_GCM_128:
    return "AES-128-GCM";
  case CIPHER_AES_GCM_192:
    return "AES-192-GCM";
  case CIPHER_AES_GCM_256:
    return "AES-256-GCM";
  case CIPHER_CHACHA20_POLY1305:
    return "CHACHA20-POLY1305";
  default:
    return "unknown type";
  }
}

int cipher_intf_alg_is_supported(const cipher_intf_t *intf, cipher_alg_t alg) {
  return (intf) && (intf->supported_algs & alg);
}

int cipher_flag_get(cipher_t *c, cipher_flag_t flag) {
  return (c) && (c->flags & flag);
}

error_t cipher_intf_alloc(const cipher_intf_t *intf, cipher_t **c,
                          size_t key_len, size_t tag_len, cipher_alg_t alg) {
  if (!intf || !intf->alloc || !c)
    return ERR_NULL_PTR;

  return (intf)->alloc(c, key_len, tag_len, alg);
}

void cipher_dealloc(cipher_t *c) {
  if (!c || !c->intf)
    return;

  ((c)->intf)->dealloc(c);
}

error_t cipher_init(cipher_t *c, const uint8_t *key, size_t key_len,
                    cipher_operation_t oper) {
  if (!c || !c->intf)
    return ERR_NULL_PTR;

  return ((c)->intf)->init(c, key, key_len, oper);
}

error_t cipher_set_iv(cipher_t *c, const uint8_t *iv, size_t iv_len) {
  if (!c || !c->intf)
    return ERR_NULL_PTR;

  return ((c)->intf)->set_iv(c, iv, iv_len);
}

error_t cipher_set_aad(cipher_t *c, const uint8_t *aad, size_t aad_len) {
  if (!c || !c->intf)
    return ERR_NULL_PTR;

  return ((c)->intf)->set_aad(c, aad, aad_len);
}

error_t cipher_encrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len) {
  if (!c || !c->intf)
    return ERR_NULL_PTR;

  return ((c)->intf)->encrypt(c, in, in_len, out, out_len);
}

error_t cipher_decrypt(cipher_t *c, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len) {
  if (!c || !c->intf)
    return ERR_NULL_PTR;

  return ((c)->intf)->decrypt(c, in, in_len, out, out_len);
}
