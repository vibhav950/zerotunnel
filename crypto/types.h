#ifndef __CIPHER_TYPES_H__
#define __CIPHER_TYPES_H__

#include "cipher.h"
#include "hmac.h"
#include "kdf.h"
#include "kem.h"
#include "kex.h"

extern const cipher_intf_t aead_intf;

extern const hmac_intf_t hmac_intf;

extern const kex_intf_t kex_ecc_intf;

extern const kdf_intf_t kdf_intf;

extern const kem_intf_t kem_kyber_intf;

#endif /* __CIPHER_TYPES_H__ */
