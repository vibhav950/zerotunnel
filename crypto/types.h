#ifndef __CIPHER_TYPES_H__
#define __CIPHER_TYPES_H__

#include "cipher.h"
#include "hmac.h"
#include "kex.h"

extern const cipher_intf_t aes_gcm_intf;

extern const hmac_intf_t hmac_intf;

extern const kex_intf_t kex_ecc_intf;

#endif /* __CIPHER_TYPES_H__ */
