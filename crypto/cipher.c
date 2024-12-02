#include "cipher.h"

int cipher_alg_is_supported(cipher_t *c, cipher_alg_t alg) {
    return ((c) && (c->intf) && (c->intf->supported_algs & alg));
}

int cipher_flag_get(cipher_t *c, cipher_flag_t flag) {
    return ((c) && (c->flags & flag));
}
