#include "hmac.h"

int hmac_alg_is_supported(hmac_t *c, hmac_alg_t alg) {
    return ((c) && (c->alg & alg));
}

int hmac_flag_get(hmac_t *c, hmac_flag_t flag) {
    return ((c) && (c->flags & flag));
}
