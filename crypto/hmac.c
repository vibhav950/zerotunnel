#include "hmac.h"

int hmac_alg_is_supported(hmac_t *h, hmac_alg_t alg) {
    return ((h) && (h->intf) && (h->intf->supported_algs & alg));
}

int hmac_flag_get(hmac_t *h, hmac_flag_t flag) {
    return ((h) && (h->flags & flag));
}
