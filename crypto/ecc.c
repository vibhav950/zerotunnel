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

int kex_curve_is_supported(kex_t *kex, kex_curve_t curve) {
    return ((kex) && (kex->intf->supported_curves & curve));
}

int kex_flag_get(kex_t *kex, kex_flag_t flag) {
    return ((kex) && (kex->flags & flag));
}
