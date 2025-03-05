#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Encode the binary data \p src of length \p len into a hex string and place
 * it into a NUL-terminated string \p dst. The length of the hex string without
 * the NUL terminator is returned. Memory for the buffer is allocated implicitly
 * and must be zt_free()'d after use.
 */
size_t zt_hex_encode(const uint8_t *src, size_t len, uint8_t **dst);

/**
 * Decode the hex string \p src of length \p len into binary data and place
 * it into \p dst. The length of the binary data is returned. Memory for the
 * buffer is allocated implicitly and must be zt_free()'d after use.
 */
size_t zt_hex_decode(const uint8_t *src, size_t len, uint8_t **dst);
