/**
 * b64.c - RFC 4648 Base-64 encoding and decoding
 *
 * Based on https://github.com/torvalds/linux/blob/master/lib/base64.c
 *
 * =================================================================
 *
 * // SPDX-License-Identifier: GPL-2.0
 *
 * base64.c - RFC4648-compliant base64 encoding
 *
 * Copyright (c) 2020 Hannes Reinecke, SUSE
 *
 * Based on the base64url routines from fs/crypto/fname.c
 * (which are using the URL-safe base64 encoding),
 * modified to use the standard coding table from RFC4648 section 4.
 *
 * =================================================================
 *
 * CHANGELOG:
 * [2-19-25] Modified by vibhav950 for zerotunnel
 */

#include "b64.h"
#include "common/defines.h"

#include <string.h>

/** Base-64 encoding/decoding table */
static const char b64unsafe[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/** Base-64 encoding with a URL and filename safe alphabet, RFC 4648 */
static const char b64urlsafe[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * base64_encode() - base64-encode some binary data
 * @table: the base64 encoding table to use
 * @src: the binary data to encode
 * @srclen: the length of @src in bytes
 * @dst: (output) the base64-encoded string.  Not NUL-terminated.
 *
 * Encodes data using base64 encoding, i.e. the "Base 64 Encoding" specified
 * by RFC 4648, including the  '='-padding.
 *
 * Return: the length of the resulting base64-encoded string in bytes.
 */
static inline int base64_encode(const char *table, const uint8_t *src,
                                int srclen, char *dst) {
  uint32_t ac = 0;
  int bits = 0;
  size_t i;
  char *cp = dst;

  for (i = 0; i < srclen; i++) {
    ac = (ac << 8) | src[i];
    bits += 8;
    do {
      bits -= 6;
      *cp++ = table[(ac >> bits) & 0x3f];
    } while (bits >= 6);
  }
  if (bits) {
    *cp++ = table[(ac << (6 - bits)) & 0x3f];
    bits -= 6;
  }
  while (bits < 0) {
    *cp++ = '=';
    bits += 2;
  }
  return cp - dst;
}

/**
 * base64_decode() - base64-decode a string
 * @table: the base64 encoding table to use
 * @src: the string to decode.  Doesn't need to be NUL-terminated.
 * @srclen: the length of @src in bytes
 * @dst: (output) the decoded binary data
 *
 * Decodes a string using base64 encoding, i.e. the "Base 64 Encoding"
 * specified by RFC 4648, including the  '='-padding.
 *
 * This implementation hasn't been optimized for performance.
 *
 * Return: the length of the resulting decoded binary data in bytes,
 *	   or -1 if the string isn't a valid base64 string.
 */
static inline int base64_decode(const char *table, const char *src, int srclen,
                                uint8_t *dst) {
  uint32_t ac = 0;
  int bits = 0;
  size_t i;
  uint8_t *bp = dst;

  for (i = 0; i < srclen; i++) {
    const char *p = strchr(table, src[i]);

    if (src[i] == '=') {
      ac = (ac << 6);
      bits += 6;
      if (bits >= 8)
        bits -= 8;
      continue;
    }
    if (p == NULL || src[i] == 0)
      return -1;
    ac = (ac << 6) | (p - table);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      *bp++ = (uint8_t)(ac >> bits);
    }
  }
  if (ac & ((1 << bits) - 1))
    return -1;
  return bp - dst;
}

/**
 * Encode data to base-64 and place the result in a newly allocated buffer. The
 * output string is NUL-terminated
 *
 * Note: you must zt_free() the output buffer when you are done with it
 *
 * @param src: the data or NUL-terminated string to be encoded
 * @param srclen: the length of the input data (for strings use strlen()). If
 * zero, the length is calculated using strlen()
 * @param dst: pointer to pointer to the output buffer that the base-64 encoded
 * string is placed in
 * @param dstlen: the length of allocated buffer at least equal to the length of
 * the encoded string (including the NUL-terminator)
 *
 * @return The actual length of the encoded string, or -1 on error
 */
int zt_b64_encode(const char *src, int srclen, char **dst, int *dstlen) {
  if (!src || !dst || !dstlen)
    return -1;

  if (!srclen)
    srclen = strlen(src);

  *dstlen = ((srclen + 2) / 3) * 4 + 1;
  if (!(*dst = zt_malloc(*dstlen)))
    return -1;

  (*dst)[*dstlen - 1] = '\0';

  return base64_encode(b64unsafe, PTR8(src), srclen, PTR8(*dst));
}

/**
 * Decode a base-64 encoded string and place the result in a newly allocated
 * buffer. The output string is NUL-terminated
 *
 * Note: you must zt_free() the output buffer when you are done with it
 *
 * @param src: the base-64 encoded string
 * @param srclen: the length of the input data (for strings use strlen()). If
 * zero, the length is calculated using strlen()
 * @param dst: pointer to pointer to the output buffer that the decoded string
 * is placed in
 * @param dstlen: the length of allocated buffer at least equal to the length of
 * the decoded string
 *
 * @return The actual length of the decoded string, or -1 on error
 */
int zt_b64_decode(const char *src, int srclen, char **dst, int *dstlen) {
  if (!src || !dst || !dstlen)
    return -1;

  if (!srclen)
    srclen = strlen(src);

  *dstlen = (srclen / 4) * 3 + 1;
  if (!(*dst = zt_malloc(*dstlen)))
    return -1;

  (*dst)[*dstlen - 1] = '\0';

  return base64_decode(b64unsafe, src, srclen, PTR8(*dst));
}

/**
 * Encode data to an RFC 4648 URL-safe base-64 string and place the result in a
 * newly allocated buffer. The output string is NUL-terminated
 *
 * Note: you must zt_free() the output buffer when you are done with it
 *
 * @param src: the data or NUL-terminated string to be encoded
 * @param srclen: the length of the input data (for strings use strlen())
 * @param dst: pointer to pointer to the output buffer that the base-64 encoded
 * string is placed in
 * @param dstlen: the length of allocated buffer at least equal to the length of
 * the encoded string (including the NUL-terminator)
 *
 * @return The actual length of the encoded string
 */
int zt_b64_urlencode(const char *src, int srclen, char **dst, int *dstlen) {
  if (!src || !dst || !dstlen)
    return -1;

  if (!srclen)
    srclen = strlen(src);

  *dstlen = ((srclen + 2) / 3) * 4 + 1;
  if (!(*dst = zt_malloc(*dstlen)))
    return -1;

  (*dst)[*dstlen - 1] = '\0';

  return base64_encode(b64urlsafe, PTR8(src), srclen, PTR8(*dst));
}

/**
 * Decode an RFC 4648 URL-safe base-64 encoded string and place the result in a
 * newly allocated buffer. The output string is NUL-terminated
 *
 * Note: you must zt_free() the output buffer when you are done with it
 *
 * @param src: the base-64 encoded string
 * @param srclen: the length of the input data (for strings use strlen())
 * @param dst: pointer to pointer to the output buffer that the decoded string
 * is placed in
 * @param dstlen: the length of allocated buffer at least equal to the length of
 * the decoded string
 *
 * @return the actual length of the decoded string, or -1 on error
 */
int zt_b64_urldecode(const char *src, int srclen, char **dst, int *dstlen) {
  if (!src || !dst || !dstlen)
    return -1;

  if (!srclen)
    srclen = strlen(src);

  *dstlen = (srclen / 4) * 3 + 1;
  if (!(*dst = zt_malloc(*dstlen)))
    return -1;

  (*dst)[*dstlen - 1] = '\0';

  return base64_decode(b64urlsafe, src, srclen, PTR8(*dst));
}
