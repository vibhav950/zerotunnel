/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * b64.h - Base64 encoding/decoding utilities
 */

#ifndef __B64_H__
#define __B64_H__

int zt_b64_encode(const char *src, int srclen, char **dst, int *dstlen);

int zt_b64_decode(const char *src, int srclen, char **dst, int *dstlen);

int zt_b64_urlencode(const char *src, int srclen, char **dst, int *dstlen);

int zt_b64_urldecode(const char *src, int srclen, char **dst, int *dstlen);

#endif /** __B64_H__ */