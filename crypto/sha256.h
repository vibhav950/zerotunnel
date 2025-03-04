/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.

 =====================================================================

 CHANGELOG:
 [2-19-25] Modified by vibhav950 (GitHub) for zerotunnel

*********************************************************************/

#pragma once

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32 // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char sha256_char_t;   // 8-bit byte
typedef unsigned int  sha256_word_t;   // 32-bit word, change to "long" for 16-bit machines

typedef struct _sha256_ctx_st {
  sha256_char_t data[64];
  sha256_word_t datalen;
  unsigned long long bitlen;
  sha256_word_t state[8];
} sha256_ctx_t;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const sha256_char_t data[], size_t len);
void sha256_final(sha256_ctx_t *ctx, sha256_char_t hash[]);

/** Built-in KAT self tests */
int sha256_self_test(void);
