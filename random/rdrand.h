/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * rdrand.h
 */

#include <stdint.h>

/**
 * Get 16-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
int rdrand16_step(uint16_t *therand);

int rdseed16_step(uint16_t *therand);

/**
 * Get 32-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
int rdrand32_step(uint32_t *therand);

int rdseed32_step(uint32_t *therand);

/**
 * Get 64-bit random number using RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
int rdrand64_step(uint64_t *therand);

int rdseed64_step(uint64_t *therand);
