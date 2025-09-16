/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * memzero.c
 */

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void memzero(void *ptr, size_t len) {
#if defined(_WIN32) && defined(_MSC_VER)
  /* Win32 provides SecureZeroMemory which won't be optimized away. */
  SecureZeroMemory(ptr, len);
#else
  memset(ptr, 0, len);

  /* Memory barrier to prevent the compiler from optimizing away the memset.
   *
   * The Linux kernel uses this method for its memzero_explicit(), and this
   * barrier is effective for both GCC and Clang.
   *
   * For more information, see
   * https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-yang.pdf
   */
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif // defined(_WIN32)
}
