/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2026 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * spin.h - Spinlock utils
 */

#ifndef __SPIN_H__
#define __SPIN_H__
#pragma once

#if defined(_WIN32)
#include <Windows.h> // SwitchToThread(), Sleep()
#include <intrin.h>  // _mm_pause()
#else                /* Linux, OSX, BSD; all have this header */
#include <sched.h>   // sched_yield()
#endif

#if ((defined(__GNUC__) && !defined(__clang__)) &&                                       \
     (defined(__i386__) || defined(__x86_64__))) ||                                      \
    (defined(__has_builtin) && __has_builtin(__builtin_ia32_pause))
#define spin_pause() __builtin_ia32_pause()
#elif defined(__x86_64__) || defined(__i386__) || defined(__amd64__) ||                  \
    defined(_M_X64) || defined(_M_IX86)
#if defined(_MSC_VER)
// FIXME: better way to do this on MSVC without pulling <intrin.h>?
#define spin_pause() _mm_pause()
#else
#define spin_pause()                                                                     \
  do {                                                                                   \
    __asm__ volatile("pause");                                                           \
    __asm__ volatile("" ::: "memory");                                                   \
  } while (0)
#endif
#else
#error "unknown platform"
#endif

/**
 * spin_yield()
 * @brief Attempt to make this thread relinquish the processor
 *
 * - On Linux, `sched_yield()` always succeeds so there is nothing we can do
 *   instead if there are no other threads waiting on the current processor
 *
 * - On Windows, we sleep for 1ms to try saving power if execution is not
 *   switched to another thread
 */

#if defined(_WIN32)
#define spin_yield()                                                                     \
  do {                                                                                   \
    if (SwitchToThread() == 0)                                                           \
      Sleep(1);                                                                          \
  } while (0)
#else
#define spin_yield() sched_yield()
#endif

/**
 * decaying_sleep(pause, pause32)
 * @brief Sleep with an exponential/multiplicative backoff
 *
 * This macro is a little misleading in that it doesn't always actually "sleep".
 * Instead, it gradually shifts from short (less) pauses to longer (more) pauses
 * to finally `yield`ing the processor on each spin. In theory this should
 * adjust the busy-wait for both short and long waiting periods, where the
 * thread doesn't steal and burn resources from other threads waiting on the
 * same processor.
 *
 * Reference: https://github.com/gstrauss/plasma/blob/master/plasma_spin.c
 */
#define decaying_sleep(pause, pause32)                                                   \
  do {                                                                                   \
    if (likely(pause)) {                                                                 \
      spin_pause();                                                                      \
      pause--;                                                                           \
    } else if (likely(pause32)) {                                                        \
      int i = 4;                                                                         \
      do {                                                                               \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
        spin_pause();                                                                    \
      } while (--i);                                                                     \
      pause32--;                                                                         \
    } else {                                                                             \
      spin_yield();                                                                      \
    }                                                                                    \
  } while (0)

#endif /* __SPIN_H__ */
