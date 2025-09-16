/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * x86_cpuid.h - x86 CPU feature detection
 */

#pragma once
#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

typedef struct _x86_cpuid_features_st {
  int fl_cpu_Intel  : 1;
  int fl_cpu_AMD    : 1;
  int fl_AVX        : 1;
  int fl_AVX2       : 1;
  int fl_SSE        : 1;
  int fl_SSE2       : 1;
  int fl_SSE3       : 1;
  int fl_SSE4_1     : 1;
  int fl_SSE4_2     : 1;
  int fl_SSSE3      : 1;
  int fl_AES        : 1;
  int fl_SHA        : 1;
  int fl_RDSEED     : 1;
  int fl_RDRAND     : 1;
} x86_cpuid_features_t;

extern volatile x86_cpuid_features_t x86_cpuid_features;

/** Called once at program entry */
void DetectX86CPUFeatures(void);

void DisableCPUExtendedFeatures(void);

#define IsIntel()     x86_cpuid_features.fl_cpu_Intel
#define IsAMD()       x86_cpuid_features.fl_cpu_AMD

#define HasSSE()      x86_cpuid_features.fl_SSE
#define HasSSE2()     x86_cpuid_features.fl_SSE2
#define HasSSE3()     x86_cpuid_features.fl_SSE3
#define HasSSE4_1()   x86_cpuid_features.fl_SSE4_1
#define HasSSE4_2()   x86_cpuid_features.fl_SSE4_2
#define HasSSSE3()    x86_cpuid_features.fl_SSSE3
#define HasAVX()      x86_cpuid_features.fl_AVX
#define HasAVX2()     x86_cpuid_features.fl_AVX2
#define HasAES()      x86_cpuid_features.fl_AES
#define HasSHA()      x86_cpuid_features.fl_SHA
#define HasRDSEED()   x86_cpuid_features.fl_RDSEED
#define HasRDRAND()   x86_cpuid_features.fl_RDRAND

#endif /* __X86_CPUID_H__ */
