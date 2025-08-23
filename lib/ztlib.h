#pragma once

#include "auth.h"
#include "client.h"
#include "common/defines.h"

#include <stdbool.h>

// clang-format off
struct config {
  char            
    *hostname,                  /* peer hostname -- can be a FQDN or IP address */
    *passwdfile,                /* location of the password database file */
    *ciphersuite,               /* ciphersuite cannonical name or alias */
    *filepath,                  /* complete target file path */
    *passwdBundleId;            /* bundle identifier for KAPPA1 auth type */
  uint32_t
    paddingFactor;              /* padding factor of the form: 2^n; 1<=n<=16 */
  uint16_t
    servicePort;                /* explicit service port number */
  char
    preferredFamily;            /* preferred address family: '4' for IPv4, '6' for IPv6 */
  long
    maxFileRecvSize;            /* maximum number of bytes to receive on an incoming transfer */
  int
    passwordBundleSize,         /* number of passwords in a bundle */
    passwordChars,              /* number of UTF-8 chars in a password */
    passwordWords;              /* number of words in a phonetic password */
  int
    connectTimeout,             /* timeout for connection phase (>0 ms) */
    idleTimeout,                /* timeout for server being idle (>0 ms) */
    recvTimeout,                /* timeout for receiving data (>0 ms) */
    sendTimeout;                /* timeout for sending data (>0 ms) */
  auth_type_t
    authType;                   /* KAPPA authentication type */
  char
    flagExplicitPort,           /* use an explicit service port */
    flagIPv4Only,               /* use IPv4 only */
    flagIPv6Only,               /* use IPv6 only */
    flagLengthObfuscation,      /* enable length obfuscation */
    flagLiveRead,               /* enable live read */
    flagLZ4Compression,         /* enable LZ4 compression */
    flagTCPFastOpen,            /* enable TCP_FASTOPEN */
    flagTCPNoDelay;             /* enable TCP_NODELAY */
};

/** Global configuration options for use within the library */
extern struct config GlobalConfig;
