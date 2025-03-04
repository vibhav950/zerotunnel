#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdint.h>

/** Length of the password string excluding null terminator */
#define MAX_PASSWD_LEN      256U

#define PASSWD_HASH_LEN     32U

typedef int32_t passwd_id_t;

typedef enum {
  auth_0 = 0,
  auth_1 = 1,
  auth_2 = 2
} auth_type_t;

struct passwd {
  passwd_id_t id;
  char       *pw;
};

#endif /* __AUTH_H__ */