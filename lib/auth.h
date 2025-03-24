#ifndef __AUTH_H__
#define __AUTH_H__

#include <stddef.h>
#include <stdint.h>

/** Length of the password string excluding null terminator */
#define MAX_PASSWD_LEN 256U

#define PASSWD_HASH_LEN 32U

#define AUTHID_LEN_BYTES 16U

typedef int32_t passwd_id_t;

typedef enum {
  AUTHTYPE_NONE,
  KAPPA_AUTHTYPE_0,
  KAPPA_AUTHTYPE_1,
  KAPPA_AUTHTYPE_2
} auth_type_t;

struct passwd {
  passwd_id_t id;
  char *pw;
  size_t pwlen;
};

struct authid {
  union {
    uint8_t bytes[AUTHID_LEN_BYTES];
    uint32_t words[AUTHID_LEN_BYTES/4];
  };
};

passwd_id_t zt_auth_passwd_load(const char *passwddb_file, const char *peer_id,
                                passwd_id_t pwid, char **passwd);

int zt_auth_passwd_delete(const char *passwddb_file, const char *peer_id,
                          passwd_id_t pwid);

struct passwd *zt_auth_passwd_new(const char *passwddb_file,
                                  auth_type_t auth_type, const char *peer_id);

struct passwd *zt_auth_passwd_get(const char *passwddb_file,
                                  auth_type_t auth_type, const char *peer_id,
                                  passwd_id_t pwid);

int zt_auth_passwddb_new(const char *passwddb_file, const char *peer_id,
                         int n_passwords);

void zt_auth_passwd_free(struct passwd *pass, ...);

int zt_get_hostid(struct authid *hostid);

#endif /* __AUTH_H__ */
