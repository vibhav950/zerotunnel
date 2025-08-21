#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Max character length of the password string excluding NULL terminator */
#define MAX_PASSWD_LEN 256U

/** Max number of passwords in a bundle */
#define MAX_BUNDLE_SIZE 90U

/** Length of the password hash in bytes */
#define PASSWD_HASH_LEN 32U

/** Length of the authid in bytes */
#define AUTHID_BYTES_LEN 16U

typedef int32_t passwd_id_t;

typedef enum {
  KAPPA_AUTHTYPE_0,
  KAPPA_AUTHTYPE_1,
  KAPPA_AUTHTYPE_2,
  AUTHTYPE_NONE = 0xff,
} auth_type_t;

struct passwd {
  passwd_id_t id;
  char *pw;
  size_t pwlen;
};

struct authid {
  union {
    uint8_t bytes[AUTHID_BYTES_LEN];
    uint32_t words[AUTHID_BYTES_LEN/4];
  };
};

passwd_id_t zt_auth_passwd_load(const char *passwdfile, const char *peer_id,
                                passwd_id_t pwid, struct passwd **passwd);

int zt_auth_passwd_delete(const char *passwdfile, const char *peer_id,
                          passwd_id_t pwid);

struct passwd *zt_auth_passwd_single_new(unsigned short count, bool phonetic);

passwd_id_t zt_auth_passwd_new(const char *passwdfile, auth_type_t auth_type,
                               const char *peer_id, struct passwd **passwd);

passwd_id_t zt_auth_passwd_get(const char *passwdfile, auth_type_t auth_type,
                               const char *peer_id, passwd_id_t pwid,
                               struct passwd **passwd);

int zt_auth_passwd_db_new(int fd, const char *peer_id,
                          unsigned short password_len,
                          unsigned short n_passwords);

void zt_auth_passwd_free(struct passwd *pass, ...);

int zt_get_hostid(struct authid *hostid);

#endif /* __AUTH_H__ */
