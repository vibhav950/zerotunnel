#include "auth.h"
#include "common/b64.h"
#include "common/defines.h"
#include "common/hex.h"
#include "common/memzero.h"
#include "crypto/sha256.h"
#include "ztlib.h"

// #include "common/map.h"

#include <assert.h>
#include <bsd/readpassphrase.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// static const char *auth_passwd_prompt(const char *prompt,
//                                       int flags ATTRIBUTE_UNUSED) {
//   int rppflags;
//   char buf[MAX_PASSWD_LEN + 1], *ret;

//   assert(prompt != NULL);

//   rppflags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;
//   if (readpassphrase(prompt, buf, sizeof(buf), rppflags) == NULL) {
//     PRINTERROR("readpassphrase(3) failed");
//     return NULL;
//   }

//   ret = zt_strdup(buf);
//   memzero(buf, sizeof(buf));
//   return ret;
// }

// struct passwd *zt_auth_get_passwd(auth_type_t auth_type, const char *peer_id,
//                                   const char *passwddb_file) {
//   int rv;
//   passwd_id_t id = -1;
//   char *pw;
//   struct passwd *passwd;

//   assert(peer_id != NULL);

//   if (!(passwd = zt_malloc(sizeof(struct passwd))))
//     return NULL;

//   switch (auth_type) {
//   case auth_0:
//     if (!(pw = auth_passwd_prompt("Enter password: ", 0)))
//       return NULL;
//     break;
//   case auth_1:
//     if (auth_load_passwd_db(peer_id, &id, pw, passwddb_file) < 0) {
//       PRINTERROR("Found no matching password entries for %s", peer_id);
//       return NULL;
//     }
//     break;
//   case auth_2:
//     break;
//   }

//   passwd->id = id;
//   passwd->pw = pw;
//   return passwd;
// }

static inline ssize_t line_read_hex(const char *linep, const char *prefix,
                                    char buf[1025]) {
  char *line = (char *)linep;
  ssize_t len = 0;

  while (isspace((unsigned char)*line))
    line++;

  if (prefix && *prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) != 0)
      return -1; // prefix not found
    line += prefix_len;
  }

  while (*line && *line != '\r' && *line != '\n' &&
         len < 1024) { // reserve 1 byte for the null terminator
    if (!isxdigit((unsigned char)*line))
      return -1; // invalid hex character

    buf[len++] = *line++;
  }

  buf[len] = '\0';
  return len;
}

static inline ssize_t line_read_decode_b64(const char *linep,
                                           const char *prefix, char **buf,
                                           ssize_t *enc_len) {
  int len;
  ssize_t elen;
  char *line = (char *)linep;

  while (isspace((unsigned char)*line))
    line++;

  if (prefix && *prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) != 0)
      return -1; // prefix not found
    line += prefix_len;
  }

  if (!line || !*line)
    return -1;

  for (linep = (char *)line, elen = 0;
       *linep && *linep != '\r' && *linep != '\n'; linep++, elen++)
    ;
  if (enc_len)
    *enc_len = elen;
  return (ssize_t)zt_b64_decode(line, elen, buf, &len);
}

static inline int line_read_uint(const char *line, uint32_t *val,
                                 const char *fmt) {
  return (sscanf(line, fmt, val) != 1) ? -1 : 1;
}

static ssize_t auth_sha256_idhash(const char *peer_id, uint8_t **idhash) {
  ssize_t len;
  sha256_char_t hashbuf[SHA256_BLOCK_SIZE];
  sha256_ctx_t sha256;

  assert(peer_id != NULL);

  sha256_init(&sha256);
  sha256_update(&sha256, peer_id, strlen(peer_id));
  sha256_final(&sha256, hashbuf);

  len = zt_hex_encode(hashbuf, SHA256_BLOCK_SIZE, idhash);
  return len ? (ssize_t)len : -1;
}

passwd_id_t auth_passwd_load(const char *passwddb_file, const char *peer_id,
                             passwd_id_t pwid, char **passwd) {
  int fd;
  FILE *fp;
  struct flock fl;
  char *buf = NULL, *linep, *linep_save;
  uint8_t *idhash;
  uint8_t bufx1[1024 + 1] = {0};
  size_t bufsize = 0;
  ssize_t nread, pwlen;
  passwd_id_t pwid_cmp;
  bool found = false;

  assert(passwddb_file != NULL);
  assert(peer_id != NULL);

  if ((fd = open(passwddb_file, O_RDWR)) < 0) {
    PRINTERROR("open: could not open %s (%s)", passwddb_file, strerror(errno));
    return -1;
  }

  if ((fp = fdopen(fd, "r+")) == NULL) {
    PRINTERROR("fdopen: could not open %s (%s)", passwddb_file,
               strerror(errno));
    close(fd);
    return -1;
  }

  /** Put a write lock on this file which is held till this function returns */
  fl.l_type = F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0;
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    PRINTERROR("fnctl: failed to acquire x-lock on %s (%s)", passwddb_file,
               strerror(errno));
    fclose(fp);
    close(fd);
    return -1;
  }

  if (auth_sha256_idhash(peer_id, &idhash) < 0)
    goto cleanup;

  *passwd = NULL;
  while ((nread = getline(&buf, &bufsize, fp)) != -1) {
    // enforce a max length on the line size
    // so that we don't read outside the buf
    if (nread > 1018)
      continue;
    linep = buf;

    while (isspace(*linep))
      linep++;

    if (!*linep || *linep == '#')
      continue; // skip empty and comment lines

    // strip trailing newline characters
    char *end = buf + nread - 1;
    while (end > buf && (*end == '\n' || *end == '\r'))
      *end-- = '\0';

    // read "::<idhash>"
    if (*linep && !found) {
      if (line_read_hex(linep, "::", bufx1) !=
          SHA256_BLOCK_SIZE * 2 /* hex chars */) {
        continue;
      }

      if (zt_strcmp(bufx1, idhash) != 0)
        continue;
      found = true;

      linep += SHA256_BLOCK_SIZE * 2 + 2;
    }

    // read ":<pwid>:<'x'/' '>:<pw>:"
    if (*linep) {
      if (line_read_uint(linep, &pwid_cmp, ":%u:") < 0)
        continue;
      *linep++;

      if ((pwid != -1) && (pwid_cmp != pwid))
        continue;

      char *marker_pos = strchr(linep, ':');
      if (!marker_pos || *(marker_pos + 1) != ' ' || *(marker_pos + 2) != ':')
        continue; // skip passwords marked used

      // position after the "x" or " " marker
      linep_save = marker_pos + 2;

      char *pw_start = strchr(linep_save, ':');
      if (!pw_start)
        continue;

      char *bufx2;
      if ((pwlen = line_read_decode_b64(pw_start, ":", &bufx2, NULL)) < 0) {
        free(bufx2);
        continue;
      }

      *passwd = zt_strmemdup(bufx2, pwlen);
      memzero(bufx2, pwlen);
      free(bufx2);
      break;
    }
  }

cleanup:
  /** Unlock the file before leaving :-) */
  fl.l_type = F_UNLCK;
  fcntl(fd, F_SETLK, &fl);

  zt_free(idhash);
  free(buf);
  fclose(fp);
  close(fd);
  return (passwd) ? pwid_cmp : -1;
}

int auth_passwd_delete(const char *passwddb_file, const char *peer_id,
                       passwd_id_t pwid) {
  int ret = -1;
  int fd;
  FILE *fp;
  struct flock fl;
  char *buf = NULL, *linep, *linep_save;
  uint8_t *idhash;
  uint8_t bufx1[1024 + 1] = {0};
  size_t bufsize = 0;
  ssize_t nread;
  passwd_id_t pwid_cmp;
  bool found = false;

  assert(passwddb_file != NULL);
  assert(peer_id != NULL);

  if ((fd = open(passwddb_file, O_RDWR)) < 0) {
    PRINTERROR("open: could not open %s (%s)", passwddb_file, strerror(errno));
    return -1;
  }

  if ((fp = fdopen(fd, "r+")) == NULL) {
    PRINTERROR("fdopen: could not open %s (%s)", passwddb_file,
               strerror(errno));
    close(fd);
    return -1;
  }

  /** Put a write lock on this file which is held till this function returns */
  fl.l_type = F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0;
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    PRINTERROR("fnctl: failed to acquire x-lock on %s (%s)", passwddb_file,
               strerror(errno));
    fclose(fp);
    close(fd);
    return -1;
  }

  if (auth_sha256_idhash(peer_id, &idhash) < 0)
    goto cleanup;

  while ((nread = getline(&buf, &bufsize, fp)) != -1) {
    if (nread > 1018)
      continue;
    linep = buf;

    while (isspace(*linep))
      linep++;

    if (!*linep || *linep == '#')
      continue; // skip empty and comment lines

    // read "::<idhash>"
    if (*linep && !found) {
      if (line_read_hex(linep, "::", bufx1) !=
          SHA256_BLOCK_SIZE * 2 /* hex chars */) {
        continue;
      }

      if (zt_strcmp(bufx1, idhash) != 0)
        continue;
      found = true;

      linep += SHA256_BLOCK_SIZE * 2 + 2;
    }

    // read ":<pwid>:<'x'/' '>:<pw>:" and delete the password
    if (*linep) {
      if (line_read_uint(linep, &pwid_cmp, ":%u:") < 0)
        continue;
      *linep++;

      if (pwid_cmp != pwid)
        continue;

      char *marker_pos = strchr(linep, ':');
      if (!marker_pos || *(marker_pos + 2) != ':')
        continue;
      marker_pos++;

      // position after the "x" or " " marker
      char *pw_start = strchr(marker_pos, ':');
      if (!pw_start)
        continue;

      char *bufx2;
      ssize_t pwlen, enc_len;
      if ((pwlen = line_read_decode_b64(pw_start, ":", &bufx2, &enc_len)) < 0) {
        zt_free(bufx2);
        continue;
      }

      *marker_pos = 'x';
      pw_start++;
      memset(pw_start, '0', enc_len);

      fseek(fp, -(nread), SEEK_CUR);
      fwrite(buf, 1, nread, fp);
      fflush(fp);
      memzero(bufx2, pwlen);
      zt_free(bufx2);
      ret = 0;
      break;
    }
  }

cleanup:
  /** Unlock the file before leaving :-) */
  fl.l_type = F_UNLCK;
  fcntl(fd, F_SETLK, &fl);
  zt_free(idhash);
  free(buf);
  fclose(fp);
  close(fd);
  return ret;
}

int main() {
  const char *passwddb_file = "passwddb.txt";
  const char *peer_id = "peer1";
  passwd_id_t pwid = -1, pwid_ret;
  char *pw;
  pwid_ret = auth_passwd_load(passwddb_file, peer_id, pwid, &pw);
  assert(pw != NULL);
  printf("Password: %s pwid_ret=%u\n", pw, pwid_ret);
  free(pw);
  assert(auth_passwd_delete(passwddb_file, peer_id, pwid_ret) == 0);
  return 0;
}
