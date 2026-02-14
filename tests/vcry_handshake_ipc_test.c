/**
 * IPC-based test for the handshake protocol.
 *
 * The initiator and responder run in separate forked processes and communicate
 * through pipes to simulate the four-way handshake.
 */

#include "common/log.h"
#include "lib/vcry.h"
#include "test.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const uint8_t AUTHKEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x15, 0x15, 0x16, 0x17,
                                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static const uint8_t STREAMID[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

static const uint8_t plaintext[32] = {0};

static const uint8_t plaintext2[32] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
  0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
};

static const char *id_initiator = "Alice";
static const char *id_responder = "Bob";

/**
 * Helper function to send data over pipe
 * Format: send length first (4 bytes), then data
 */
static int send_data(int fd, const uint8_t *data, size_t len) {
  uint32_t msg_len = (uint32_t)len;

  if (write(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len))
    return -1;

  if (len > 0 && write(fd, data, len) != (ssize_t)len)
    return -1;

  return 0;
}

/**
 * Helper function to receive data from pipe
 * Returns allocated buffer that caller must free
 */
static uint8_t *recv_data(int fd, size_t *len) {
  uint32_t msg_len;

  if (read(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len))
    return NULL;

  *len = msg_len;

  if (msg_len == 0)
    return NULL;

  uint8_t *data = zt_malloc(msg_len);
  if (!data)
    return NULL;

  if (read(fd, data, msg_len) != (ssize_t)msg_len) {
    zt_free(data);
    return NULL;
  }

  return data;
}

static void initiator_process(int read_fd, int write_fd) {
  uint8_t *read_data = NULL, *write_data = NULL;
  size_t read_len = 0, write_len = 0;
  vcry_crypto_hdr_t *hdr;

  ASSERT(vcry_module_init() == ERR_SUCCESS);

  ASSERT((hdr = vcry_crypto_hdr_new(STREAMID)) != NULL);

  vcry_set_role_initiator();

  ASSERT(vcry_set_authpass(AUTHKEY, sizeof(AUTHKEY)) == ERR_SUCCESS);

  ASSERT(vcry_set_crypto_params_from_names("AES-CTR-256", "AES-GCM-256", "HMAC-SHA256",
                                           "ECDH-X25519", "KEM-KYBER512",
                                           "KDF-ARGON2") == ERR_SUCCESS);

  /* ============ HANDSHAKE INITIATE ============ */

  ASSERT(vcry_handshake_initiate(&write_data, &write_len) == ERR_SUCCESS);

  /* send initiation message */
  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* wait for response message */
  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  /* ============ HANDSHAKE COMPLETE ============ */

  ASSERT(vcry_handshake_complete(read_data, read_len) == ERR_SUCCESS);
  zt_free(read_data);

  ASSERT(vcry_derive_session_key() == ERR_SUCCESS);

  /* ============ VERIFY INITIATE ============ */

  ASSERT(vcry_initiator_verify_initiate(&write_data, &write_len, id_initiator,
                                        id_responder, strlen(id_initiator),
                                        strlen(id_responder)) == ERR_SUCCESS);

  /* Send initiator verify message */
  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* wait for responder verify message */
  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  /* ============ VERIFY COMPLETE ============ */

  ASSERT(vcry_initiator_verify_complete(read_data, id_initiator, id_responder,
                                        strlen(id_initiator),
                                        strlen(id_responder)) == ERR_SUCCESS);
  zt_free(read_data);

  /* ================ SEND DATA ================ */

  write_len = sizeof(plaintext) + vcry_get_aead_tag_len();
  write_data = zt_malloc(write_len);
  ASSERT(write_data != NULL);

  ASSERT(vcry_aead_encrypt((uint8_t *)plaintext, sizeof(plaintext), NULL, 0, hdr,
                           write_data, &write_len) == ERR_SUCCESS);

  /* send encrypted data */
  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* ================ RECV DATA ================ */

  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  uint8_t *buf = zt_malloc(sizeof(plaintext));
  size_t len = sizeof(plaintext);
  ASSERT(buf != NULL);

  ASSERT(vcry_aead_decrypt(read_data, read_len, NULL, 0, hdr, buf, &len) == ERR_SUCCESS);

  ASSERT_EQ(len, sizeof(plaintext));
  ASSERT_MEMEQ(buf, plaintext, sizeof(plaintext));

  zt_free(read_data);
  zt_free(buf);

  /* ============ ROUND 2: SEND DATA ============ */

  write_len = sizeof(plaintext2) + vcry_get_aead_tag_len();
  write_data = zt_malloc(write_len);
  ASSERT(write_data != NULL);

  ASSERT(vcry_aead_encrypt((uint8_t *)plaintext2, sizeof(plaintext2), NULL, 0, hdr,
                           write_data, &write_len) == ERR_SUCCESS);

  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* ============ ROUND 2: RECV DATA ============ */

  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  buf = zt_malloc(sizeof(plaintext2));
  len = sizeof(plaintext2);
  ASSERT(buf != NULL);

  ASSERT(vcry_aead_decrypt(read_data, read_len, NULL, 0, hdr, buf, &len) == ERR_SUCCESS);

  ASSERT_EQ(len, sizeof(plaintext2));
  ASSERT_MEMEQ(buf, plaintext2, sizeof(plaintext2));

  zt_free(read_data);
  zt_free(buf);

  vcry_crypto_hdr_free(hdr);

  vcry_module_release();

  close(read_fd);
  close(write_fd);
}

static void responder_process(int read_fd, int write_fd) {
  uint8_t *read_data = NULL, *write_data = NULL;
  size_t read_len = 0, write_len = 0;
  vcry_crypto_hdr_t *hdr;

  ASSERT(vcry_module_init() == ERR_SUCCESS);

  ASSERT((hdr = vcry_crypto_hdr_new(STREAMID)) != NULL);

  vcry_set_role_responder();

  ASSERT(vcry_set_authpass(AUTHKEY, sizeof(AUTHKEY)) == ERR_SUCCESS);

  ASSERT(vcry_set_crypto_params_from_names("AES-CTR-256", "AES-GCM-256", "HMAC-SHA256",
                                           "ECDH-X25519", "KEM-KYBER512",
                                           "KDF-ARGON2") == ERR_SUCCESS);

  /* wait for initiation message */
  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  /* ============ HANDSHAKE RESPONSE ============ */

  ASSERT(vcry_handshake_respond(read_data, read_len, &write_data, &write_len) ==
         ERR_SUCCESS);
  zt_free(read_data);

  /* send response message */
  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  ASSERT(vcry_derive_session_key() == ERR_SUCCESS);

  /* ============ VERIFY INITIATE ============ */

  ASSERT(vcry_responder_verify_initiate(&write_data, &write_len, id_initiator,
                                        id_responder, strlen(id_initiator),
                                        strlen(id_responder)) == ERR_SUCCESS);

  /* send responder verify message */
  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* wait for initiator verify message */
  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  /* ============ VERIFY COMPLETE ============ */

  ASSERT(vcry_responder_verify_complete(read_data, id_initiator, id_responder,
                                        strlen(id_initiator),
                                        strlen(id_responder)) == ERR_SUCCESS);
  zt_free(read_data);

  /* ================ SEND DATA ================ */

  write_len = sizeof(plaintext) + vcry_get_aead_tag_len();
  write_data = zt_malloc(write_len);
  ASSERT(write_data != NULL);

  ASSERT(vcry_aead_encrypt((uint8_t *)plaintext, sizeof(plaintext), NULL, 0, hdr,
                           write_data, &write_len) == ERR_SUCCESS);

  /* send encrypted data */
  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* ================ RECV DATA ================ */

  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  uint8_t *buf = zt_malloc(sizeof(plaintext));
  size_t len = sizeof(plaintext);
  ASSERT(buf != NULL);

  ASSERT(vcry_aead_decrypt(read_data, read_len, NULL, 0, hdr, buf, &len) == ERR_SUCCESS);

  ASSERT_EQ(len, sizeof(plaintext));
  ASSERT_MEMEQ(buf, plaintext, sizeof(plaintext));

  zt_free(read_data);
  zt_free(buf);

  /* ============ ROUND 2: SEND DATA ============ */

  write_len = sizeof(plaintext2) + vcry_get_aead_tag_len();
  write_data = zt_malloc(write_len);
  ASSERT(write_data != NULL);

  ASSERT(vcry_aead_encrypt((uint8_t *)plaintext2, sizeof(plaintext2), NULL, 0, hdr,
                           write_data, &write_len) == ERR_SUCCESS);

  ASSERT(send_data(write_fd, write_data, write_len) == 0);
  zt_free(write_data);

  /* ============ ROUND 2: RECV DATA ============ */

  read_data = recv_data(read_fd, &read_len);
  ASSERT(read_data != NULL);

  buf = zt_malloc(sizeof(plaintext2));
  len = sizeof(plaintext2);
  ASSERT(buf != NULL);

  ASSERT(vcry_aead_decrypt(read_data, read_len, NULL, 0, hdr, buf, &len) == ERR_SUCCESS);

  ASSERT_EQ(len, sizeof(plaintext2));
  ASSERT_MEMEQ(buf, plaintext2, sizeof(plaintext2));

  zt_free(read_data);
  zt_free(buf);

  vcry_crypto_hdr_free(hdr);

  vcry_module_release();

  close(read_fd);
  close(write_fd);
}

int main(void) {
  /** pipe1: initiator->responder, pipe2: responder->initiator */
  int pipe1[2], pipe2[2];
  pid_t pid;
  int status;

  if (pipe(pipe1) == -1) {
    perror("pipe1");
    exit(EXIT_FAILURE);
  }

  if (pipe(pipe2) == -1) {
    perror("pipe2");
    close(pipe1[0]);
    close(pipe1[1]);
    exit(EXIT_FAILURE);
  }

  pid = fork();
  if (pid == -1) {
    perror("fork");
    close(pipe1[0]);
    close(pipe1[1]);
    close(pipe2[0]);
    close(pipe2[1]);
    exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    /** child process -- responder */
    close(pipe1[1]); /* close write end of pipe1 */
    close(pipe2[0]); /* close read end of pipe2 */

    responder_process(pipe1[0], pipe2[1]);

    exit(EXIT_SUCCESS);
  } else {
    /** parent process -- initiator */
    close(pipe1[0]); /* close read end of pipe1 */
    close(pipe2[1]); /* close write end of pipe2 */

    initiator_process(pipe2[0], pipe1[1]);

    /** wait for child process */
    if (waitpid(pid, &status, 0) == -1) {
      perror("waitpid");
      exit(EXIT_FAILURE);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
      fprintf(stderr, "Child process failed\n");
      exit(EXIT_FAILURE);
    }
  }

  return EXIT_SUCCESS;
}
