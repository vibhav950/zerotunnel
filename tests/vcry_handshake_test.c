/**
 * Multi-threaded test for the handshake protocol.
 *
 * The initiator and responder run on separate threads and communicate through
 * shared global pointers in a somewhat crude ping-pong manner to simulate the
 * four-way handshake.
 */

#include "test.h"
#include "lib/vcry.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_THREADS 2

/**
 * There are two shared buffers - the "initiator buffer" will be used by the
 * initiator thread to place its data and the responder thread to read this
 * data, and the vice-versa for the "responder buffer".
 *
 * 1. Reading - the thread trying to read from the peer's buffer will wait until
 * it is given the green light to perform the read by the other thread (through
 * the buffer length and the condition variable). The thread performing the read
 * then takes ownership of the data buffer and is now responsible to free the
 * memory after it is done with the data.
 *
 * 2. Writing - the thread trying to write to its own buffer will wait until the
 * other thread has consumed any previous data. The "write" operation is done by
 * simply assinging the data buffer to the shared pointer and setting the length
 * of the data before signalling the other thread to consume the data.
 */
struct buffer_st {
  uint8_t *data;
  volatile size_t len;
  pthread_mutex_t lock;
  pthread_cond_t can_produce;
  pthread_cond_t can_consume;
};

pthread_barrier_t barrier;

static const uint8_t AUTHKEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x15, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

void *initiator_thread(void *arg) {
  struct buffer_st *initiator_buf = ((struct buffer_st **)arg)[0];
  struct buffer_st *responder_buf = ((struct buffer_st **)arg)[1];
  uint8_t *read = NULL, *write = NULL;
  size_t read_len = 0, write_len = 0;

  vcry_set_role_initiator();

  vcry_set_authkey(AUTHKEY, sizeof(AUTHKEY));

  ASSERT(vcry_set_cipher_from_name("AES-CTR-256") == 0);
  ASSERT(vcry_set_aead_from_name("AES-GCM-256") == 0);
  ASSERT(vcry_set_hmac_from_name("HMAC-SHA256") == 0);
  ASSERT(vcry_set_ecdh_from_name("ECDH-X25519") == 0);
  ASSERT(vcry_set_kem_from_name("KEM-KYBER512") == 0);
  ASSERT(vcry_set_kdf_from_name("KDF-PBKDF2") == 0);

  /* ============ HANDSHAKE INITIATE ============ */
  ASSERT(vcry_handshake_initiate(&write, &write_len) == 0);

  /* Send initiation message */
  pthread_mutex_lock(&initiator_buf->lock);
  // while (initiator_buf->len != 0)
  // pthread_cond_wait(&initiator_buf->can_produce, &initiator_buf->lock);
  initiator_buf->data = write;
  initiator_buf->len = write_len;
  pthread_cond_signal(&initiator_buf->can_consume);
  pthread_mutex_unlock(&initiator_buf->lock);

  /* Wait for response message */
  pthread_mutex_lock(&responder_buf->lock);
  while (responder_buf->len == 0)
    pthread_cond_wait(&responder_buf->can_consume, &responder_buf->lock);
  read = responder_buf->data;
  read_len = responder_buf->len;
  responder_buf->data = NULL;
  responder_buf->len = 0;
  pthread_cond_signal(&responder_buf->can_produce);
  pthread_mutex_unlock(&responder_buf->lock);

  /* ============ HANDSHAKE COMPLETE ============ */
  ASSERT(vcry_handshake_complete(read, read_len) == 0);
  zt_free(read); // free after use

  /* We are now in the right state to derive the session key */
  pthread_barrier_wait(&barrier);

  ASSERT(vcry_derive_session_key() == 0);

  /* ============ VERIFY INITIATE ============ */
  vcry_initiator_verify_initiate(&write, &write_len, "Alice", "Bob");

  /* Send initiator verify message */
  pthread_mutex_lock(&initiator_buf->lock);
  // while (initiator_buf->len != 0)
  // pthread_cond_wait(&initiator_buf->can_produce, &initiator_buf->lock);
  initiator_buf->data = write;
  initiator_buf->len = write_len;
  pthread_cond_signal(&initiator_buf->can_consume);
  pthread_mutex_unlock(&initiator_buf->lock);

  /* Wait for responder verify message */
  pthread_mutex_lock(&responder_buf->lock);
  while (responder_buf->len == 0)
    pthread_cond_wait(&responder_buf->can_consume, &responder_buf->lock);
  read = responder_buf->data;
  read_len = responder_buf->len;
  responder_buf->data = NULL;
  responder_buf->len = 0;
  pthread_cond_signal(&responder_buf->can_produce);
  pthread_mutex_unlock(&responder_buf->lock);

  /* ============ VERIFY COMPLETE ============ */
  ASSERT(vcry_initiator_verify_complete(read, "Alice", "Bob") == 0);
  zt_free(read); // free after use

  vcry_module_release();

  return NULL;
}

void *responder_thread(void *arg) {
  struct buffer_st *initiator_buf = ((struct buffer_st **)arg)[0];
  struct buffer_st *responder_buf = ((struct buffer_st **)arg)[1];

  uint8_t *read = NULL, *write = NULL;
  size_t read_len = 0, write_len = 0;

  vcry_set_role_responder();

  vcry_set_authkey(AUTHKEY, sizeof(AUTHKEY));

  ASSERT(vcry_set_cipher_from_name("AES-CTR-256") == 0);
  ASSERT(vcry_set_aead_from_name("AES-GCM-256") == 0);
  ASSERT(vcry_set_hmac_from_name("HMAC-SHA256") == 0);
  ASSERT(vcry_set_ecdh_from_name("ECDH-X25519") == 0);
  ASSERT(vcry_set_kem_from_name("KEM-KYBER512") == 0);
  ASSERT(vcry_set_kdf_from_name("KDF-PBKDF2") == 0);

  /* Wait for initiation message */
  pthread_mutex_lock(&initiator_buf->lock);
  while (initiator_buf->len == 0)
    pthread_cond_wait(&initiator_buf->can_consume, &initiator_buf->lock);
  read = initiator_buf->data;
  read_len = initiator_buf->len;
  initiator_buf->data = NULL;
  initiator_buf->len = 0;
  pthread_cond_signal(&initiator_buf->can_produce);
  pthread_mutex_unlock(&initiator_buf->lock);

  /* ============ HANDSHAKE RESPONSE ============ */
  ASSERT(vcry_handshake_respond(read, read_len, &write, &write_len) == 0);
  zt_free(read);

  /* Send response message */
  pthread_mutex_lock(&responder_buf->lock);
  while (responder_buf->len != 0)
    pthread_cond_wait(&responder_buf->can_produce, &responder_buf->lock);
  responder_buf->data = write;
  responder_buf->len = write_len;
  pthread_cond_signal(&responder_buf->can_consume);
  pthread_mutex_unlock(&responder_buf->lock);

  /* We are now in the right state to derive the session key */
  pthread_barrier_wait(&barrier);

  ASSERT(vcry_derive_session_key() == 0);

  /* ============ VERIFY INITIATE ============ */
  ASSERT(vcry_responder_verify_initiate(&write, &write_len, "Alice", "Bob") ==
         0);

  /* Send responder verify message */
  pthread_mutex_lock(&responder_buf->lock);
  // while (responder_buf->len != 0)
  // pthread_cond_wait(&responder_buf->can_produce, &responder_buf->lock);
  responder_buf->data = write;
  responder_buf->len = write_len;
  pthread_cond_signal(&responder_buf->can_consume);
  pthread_mutex_unlock(&responder_buf->lock);

  /* Wait for initiator verify message */
  pthread_mutex_lock(&initiator_buf->lock);
  while (initiator_buf->len == 0)
    pthread_cond_wait(&initiator_buf->can_consume, &initiator_buf->lock);
  read = initiator_buf->data;
  read_len = initiator_buf->len;
  initiator_buf->data = NULL;
  initiator_buf->len = 0;
  pthread_cond_signal(&initiator_buf->can_produce);
  pthread_mutex_unlock(&initiator_buf->lock);

  /* ============ VERIFY COMPLETE ============ */
  ASSERT(vcry_responder_verify_complete(read, "Alice", "Bob") == 0);
  zt_free(read);

  vcry_module_release();

  return NULL;
}

int main(void) {
  struct buffer_st initiator_buf = {.data = NULL,
                                    .len = 0,
                                    .lock = PTHREAD_MUTEX_INITIALIZER,
                                    .can_produce = PTHREAD_COND_INITIALIZER,
                                    .can_consume = PTHREAD_COND_INITIALIZER};
  struct buffer_st responder_buf = {.data = NULL,
                                    .len = 0,
                                    .lock = PTHREAD_MUTEX_INITIALIZER,
                                    .can_produce = PTHREAD_COND_INITIALIZER,
                                    .can_consume = PTHREAD_COND_INITIALIZER};
  struct buffer_st *buffers[N_THREADS] = {&initiator_buf, &responder_buf};

  pthread_t initiator, responder;

  pthread_barrier_init(&barrier, NULL, N_THREADS + 1);

  if (pthread_create(&responder, NULL, responder_thread, (void *)buffers))
    exit(EXIT_FAILURE);

  if (pthread_create(&initiator, NULL, initiator_thread, (void *)buffers))
    exit(EXIT_FAILURE);

  pthread_barrier_wait(&barrier);

  pthread_join(initiator, NULL);
  pthread_join(responder, NULL);

  pthread_barrier_destroy(&barrier);

  pthread_mutex_destroy(&initiator_buf.lock);
  pthread_mutex_destroy(&responder_buf.lock);

  pthread_cond_destroy(&initiator_buf.can_produce);
  pthread_cond_destroy(&initiator_buf.can_consume);
  pthread_cond_destroy(&responder_buf.can_produce);
  pthread_cond_destroy(&responder_buf.can_consume);

  exit(EXIT_SUCCESS);
}
