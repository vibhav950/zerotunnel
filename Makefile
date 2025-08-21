CC := gcc
CFLAGS := -Wno-pedantic -std=gnu17 -I./ -DDEBUG -DOPENSSL -DLIBOQS -ggdb -fsanitize=address
LIBS := -lcrypto -lm -loqs -lbsd -lsystemd -pthread

# Object files from all directories
COMMON_OBJS = bin/log.o bin/mem.o bin/memzero.o bin/time_utils.o bin/timeout.o \
              bin/x86_cpuid.o bin/cpu.o bin/hex.o bin/b64.o bin/sha256.o \
              bin/sha256_alg.o bin/sha256_x86.o bin/progressbar.o bin/tty_io.o \
              bin/prompts.o bin/utils.o bin/fzero.o

CRYPTO_OBJS = bin/cipher.o bin/cipher_ossl.o bin/aead_ossl.o \
              bin/hmac.o bin/hmac_ossl.o bin/kdf.o bin/kdf_ossl.o \
              bin/kem.o bin/kem_kyber_oqs.o bin/kex.o bin/kex_ecc_ossl.o

LIB_OBJS = bin/vcry.o bin/auth.o bin/ciphersuites.o bin/client.o bin/server.o \
           bin/io.o bin/ip.o bin/lz4.o bin/netio.o bin/password.o bin/zt_addrinfo.o

RANDOM_OBJS = bin/rdrand.o bin/systemrand.o

SRC_OBJS = bin/main.o bin/options.o

ALL_OBJS = $(COMMON_OBJS) $(CRYPTO_OBJS) $(LIB_OBJS) $(RANDOM_OBJS) $(SRC_OBJS)

all: bin/zerotunnel

bin/zerotunnel: $(ALL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Source files compilation rules
bin/main.o: src/main.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/options.o: src/options.c
	$(CC) $(CFLAGS) -c -o $@ $^

# Common directory object files
bin/log.o: common/log.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/mem.o: common/mem.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/memzero.o: common/memzero.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/time_utils.o: common/time_utils.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/timeout.o: common/timeout.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/x86_cpuid.o: common/x86_cpuid.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/cpu.o: common/cpu.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/hex.o: common/hex.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/b64.o: common/b64.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/sha256.o: common/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/sha256_alg.o: common/sha256_alg.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/sha256_x86.o: common/sha256_x86.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/progressbar.o: common/progressbar.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/tty_io.o: common/tty_io.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/prompts.o: common/prompts.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/utils.o: common/utils.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/fzero.o: common/fzero.c
	$(CC) $(CFLAGS) -c -o $@ $^

# Crypto directory object files
bin/cipher.o: crypto/cipher.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/cipher_ossl.o: crypto/cipher_ossl.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/aead_ossl.o: crypto/aead_ossl.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/hmac.o: crypto/hmac.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/hmac_ossl.o: crypto/hmac_ossl.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/kdf.o: crypto/kdf.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/kdf_ossl.o: crypto/kdf_ossl.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/kem.o: crypto/kem.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/kem_kyber_oqs.o: crypto/kem_kyber_oqs.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/kex.o: crypto/kex.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/kex_ecc_ossl.o: crypto/kex_ecc_ossl.c
	$(CC) $(CFLAGS) -c -o $@ $^

# Lib directory object files
bin/vcry.o: lib/vcry.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/auth.o: lib/auth.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/ciphersuites.o: lib/ciphersuites.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/client.o: lib/client.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/server.o: lib/server.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/io.o: lib/io.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/ip.o: lib/ip.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/lz4.o: lib/lz4.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/netio.o: lib/netio.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/password.o: lib/password.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/zt_addrinfo.o: lib/zt_addrinfo.c
	$(CC) $(CFLAGS) -c -o $@ $^

# Random directory object files
bin/rdrand.o: random/rdrand.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/systemrand.o: random/systemrand.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f bin/*.o bin/zerotunnel

