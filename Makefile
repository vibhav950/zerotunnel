CC := gcc
CFLAGS := -Wno-pedantic -std=c23 -ggdb -I./ -DDEBUG -DOPENSSL
LIBS := -lcrypto -lssl

all: bin/test_aes_gcm_128

bin/test_aes_gcm_128: bin/test_aes_gcm_128.o bin/aes_gcm_ossl.o bin/cipher.o bin/log.o bin/memzero.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

bin/test_aes_gcm_128.o: tests/test_aes_gcm_128.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/aes_gcm_ossl.o: crypto/aes_gcm_ossl.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $^

bin/cipher.o: crypto/cipher.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/log.o: common/log.c
	$(CC) $(CFLAGS) -c -o $@ $^

bin/memzero.o: common/memzero.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f bin/*.o bin/test_aes_gcm_128
