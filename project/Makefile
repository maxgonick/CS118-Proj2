OPENSSL_INCLUDE = /opt/homebrew/opt/openssl@3/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@3/lib

CC=gcc
CFLAGS=-I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -lcrypto

all: clean copy_keys build

copy_keys: 
	cp ../keys/server_cert.bin .
	cp ../keys/server_key.bin .
	cp ../keys/ca_public_key.bin .



default: build

build: server.c client.c transport.c io.c security.c sec.c 
	${CC} -o server server.c transport.c io.c security.c sec.c ${CFLAGS}
	${CC} -o client client.c transport.c io.c security.c sec.c ${CFLAGS}

clean:
	rm -rf server client *.bin *.out *.dSYM *.zip

zip: clean
	rm -f project2.zip
	mkdir -p project
	cp server.c client.c transport.c io.c security.c sec.c transport.h io.h consts.h security.h sec.h Makefile project
	zip project2.zip project/*
	rm -rf project
