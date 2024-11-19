CC = gcc
CFLAGS = -I../common -Wall
LDFLAGS = -lcrypto -lssl

server: server.c ../common/crypto.c
	$(CC) $(CFLAGS) -o server server.c ../common/crypto.c $(LDFLAGS)

clean:
	rm -f server