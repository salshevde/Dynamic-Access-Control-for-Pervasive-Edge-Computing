CC = gcc
CFLAGS = -I../common -Wall
LDFLAGS = -lcrypto -lssl

owner: owner.c ../common/crypto.c
	$(CC) $(CFLAGS) -o owner owner.c ../common/crypto.c $(LDFLAGS)

clean:
	rm -f owner