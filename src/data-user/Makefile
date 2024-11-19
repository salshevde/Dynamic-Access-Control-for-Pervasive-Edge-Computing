CC = gcc
CFLAGS = -I../common -Wall
LDFLAGS = -lcrypto -lssl

user: user.c ../common/crypto.c
	$(CC) $(CFLAGS) -o user user.c ../common/crypto.c $(LDFLAGS)

clean:
	rm -f user