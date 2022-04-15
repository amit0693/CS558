CC:=clang

# If you install OpenSSL locally: 
# 1. Uncomment the line for the SSLDIR variable,
# 2. Uncomment the remainder of the line for EXTRA_CFLAGS and EXTRA_LDFLAGS, 
# 3. Adjust all paths accordingly.

#SSLDIR=./openssl-1.1.1k
EXTRA_CFLAGS:= #-I$(SSLDIR)/include
CFLAGS:=-g -Wall -O2 $(EXTRA_CFLAGS)
EXTRA_LDFLAGS:= #-L$(SSLDIR)/lib
LDFLAGS:= $(EXTRA_LDFLAGS) -lcrypto

.PHONY: all
all: exec exec2

exec: fscrypt.c main.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

exec2: fscrypt2.c main2.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -fv *.o
	rm -fv *~
	rm -fv exec exec2
