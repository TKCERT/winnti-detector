CC=gcc
CFLAGS=-Wall -std=gnu99 -O3
LDFLAGS=-lnids
default: all

all: wntidect.o
	$(CC) $(CFLAGS) -o wntidect wntidect.o $(LDFLAGS)

wntidect.o: wntidect.c
	$(CC) $(CFLAGS) -c wntidect.c

clean: 
	$(RM) wntidect *.o *~

