# I am a comment, and I want to say that the variable CC will be
# the compiler to use.
CC=cc
# Hey!, I am comment number 2. I want to say that CFLAGS will be the
# options I'll pass to the compiler.
CFLAGS = -c

all: hw4

hw4: gentable.o crack.o
	$(CC) aes.o gentable.o -o gentable
	$(CC) aes.o crack.o -o crack

genatble.o: gentable.c
	$(CC) $(CFLAGS) aes.c gentable.c

crack.o: crack.c
	$(CC) $(CFLAGS) aes.c crack.c

clean:
	rm -rf *o hw4

