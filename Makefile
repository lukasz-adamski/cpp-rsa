all: crypter

CFLAGS=-Wall -std=c++11 -stdlib=libc++
CC=$(CXX) $(CFLAGS)

OBJS=src/rsa.o src/main.o

%.o:%.cpp
	$(CC) -c -o $@ $<

crypter: $(OBJS)
	$(CC) -o crypter $(OBJS)

clean:
	rm -f src/*.o crypter
