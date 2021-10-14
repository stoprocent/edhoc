PROG = vectors
CC = g++
CPPFLAGS = -g –Wall –I/usr/class/cs193d/include
LDFLAGS = -L/usr/class/cs193/lib –lCoolFns
OBJS = main.o blurb.o database.o

$(PROG) : $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS)

main.o :
	$(CC) $(CPPFLAGS) -c main.cpp
blurb.o : blurb.h
	$(CC) $(CPPFLAGS) -c blurb.cpp
database.o : database.h
	$(CC) $(CPPFLAGS) -c database.cpp
	
clean:
	rm -f core $(PROG) $(OBJS)


vectors: vectors
    g++ aes.c aes-ccm.c aes-enc.c vectors.cpp -lmbedtls -lmbedx509 -lmbedcrypto -o vectors.exe -Imbedtls/include/psa -Lmbedtls/library -std=c++17
