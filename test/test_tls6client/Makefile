I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
S2=../../proxy/common/src

CC = gcc
CFLAGS = -Wall \
         -g \
         -I$(I1) \
         -I$(I2) \
         -DTLS_CLIENT_AUTH
LD = gcc
LDFLAGS =
INCS = $(I2)/tls6sock.h \
       $(I2)/sock.h \
       $(I2)/tls.h \
       $(I2)/util.h
OBJS = test_tls6client.o \
       tls6sock.o \
       sock.o \
       tls.o \
       util.o
LIBS = -lgnutls \
       -lnettle \
       -lhogweed \
       -lgmp
PROG = test_tls6client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_tls6client.o: test_tls6client.c $(INCS)
	$(CC) $(CFLAGS) -c test_tls6client.c

tls6sock.o: $(S2)/tls6sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls6sock.c

sock.o: $(S2)/sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/sock.c

tls.o: $(S2)/tls.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls.c

util.o: $(S2)/util.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/util.c

clean:
	$(RM) $(PROG) $(OBJS)
