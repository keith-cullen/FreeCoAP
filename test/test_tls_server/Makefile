ifeq ($(ip6),y)
EXTRA_CFLAGS = -DSOCK_IP6
endif

I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
S2=../../proxy/common/src

CC = gcc
CFLAGS = $(EXTRA_CFLAGS) \
         -Wall \
         -I$(I1) \
         -I$(I2) \
         -DTLS_CLIENT_AUTH
LD = gcc
LDFLAGS =
INCS = $(I2)/tls_sock.h \
       $(I2)/sock.h \
       $(I2)/tls.h \
       $(I2)/util.h \
       $(I1)/coap_log.h
OBJS = test_tls_server.o \
       tls_sock.o \
       sock.o \
       tls.o \
       util.o \
       coap_log.o
LIBS = -lpthread \
       -lgnutls \
       -lnettle \
       -lhogweed \
       -lgmp
PROG = test_tls_server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_tls_server.o: test_tls_server.c $(INCS)
	$(CC) $(CFLAGS) -c test_tls_server.c

tls_sock.o: $(S2)/tls_sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls_sock.c

sock.o: $(S2)/sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/sock.c

tls.o: $(S2)/tls.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls.c

util.o: $(S2)/util.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/util.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

clean:
	$(RM) $(PROG) $(OBJS)
