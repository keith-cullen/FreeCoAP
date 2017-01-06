ifeq ($(http_ip6),y)
EXTRA_CFLAGS += -DSOCK_IP6
endif

ifeq ($(coap_ip6),y)
EXTRA_CFLAGS += -DCOAP_IP6
endif

I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
S2=../../proxy/common/src
T1=..

CC = gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(T1) \
         -DTLS_CLIENT_AUTH
CFLAGS += $(EXTRA_CFLAGS)
LD = gcc
LDFLAGS =

INCS = $(I2)/http_msg.h \
       $(I2)/tls.h \
       $(I2)/sock.h \
       $(I2)/tls_sock.h \
       $(I2)/data_buf.h \
       $(I2)/util.h \
       $(I1)/coap_log.h \
       $(T1)/test.h
OBJS = test_http_client.o \
       http_msg.o \
       tls.o \
       sock.o \
       tls_sock.o \
       data_buf.o \
       util.o \
       coap_log.o \
       test.o
LIBS = -lpthread \
       -lgnutls \
       -lnettle \
       -lhogweed \
       -lgmp
PROG = test_http_client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_http_client.o: test_http_client.c $(INCS)
	$(CC) $(CFLAGS) -c test_http_client.c

http_msg.o: $(S2)/http_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/http_msg.c

tls.o: $(S2)/tls.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls.c

sock.o: $(S2)/sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/sock.c

tls_sock.o: $(S2)/tls_sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls_sock.c

data_buf.o: $(S2)/data_buf.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/data_buf.c

util.o: $(S2)/util.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/util.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
