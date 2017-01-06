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
I3=../../proxy/http_coap/include
S3=../../proxy/http_coap/src

CC = gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(I3) \
         -DTLS_CLIENT_AUTH \
         -DCOAP_PROXY \
         -DCOAP_DTLS_EN \
         -DCONNECTION_STATS
CFLAGS += $(EXTRA_CFLAGS)
LD = gcc
LDFLAGS =
INCS = $(I1)/coap_client.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h \
       $(I1)/coap_ipv.h \
       $(I3)/listener.h \
       $(I3)/connection.h \
       $(I3)/param.h \
       $(I2)/http_msg.h \
       $(I2)/uri.h \
       $(I2)/cross.h \
       $(I2)/tls.h \
       $(I2)/sock.h \
       $(I2)/tls_sock.h \
       $(I2)/config.h \
       $(I2)/data_buf.h \
       $(I2)/util.h \
       $(I2)/thread.h \
       $(I2)/lock.h
OBJS = proxy.o \
       coap_client.o \
       coap_msg.o \
       listener.o \
       connection.o \
       param.o \
       http_msg.o \
       uri.o \
       cross.o \
       tls.o \
       sock.o \
       tls_sock.o \
       config.o \
       data_buf.o \
       util.o \
       thread.o \
       coap_log.o
LIBS = -lpthread \
       -lgnutls \
       -lnettle \
       -lhogweed \
       -lgmp
PROG = proxy
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

proxy.o: $(S3)/proxy.c $(INCS)
	$(CC) $(CFLAGS) -c $(S3)/proxy.c

coap_client.o: $(S1)/coap_client.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_client.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_msg.c

listener.o: $(S3)/listener.c $(INCS)
	$(CC) $(CFLAGS) -c $(S3)/listener.c

connection.o: $(S3)/connection.c $(INCS)
	$(CC) $(CFLAGS) -c $(S3)/connection.c

param.o: $(S3)/param.c $(INCS)
	$(CC) $(CFLAGS) -c $(S3)/param.c

http_msg.o: $(S2)/http_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/http_msg.c

uri.o: $(S2)/uri.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/uri.c

cross.o: $(S2)/cross.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/cross.c

tls.o: $(S2)/tls.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls.c

sock.o: $(S2)/sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/sock.c

tls_sock.o: $(S2)/tls_sock.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/tls_sock.c

config.o: $(S2)/config.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/config.c

data_buf.o: $(S2)/data_buf.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/data_buf.c

util.o: $(S2)/util.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/util.c

thread.o: $(S2)/thread.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/thread.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

clean:
	$(RM) $(PROG) $(OBJS)
