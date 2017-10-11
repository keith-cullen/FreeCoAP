ifeq ($(http_ip6),y)
HTTP_IP6_CFLAGS += -DSOCK_IP6
endif

ifeq ($(coap_ip6),y)
COAP_IP6_CFLAGS += -DCOAP_IP6
endif

I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
S2=../../proxy/common/src
I3=../../proxy/http_coap/include
S3=../../proxy/http_coap/src
D1 = ../../org.eclipse.tinydtls
K1 = ../raw_keys

CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(I3) \
         -I$(D1) \
         -I$(K1) \
         -DCOAP_PROXY \
         -DCOAP_DTLS_EN \
         -DCONNECTION_STATS \
         -DWITH_SHA256
CFLAGS += $(HTTP_IP6_CFLAGS)
CFLAGS += $(COAP_IP6_CFLAGS)
LD_ ?= gcc
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
       $(I2)/lock.h \
       $(D1)/alert.h \
       $(D1)/ccm.h \
       $(D1)/crypto.h \
       $(D1)/dtls_config.h \
       $(D1)/dtls_debug.h \
       $(D1)/dtls.h \
       $(D1)/dtls_time.h \
       $(D1)/global.h \
       $(D1)/hmac.h \
       $(D1)/netq.h \
       $(D1)/numeric.h \
       $(D1)/peer.h \
       $(D1)/prng.h \
       $(D1)/session.h \
       $(D1)/state.h \
       $(D1)/tinydtls.h \
       $(D1)/uthash.h \
       $(D1)/utlist.h \
       $(D1)/aes/rijndael.h \
       $(D1)/ecc/ecc.h \
       $(D1)/sha2/sha2.h \
       $(K1)/raw_keys.h
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
       coap_log.o \
       ccm.o \
       crypto.o \
       dtls.o \
       dtls_debug.o \
       dtls_time.o \
       hmac.o \
       netq.o \
       peer.o \
       session.o \
       rijndael.o \
       ecc.o \
       sha2.o \
       raw_keys.o
LIBS = -lpthread \
       -lgnutls \
       -lnettle \
       -lhogweed \
       -lgmp
PROG = test_proxy_http_coap
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

proxy.o: $(S3)/proxy.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S3)/proxy.c

coap_client.o: $(S1)/coap_client.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_client.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_msg.c

listener.o: $(S3)/listener.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S3)/listener.c

connection.o: $(S3)/connection.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S3)/connection.c

param.o: $(S3)/param.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S3)/param.c

http_msg.o: $(S2)/http_msg.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/http_msg.c

uri.o: $(S2)/uri.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/uri.c

cross.o: $(S2)/cross.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/cross.c

tls.o: $(S2)/tls.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/tls.c

sock.o: $(S2)/sock.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/sock.c

tls_sock.o: $(S2)/tls_sock.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/tls_sock.c

config.o: $(S2)/config.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/config.c

data_buf.o: $(S2)/data_buf.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/data_buf.c

util.o: $(S2)/util.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/util.c

thread.o: $(S2)/thread.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/thread.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_log.c

ccm.o: $(D1)/ccm.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/ccm.c

crypto.o: $(D1)/crypto.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/crypto.c

dtls.o: $(D1)/dtls.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/dtls.c

dtls_debug.o: $(D1)/dtls_debug.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/dtls_debug.c

dtls_time.o: $(D1)/dtls_time.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/dtls_time.c

hmac.o: $(D1)/hmac.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/hmac.c

netq.o: $(D1)/netq.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/netq.c

peer.o: $(D1)/peer.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/peer.c

session.o: $(D1)/session.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/session.c

rijndael.o: $(D1)/aes/rijndael.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/aes/rijndael.c

ecc.o: $(D1)/ecc/ecc.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/ecc/ecc.c

sha2.o: $(D1)/sha2/sha2.c $(INCS)
	$(CC_) $(CFLAGS) -c $(D1)/sha2/sha2.c

raw_keys.o: $(K1)/raw_keys.c $(INCS)
	$(CC_) $(CFLAGS) -c $(K1)/raw_keys.c

clean:
	$(RM) $(PROG) $(OBJS)
