ifeq ($(http_ip6),y)
HTTP_IP6_CFLAGS = -DSOCK_IP6
endif
ifeq ($(coap_ip6),y)
COAP_IP6_CFLAGS = -DCOAP_IP6
endif
I1 = ../../lib/include
S1 = ../../lib/src
I2 = ../../proxy/common/include
S2 = ../../proxy/common/src
I3 = ../../proxy/http_coap/include
S3 = ../../proxy/http_coap/src
D1 = ../../org.eclipse.tinydtls
D2 = $(D1)/aes
D3 = $(D1)/ecc
D4 = $(D1)/sha2
K1 = ../raw_keys
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(I3) \
         -I$(D1) \
         -I$(D2) \
         -I$(D3) \
         -I$(D4) \
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
       $(I1)/coap_mem.h \
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
       $(D2)/rijndael.h \
       $(D3)/ecc.h \
       $(D4)/sha2.h \
       $(K1)/raw_keys.h
OBJS = proxy.o \
       coap_client.o \
       coap_msg.o \
       coap_mem.o \
       coap_log.o \
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
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S2)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S3)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(D1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(D2)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(D3)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(D4)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(K1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
