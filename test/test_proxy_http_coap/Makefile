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
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(I3) \
         -DTLS_CLIENT_AUTH \
         -DCOAP_PROXY \
         -DCOAP_DTLS_EN \
         -DCONNECTION_STATS
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
       $(I2)/lock.h
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
       thread.o
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

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
