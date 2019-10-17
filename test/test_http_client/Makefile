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
T1 = ..
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(T1) \
         -DTLS_CLIENT_AUTH
CFLAGS += $(HTTP_IP6_CFLAGS)
CFLAGS += $(COAP_IP6_CFLAGS)
LD_ ?= gcc
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
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S2)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
