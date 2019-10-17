ifeq ($(ip6),y)
IP6_CFLAGS = -DCOAP_IP6
endif
ifneq ($(dtls),n)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
endif
I1 = ../../lib/include
S1 = ../../lib/src
T1 = ..
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(T1)
CFLAGS += $(IP6_CFLAGS)
CFLAGS += $(DTLS_CFLAGS)
LD_ ?= gcc
LDFLAGS =
INCS = $(I1)/coap_client.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_mem.h \
       $(I1)/coap_log.h \
       $(I1)/coap_ipv.h \
       $(T1)/test.h
OBJS = test_coap_client.o \
       coap_client.o \
       coap_msg.o \
       coap_mem.o \
       coap_log.o \
       test.o
LIBS = $(DTLS_LIBS)
PROG = test_coap_client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
