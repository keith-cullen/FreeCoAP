ifeq ($(ip6),y)
IP6_CFLAGS = -DCOAP_IP6
endif
ifneq ($(dtls),n)
D1 = ../../org.eclipse.tinydtls
D2 = $(D1)/aes
D3 = $(D1)/ecc
D4 = $(D1)/sha2
K1 = ../../test/raw_keys
DTLS_CFLAGS = -DCOAP_DTLS_EN \
              -DWITH_SHA256 \
              -I$(D1) \
              -I$(D2) \
              -I$(D3) \
              -I$(D4) \
              -I$(K1)
DTLS_INCS = $(D1)/alert.h \
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
DTLS_OBJS = ccm.o \
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
endif
I1 = ../../lib/include
S1 = ../../lib/src
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1)
CFLAGS += $(IP6_CFLAGS)
CFLAGS += $(DTLS_CFLAGS)
LD_ ?= gcc
LDFLAGS =
INCS = reg_server.h \
       registrar.h \
       $(I1)/coap_server.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_mem.h \
       $(I1)/coap_log.h \
       $(I1)/coap_ipv.h
INCS += $(DTLS_INCS)
OBJS = main.o \
       reg_server.o \
       registrar.o \
       coap_server.o \
       coap_msg.o \
       coap_mem.o \
       coap_log.o
OBJS += $(DTLS_OBJS)
LIBS =
PROG = reg_server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
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

clean:
	$(RM) $(PROG) $(OBJS)
