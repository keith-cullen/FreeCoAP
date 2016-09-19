ifneq ($(dtls),n)
D1 = ../../org.eclipse.tinydtls
DTLS_CFLAGS = -DCOAP_DTLS_EN \
              -DWITH_SHA256 \
              -I $(D1)
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
            $(D1)/aes/rijndael.h \
            $(D1)/ecc/ecc.h \
            $(D1)/sha2/sha2.h
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
            sha2.o
endif

I1 = ../../lib/include
S1 = ../../lib/src

CC = gcc
CFLAGS = -Wall \
         -I $(I1)
CFLAGS += $(DTLS_CFLAGS)
LD = gcc
LDFLAGS =
INCS = $(I1)/coap_server.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h
INCS += $(DTLS_INCS)
OBJS = test_coap_server.o \
       coap_server.o \
       coap_msg.o \
       coap_log.o
OBJS += $(DTLS_OBJS)
LIBS =
PROG = test_coap_server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_coap_server.o: test_coap_server.c $(INCS)
	$(CC) $(CFLAGS) -c test_coap_server.c

coap_server.o: $(S1)/coap_server.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_server.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_msg.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

ccm.o: $(D1)/ccm.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/ccm.c

crypto.o: $(D1)/crypto.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/crypto.c

dtls.o: $(D1)/dtls.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/dtls.c

dtls_debug.o: $(D1)/dtls_debug.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/dtls_debug.c

dtls_time.o: $(D1)/dtls_time.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/dtls_time.c

hmac.o: $(D1)/hmac.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/hmac.c

netq.o: $(D1)/netq.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/netq.c

peer.o: $(D1)/peer.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/peer.c

session.o: $(D1)/session.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/session.c

rijndael.o: $(D1)/aes/rijndael.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/aes/rijndael.c

ecc.o: $(D1)/ecc/ecc.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/ecc/ecc.c

sha2.o: $(D1)/sha2/sha2.c $(INCS)
	$(CC) $(CFLAGS) -c $(D1)/sha2/sha2.c

clean:
	$(RM) $(PROG) $(OBJS)
