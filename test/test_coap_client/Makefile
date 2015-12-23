ifeq ($(dtls),y)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
endif

I1 = ../../lib/include
S1 = ../../lib/src
T1 = ..

CFLAGS = $(EXTRA_CFLAGS) \
         --sysroot=$(ROOTFS) \
         -Wall \
         -g \
         -I$(I1) \
         -I$(T1)
CFLAGS += $(DTLS_CFLAGS)
LDFLAGS = $(EXTRA_LDFLAGS) \
          --sysroot=$(ROOTFS) \
          -L$(ROOTFS)/usr/local/lib
INCS = $(I1)/coap_client.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h \
       $(T1)/test.h
OBJS = test_coap_client.o \
       coap_client.o \
       coap_msg.o \
       coap_log.o \
       test.o
LIBS += $(DTLS_LIBS)
PROG = test_coap_client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_coap_client.o: test_coap_client.c $(INCS)
	$(CC) $(CFLAGS) -c test_coap_client.c

coap_client.o: $(S1)/coap_client.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_client.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_msg.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
