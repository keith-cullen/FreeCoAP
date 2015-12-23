ifeq ($(dtls),y)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
endif

I1 = ../../lib/include
S1 = ../../lib/src

CFLAGS = $(EXTRA_CFLAGS) \
         --sysroot=$(ROOTFS) \
         -Wall \
         -I $(I1)
CFLAGS += $(DTLS_CFLAGS)
LDFLAGS = $(EXTRA_LDFLAGS) \
          --sysroot=$(ROOTFS) \
          -L$(ROOTFS)/usr/local/lib
INCS = $(I1)/coap_server.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h
OBJS = test_coap_server.o \
       coap_server.o \
       coap_msg.o \
       coap_log.o
LIBS += $(DTLS_LIBS)
PROG = test_coap_server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_coap_server.o: test_coap_server.c $(INCS)
	$(CC) $(CFLAGS) -c test_coap_server.c

coap_server.o: $(S1)/coap_server.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_server.c

coap_server_dtls.o: $(S1)/coap_server_dtls.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_server_dtls.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_msg.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

clean:
	$(RM) $(PROG) $(OBJS)
