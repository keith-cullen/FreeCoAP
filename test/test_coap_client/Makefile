ifeq ($(dtls),y)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
endif

IDH = ../../include
IDS = ../../src
IDT = ..

CFLAGS = $(EXTRA_CFLAGS) \
         --sysroot=$(ROOTFS) \
         -Wall \
         -g \
         -I$(IDH) \
         -I$(IDT)
CFLAGS += $(DTLS_CFLAGS)
LDFLAGS = $(EXTRA_LDFLAGS) \
          --sysroot=$(ROOTFS) \
          -L$(ROOTFS)/usr/local/lib
INCS = $(IDH)/coap_client.h \
       $(IDH)/coap_msg.h \
       $(IDH)/coap_log.h \
       $(IDT)/test.h
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

coap_client.o: $(IDS)/coap_client.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_client.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

coap_log.o: $(IDS)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_log.c

test.o: $(IDT)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDT)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
