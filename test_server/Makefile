ifeq ($(dtls),y)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgnutls
endif

IDH = ../include
IDS = ../src

CFLAGS = $(EXTRA_CFLAGS) \
         --sysroot=$(ROOTFS) \
         -Wall \
         -I $(IDH)
CFLAGS += $(DTLS_CFLAGS)
LDFLAGS = $(EXTRA_LDFLAGS) \
          --sysroot=$(ROOTFS) \
          -L$(ROOTFS)/usr/local/lib
INCS = $(IDH)/coap_server.h \
       $(IDH)/coap_msg.h \
       $(IDH)/coap_log.h
OBJS = test_server.o \
       coap_server.o \
       coap_msg.o \
       coap_log.o
LIBS += $(DTLS_LIBS)
PROG = test_server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_server.o: test_server.c $(INCS)
	$(CC) $(CFLAGS) -c test_server.c

coap_server.o: $(IDS)/coap_server.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_server.c

coap_server_dtls.o: $(IDS)/coap_server_dtls.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_server_dtls.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

coap_log.o: $(IDS)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_log.c

clean:
	$(RM) $(PROG) $(OBJS)
