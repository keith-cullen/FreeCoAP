ifeq ($(ip6),y)
EXTRA_CFLAGS = -DCOAP_IP6
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

CC = gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(T1)
CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += $(DTLS_CFLAGS)
LD = gcc
LDFLAGS =
INCS = $(I1)/coap_client.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h \
       $(I1)/coap_ipv.h \
       $(T1)/test.h
OBJS = test_coap_client.o \
       coap_client.o \
       coap_msg.o \
       coap_log.o \
       test.o
LIBS = $(DTLS_LIBS)
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
