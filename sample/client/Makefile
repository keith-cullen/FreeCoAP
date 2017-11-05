ifeq ($(ip6),y)
IP6_CFLAGS = -DCOAP_IP6
endif
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
I1 = ../../lib/include
S1 = ../../lib/src
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1)
CFLAGS += $(IP6_CFLAGS)
CFLAGS += $(DTLS_CFLAGS)
LD_ ?= gcc
LDFLAGS =
INCS = client.h \
       $(I1)/coap_client.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h \
       $(I1)/coap_ipv.h
OBJS = main.o \
       client.o \
       coap_client.o \
       coap_msg.o \
       coap_log.o
LIBS = $(DTLS_LIBS)
PROG = client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

main.o: main.c $(INCS)
	$(CC_) $(CFLAGS) -c main.c

client.o: client.c $(INCS)
	$(CC_) $(CFLAGS) -c client.c

coap_client.o: $(S1)/coap_client.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_client.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_msg.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_log.c

clean:
	$(RM) $(PROG) $(OBJS)
