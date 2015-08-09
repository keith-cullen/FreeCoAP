ifeq ($(dtls),y)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgnutls
endif

IDH = ../include
IDS = ../src

CC = gcc
CFLAGS = -Wall -g -I $(IDH)
CFLAGS += $(DTLS_CFLAGS)
LD = gcc
LDFLAGS =
INCS = $(IDH)/coap_server.h \
       $(IDH)/coap_msg.h \
       $(IDH)/coap_log.h
OBJS = server.o \
       coap_server.o \
       coap_msg.o \
       coap_log.o
LIBS += $(DTLS_LIBS)
PROG = server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

server.o: server.c $(INCS)
	$(CC) $(CFLAGS) -c server.c

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
