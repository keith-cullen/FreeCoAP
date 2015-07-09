IDH = ../include
IDS = ../src

CC = gcc
CFLAGS = -Wall -g -I $(IDH)
LD = gcc
LDFLAGS =
INCS = $(IDH)/coap_client.h \
       $(IDH)/coap_msg.h
OBJS = client.o \
       coap_client.o \
       coap_msg.o
PROG = client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

client.o: client.c $(INCS)
	$(CC) $(CFLAGS) -c client.c

coap_client.o: $(IDS)/coap_client.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_client.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

clean:
	$(RM) $(PROG) $(OBJS)
