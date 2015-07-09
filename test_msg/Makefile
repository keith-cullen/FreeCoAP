IDH=../include
IDS=../src
ID1=../harness

CC = gcc
CFLAGS = -Wall -g -I$(IDH) -I$(ID1)
LD = gcc
LDFLAGS =
INCS = $(IDH)/coap_msg.h \
       $(ID1)/harness.h
OBJS = test_coap_msg.o \
       coap_msg.o \
       harness.o
LIBS =
PROG = test_coap_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_coap_msg.o: test_coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c test_coap_msg.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

harness.o: $(ID1)/harness.c $(INCS)
	$(CC) $(CFLAGS) -c $(ID1)/harness.c

clean:
	$(RM) $(PROG) $(OBJS)
