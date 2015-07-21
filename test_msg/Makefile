IDH=../include
IDS=../src

CC = gcc
CFLAGS = -Wall -g -I$(IDH)
LD = gcc
LDFLAGS =
INCS = $(IDH)/coap_msg.h \
       harness.h
OBJS = test_msg.o \
       coap_msg.o \
       harness.o
LIBS =
PROG = test_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_msg.o: test_msg.c $(INCS)
	$(CC) $(CFLAGS) -c test_msg.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

harness.o: harness.c $(INCS)
	$(CC) $(CFLAGS) -c harness.c

clean:
	$(RM) $(PROG) $(OBJS)
