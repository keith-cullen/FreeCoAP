IDH=../include
IDS=../src
IDT=../test

CC = gcc
CFLAGS = -Wall -g -I$(IDH) -I$(IDT)
LD = gcc
LDFLAGS =
INCS = $(IDH)/coap_msg.h \
       $(IDT)/test.h
OBJS = test_msg.o \
       coap_msg.o \
       coap_log.o \
       test.o
LIBS =
PROG = test_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_msg.o: test_msg.c $(INCS)
	$(CC) $(CFLAGS) -c test_msg.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

coap_log.o: $(IDS)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_log.c

test.o: $(IDT)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDT)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
