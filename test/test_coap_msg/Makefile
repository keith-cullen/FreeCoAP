IDH=../../include
IDS=../../src
IDT=..

CFLAGS = $(EXTRA_CFLAGS) \
         --sysroot=$(ROOTFS) \
         -Wall \
         -I$(IDH) \
         -I$(IDT)
LDFLAGS = $(EXTRA_LDFLAGS) \
          --sysroot=$(ROOTFS)
INCS = $(IDH)/coap_msg.h \
       $(IDH)/coap_log.h \
       $(IDT)/test.h
OBJS = test_coap_msg.o \
       coap_msg.o \
       coap_log.o \
       test.o
LIBS = $(EXTRA_LIBS)
PROG = test_coap_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_coap_msg.o: test_coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c test_coap_msg.c

coap_msg.o: $(IDS)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_msg.c

coap_log.o: $(IDS)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDS)/coap_log.c

test.o: $(IDT)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(IDT)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
