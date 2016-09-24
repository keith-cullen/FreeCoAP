I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
S2=../../proxy/common/src
T1=..

CC = gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(T1)
LD = gcc
LDFLAGS = $(EXTRA_LDFLAGS) \
          --sysroot=$(ROOTFS)
INCS = $(I2)/cross.h \
       $(I1)/coap_msg.h \
       $(I2)/http_msg.h \
       $(I2)/uri.h \
       $(I2)/util.h \
       $(I1)/coap_log.h \
       $(T1)/test.h
OBJS = test_cross.o \
       cross.o \
       coap_msg.o \
       http_msg.o \
       uri.o \
       util.o \
       coap_log.o \
       test.o
LIBS = $(EXTRA_LIBS)
PROG = test_cross
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_cross.o: test_cross.c $(INCS)
	$(CC) $(CFLAGS) -c test_cross.c

cross.o: $(S2)/cross.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/cross.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_msg.c

http_msg.o: $(S2)/http_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/http_msg.c

uri.o: $(S2)/uri.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/uri.c

util.o: $(S2)/util.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/util.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
