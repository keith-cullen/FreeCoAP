I1=../../lib/include
S1=../../lib/src
T1=..

CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(T1)
LD_ ?= gcc
LDFLAGS =
INCS = $(I1)/coap_msg.h \
       $(I1)/coap_log.h \
       $(T1)/test.h
OBJS = test_coap_msg.o \
       coap_msg.o \
       coap_log.o \
       test.o
LIBS =
PROG = test_coap_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_coap_msg.o: test_coap_msg.c $(INCS)
	$(CC_) $(CFLAGS) -c test_coap_msg.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_msg.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S1)/coap_log.c

test.o: $(T1)/test.c $(INCS)
	$(CC_) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
