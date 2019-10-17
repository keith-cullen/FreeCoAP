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
       $(I1)/coap_mem.h \
       $(I1)/coap_log.h \
       $(T1)/test.h
OBJS = test_coap_msg.o \
       coap_msg.o \
       coap_mem.o \
       coap_log.o \
       test.o
LIBS =
PROG = test_coap_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
