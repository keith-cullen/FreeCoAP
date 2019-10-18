I1 = ../../lib/include
S1 = ../../lib/src
I2 = ../../proxy/common/include
S2 = ../../proxy/common/src
T1 = ..
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(T1)
LD_ ?= gcc
LDFLAGS =
INCS = $(I2)/cross.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_mem.h \
       $(I2)/http_msg.h \
       $(I2)/uri.h \
       $(I2)/util.h \
       $(I1)/coap_log.h \
       $(T1)/test.h
OBJS = test_cross.o \
       cross.o \
       coap_msg.o \
       coap_mem.o \
       http_msg.o \
       uri.o \
       util.o \
       coap_log.o \
       test.o
LIBS =
PROG = test_cross
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S2)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
