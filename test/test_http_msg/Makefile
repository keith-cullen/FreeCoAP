I1 = ../../proxy/common/include
S1 = ../../proxy/common/src
T1 = ..
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(T1)
LD_ ?= gcc
LDFLAGS =
INCS = $(I1)/http_msg.h \
       $(I1)/util.h \
       $(T1)/test.h
OBJS = test_http_msg.o \
       http_msg.o \
       util.o \
       test.o
LIBS =
PROG = test_http_msg
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
