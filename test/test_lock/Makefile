I1 = ../../proxy/common/include
T1 = ..
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(T1)
LD_ ?= gcc
LDFLAGS =
INCS = $(I1)/lock.h \
       $(T1)/test.h
OBJS = test_lock.o \
       test.o
LIBS = -lpthread
PROG = test_lock
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
