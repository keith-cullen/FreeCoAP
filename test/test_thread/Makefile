I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
S2=../../proxy/common/src
T1=..
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(T1)
LD_ ?= gcc
LDFLAGS =
INCS = $(I2)/thread.h \
       $(T1)/test.h
OBJS = test_thread.o \
       thread.o \
       test.o
LIBS = -lpthread
PROG = test_thread
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_thread.o: test_thread.c $(INCS)
	$(CC_) $(CFLAGS) -c test_thread.c

thread.o: $(S2)/thread.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/thread.c

test.o: $(T1)/test.c $(INCS)
	$(CC_) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
