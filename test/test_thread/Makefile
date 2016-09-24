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
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_thread.o: test_thread.c $(INCS)
	$(CC) $(CFLAGS) -c test_thread.c

thread.o: $(S2)/thread.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/thread.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
