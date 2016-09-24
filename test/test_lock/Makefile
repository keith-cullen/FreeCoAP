I1=../../lib/include
S1=../../lib/src
I2=../../proxy/common/include
T1=..

CC = gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -I$(T1)
LD = gcc
LDFLAGS =
INCS = $(I2)/lock.h \
       $(T1)/test.h
OBJS = test_lock.o \
       test.o
LIBS = -lpthread
PROG = test_lock
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_lock.o: test_lock.c $(INCS)
	$(CC) $(CFLAGS) -c test_lock.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
