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
INCS = $(I2)/uri.h \
       $(T1)/test.h
OBJS = test_uri.o \
       uri.o \
       test.o
LIBS = $(EXTRA_LIBS)
PROG = test_uri
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_uri.o: test_uri.c $(INCS)
	$(CC) $(CFLAGS) -c test_uri.c

uri.o: $(S2)/uri.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/uri.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
