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
INCS = $(I2)/http_msg.h \
       $(I2)/util.h \
       $(T1)/test.h
OBJS = test_http_msg.o \
       http_msg.o \
       util.o \
       test.o
LIBS =
PROG = test_http_msg
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_http_msg.o: test_http_msg.c $(INCS)
	$(CC) $(CFLAGS) -c test_http_msg.c

http_msg.o: $(S2)/http_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/http_msg.c

util.o: $(S2)/util.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/util.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
