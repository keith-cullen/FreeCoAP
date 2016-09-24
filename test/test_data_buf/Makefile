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
INCS = $(I2)/data_buf.h \
       $(T1)/test.h
OBJS = test_data_buf.o \
       data_buf.o \
       test.o
LIBS =
PROG = test_data_buf
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

test_data_buf.o: test_data_buf.c $(INCS)
	$(CC) $(CFLAGS) -c test_data_buf.c

data_buf.o: $(S2)/data_buf.c $(INCS)
	$(CC) $(CFLAGS) -c $(S2)/data_buf.c

test.o: $(T1)/test.c $(INCS)
	$(CC) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
