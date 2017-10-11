I1=../../include
S1=../../src
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
INCS = $(I2)/config.h \
       $(T1)/test.h
OBJS = test_config.o \
       config.o \
       test.o
LIBS =
PROG = test_config
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(OBJS) -o $(PROG) $(LDFLAGS) $(LIBS)

test_config.o: test_config.c $(INCS)
	$(CC_) $(CFLAGS) -c test_config.c

config.o: $(S2)/config.c $(INCS)
	$(CC_) $(CFLAGS) -c $(S2)/config.c

test.o: $(T1)/test.c $(INCS)
	$(CC_) $(CFLAGS) -c $(T1)/test.c

clean:
	$(RM) $(PROG) $(OBJS)
