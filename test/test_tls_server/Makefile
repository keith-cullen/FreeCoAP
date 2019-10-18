ifeq ($(ip6),y)
IP6_CFLAGS = -DSOCK_IP6
endif
I1 = ../../lib/include
S1 = ../../lib/src
I2 = ../../proxy/common/include
S2 = ../../proxy/common/src
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1) \
         -I$(I2) \
         -DTLS_CLIENT_AUTH
CFLAGS += $(IP6_CFLAGS)
LD_ ?= gcc
LDFLAGS =
INCS = $(I2)/tls_sock.h \
       $(I2)/sock.h \
       $(I2)/tls.h \
       $(I2)/util.h \
       $(I1)/coap_log.h
OBJS = test_tls_server.o \
       tls_sock.o \
       sock.o \
       tls.o \
       util.o \
       coap_log.o
LIBS = -lpthread \
       -lgnutls \
       -lnettle \
       -lhogweed \
       -lgmp
PROG = test_tls_server
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
