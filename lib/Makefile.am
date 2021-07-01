AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = -I$(srcdir)/include -DCOAP_DTLS_EN
lib_LTLIBRARIES = libfreecoap.la
libfreecoap_la_SOURCES = src/coap_msg.c include/coap_msg.h src/coap_log.c include/coap_log.h src/coap_client.c include/coap_client.h src/coap_server.c include/coap_server.h include/coap_ipv.h src/coap_mem.c include/coap_mem.h
libfreecoap_la_LDFLAGS = -version-info 0:5:0
include_HEADERS = include/coap_msg.h include/coap_log.h include/coap_client.h include/coap_server.h include/coap_ipv.h include/coap_mem.h
