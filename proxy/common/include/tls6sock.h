/*
 * Copyright (c) 2010 Keith Cullen.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *  @file tls6sock.h
 *
 *  @brief Include file for the FreeCoAP TLS/IPv6 socket library
 */

#ifndef TLS6SOCK_H
#define TLS6SOCK_H

#include <string.h>         /* size_t */
#include <unistd.h>         /* ssize_t */
#include <arpa/inet.h>      /* ntohs */
#include <netinet/in.h>     /* sockaddr_in */
#include <gnutls/gnutls.h>  /* gnutls_session_t */
#include "sock.h"           /* error codes */
#include "tls.h"            /* tls_init() */

#define tls6sock_get_type(s)                         ((s)->type)
#define tls6sock_get_sd(s)                           ((s)->sd)
#define tls6sock_get_sin(s)                          ((s)->sin)
#define tls6sock_get_addr(s)                         ((s)->sin.sin6_addr)
#define tls6sock_get_port(s)                         (ntohs((s)->sin.sin6_port))
#define tls6sock_get_addr_string(s, out, out_len)    (tls6sock_get_addr_string_(out, out_len, (s)->sin.sin6_addr))
#define tls6sock_get_timeout(s)                      ((s)->timeout)
#define tls6sock_get_session(s)                      ((s)->session)
#define tls6sock_is_resumed(s)                       (gnutls_session_is_resumed((s)->session))

#define tls6ssock_get_sd(ss)                         ((ss)->sd)
#define tls6ssock_get_sin(ss)                        ((ss)->sin)
#define tls6ssock_get_addr(ss)                       ((ss)->sin.sin6_addr)
#define tls6ssock_get_port(ss)                       (ntohs((ss)->sin.sin6_port))
#define tls6ssock_get_addr_string(ss, out, out_len)  (tls6sock_get_addr_string_(out, out_len, (ss)->sin.sin6_addr))
#define tls6ssock_get_timeout(ss)                    ((ss)->timeout)

typedef enum {TLS6SOCK_CLIENT = 0, TLS6SOCK_SERVER} tls6sock_type_t;

typedef struct
{
    tls6sock_type_t type;
    int sd;
    int timeout;
    struct sockaddr_in6 sin;  /* remote address and port */
    gnutls_session_t session;
}
tls6sock_t;

typedef struct
{
    int sd;
    int timeout;
    struct sockaddr_in6 sin;  /* local address and port */
}
tls6ssock_t;

int tls6sock_open_from_sockaddr_in6(tls6sock_t *s, const char *common_name, int timeout, struct sockaddr_in6 *sin);
int tls6sock_open(tls6sock_t *s, const char *host, const char *port, const char *common_name, int timeout);
void tls6sock_close(tls6sock_t *s);
int tls6sock_rehandshake(tls6sock_t *s);
void tls6sock_get_addr_string_(char *out, size_t out_len, struct in6_addr sin6_addr);
ssize_t tls6sock_read(tls6sock_t *s, void *buf, size_t len);
ssize_t tls6sock_read_full(tls6sock_t *s, void *buf, size_t len);
ssize_t tls6sock_write(tls6sock_t *s, void *buf, size_t len);
ssize_t tls6sock_write_full(tls6sock_t *s, void *buf, size_t len);

int tls6ssock_open(tls6ssock_t *ss, const char *port, int timeout, int backlog);
void tls6ssock_close(tls6ssock_t *ss);
int tls6ssock_accept(tls6ssock_t *ss, tls6sock_t *s);

#endif
