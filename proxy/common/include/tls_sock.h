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

#ifndef TLS_SOCK_H
#define TLS_SOCK_H

#include <stddef.h>         /* size_t */
#include <sys/types.h>      /* ssize_t */
#include <gnutls/gnutls.h>  /* gnutls_session_t */
#include "sock.h"           /* error codes */
#include "tls.h"            /* tls_init() */

#define tls_sock_get_type(s)                         ((s)->type)
#define tls_sock_get_sd(s)                           ((s)->sd)
#define tls_sock_get_sin(s)                          ((s)->sin)
#define tls_sock_get_addr(s)                         ((s)->sin.SOCK_SIN_ADDR)
#define tls_sock_get_port(s)                         (ntohs((s)->sin.SOCK_SIN_PORT))
#define tls_sock_get_addr_string(s, out, out_len)    (tls_sock_get_addr_string_(out, out_len, (s)->sin.SOCK_SIN_ADDR))
#define tls_sock_get_timeout(s)                      ((s)->timeout)
#define tls_sock_get_session(s)                      ((s)->session)
#define tls_sock_is_resumed(s)                       (gnutls_session_is_resumed((s)->session))

#define tls_ssoct_get_sd(ss)                         ((ss)->sd)
#define tls_ssock_get_sin(ss)                        ((ss)->sin)
#define tls_ssock_get_addr(ss)                       ((ss)->sin.SOCK_SIN_ADDR)
#define tls_ssock_get_port(ss)                       (ntohs((ss)->sin.SOCK_SIN_PORT))
#define tls_ssock_get_addr_string(ss, out, out_len)  (tls_sock_get_addr_string_(out, out_len, (ss)->sin.SOCK_SIN_ADDR))
#define tls_ssock_get_timeout(ss)                    ((ss)->timeout)

typedef enum {TLS_SOCK_CLIENT = 0, TLS_SOCK_SERVER} tls_sock_type_t;

typedef struct
{
    tls_sock_type_t type;
    union
    {
        tls_client_t *client;
        tls_server_t *server;
    }
    u;
    int sd;
    int timeout;
    sock_sockaddr_in_t sin;  /* remote address and port */
    gnutls_session_t session;
}
tls_sock_t;

typedef struct
{
    tls_server_t *server;
    int sd;
    int timeout;
    sock_sockaddr_in_t sin;  /* local address and port */
}
tls_ssock_t;

int tls_sock_open_from_sockaddr_in(tls_sock_t *s, tls_client_t *client, const char *common_name, int timeout, sock_sockaddr_in_t *sin);
int tls_sock_open(tls_sock_t *s, tls_client_t *client, const char *host, const char *port, const char *common_name, int timeout);
void tls_sock_close(tls_sock_t *s);
int tls_sock_rehandshake(tls_sock_t *s);
void tls_sock_get_addr_string_(char *out, size_t out_len, sock_in_addr_t sin_addr);
ssize_t tls_sock_read(tls_sock_t *s, void *buf, size_t len);
ssize_t tls_sock_read_full(tls_sock_t *s, void *buf, size_t len);
ssize_t tls_sock_write(tls_sock_t *s, void *buf, size_t len);
ssize_t tls_sock_write_full(tls_sock_t *s, void *buf, size_t len);

int tls_ssock_open(tls_ssock_t *ss, tls_server_t *server, const char *port, int timeout, int backlog);
void tls_ssock_close(tls_ssock_t *ss);
int tls_ssock_accept(tls_ssock_t *ss, tls_sock_t *s);

#endif
