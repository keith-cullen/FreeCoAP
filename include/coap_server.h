/*
 * Copyright (c) 2015 Keith Cullen.
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

#ifndef COAP_SERVER_H
#define COAP_SERVER_H

#include <time.h>
#include <netinet/in.h>
#include "coap_msg.h"

#define COAP_SERVER_MAX_TRANS  8

typedef struct
{
    int active;
    int timer_fd;
    struct timespec timeout;
    unsigned retransmit;
    struct sockaddr_in client_sin;
    socklen_t client_sin_len;
    coap_msg_t resp;
}
coap_server_trans_t;

typedef struct coap_server
{
    int sd;
    coap_server_trans_t trans[COAP_SERVER_MAX_TRANS];
    unsigned msg_id;
    int (* handle)(struct coap_server *, coap_msg_t *, coap_msg_t *);
}
coap_server_t;

int coap_server_create(coap_server_t *server, const char *host, unsigned port, int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *));
void coap_server_destroy(coap_server_t *server);
unsigned coap_server_get_next_msg_id(coap_server_t *server);
int coap_server_run(coap_server_t *server);

#endif
