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

/**
 *  @file listener.c
 *
 *  @brief Source file for the FreeCoAP HTTP/CoAP proxy listener module
 */

#include <stdlib.h>
#include "listener.h"
#include "connection.h"
#include "sock.h"
#include "coap_log.h"

extern int go;

static void *listener_thread_func(void *data)
{
    listener_t *listener = (listener_t *)data;
    connection_t *con = NULL;
    tls_sock_t *sock = NULL;
    unsigned con_index = 0;
    thread_t thread = {0};
    int ret = 0;

    thread_block_signals();

    coap_log_notice("[%u] Listening on port %s", listener->index, param_get_port(listener->param));

    while (go)
    {
        sock = (tls_sock_t *)malloc(sizeof(tls_sock_t));
        if (sock == NULL)
        {
            coap_log_error("Out of memory");
            break;
        }

        ret = tls_ssock_accept(&listener->ssock, sock);
        if (ret != SOCK_OK)
        {
            free(sock);
            if (ret != SOCK_TIMEOUT)
            {
                coap_log_error("TLS socket error: %s", sock_strerror(ret));
            }
            continue;
        }

        con = connection_new(sock, listener->index, con_index++, listener->param);
        if (con == NULL)
        {
            coap_log_error("Unable to create connection data");
            tls_sock_close(sock);
            free(sock);
            break;
        }

        ret = thread_init(&thread, &listener->ctx, connection_thread_func, con);
        if (ret < 0)
        {
            coap_log_error("Unable to create connection thread");
            connection_delete(con);
            break;
        }
    }
    coap_log_notice("[%u] Stopped listening on port %s", listener->index, param_get_port(listener->param));
    listener_delete(listener);
    return NULL;
}


listener_t *listener_new(unsigned index, tls_server_t *server, param_t *param, int timeout, int backlog)
{
    listener_t *listener = NULL;
    int ret = 0;

    listener = (listener_t *)malloc(sizeof(listener_t));
    if (listener == NULL)
    {
        coap_log_error("Out of memory");
        return NULL;
    }

    listener->index = index;
    listener->param = param;

    ret = thread_detached_ctx_create(&listener->ctx);
    if (ret < 0)
    {
        coap_log_error("Unable to initialise thread context");
        free(listener);
        return NULL;
    }

    ret = tls_ssock_open(&listener->ssock, server, param_get_port(param), timeout, backlog);
    if (ret != SOCK_OK)
    {
        coap_log_error(sock_strerror(ret));
        thread_ctx_destroy(&listener->ctx);
        free(listener);
        return NULL;
    }

    return listener;
}

void listener_delete(listener_t *listener)
{
    tls_ssock_close(&listener->ssock);
    thread_ctx_destroy(&listener->ctx);
    free(listener);
}

int listener_run(listener_t *listener)
{
    thread_t thread = {0};
    int ret = 0;

    ret = thread_init(&thread, &listener->ctx, listener_thread_func, listener);
    if (ret < 0)
    {
        coap_log_error("Unable to create listener thread");
        return -1;
    }
    return 0;
}
