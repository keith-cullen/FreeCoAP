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
 *  @file coap_server.h
 *
 *  @brief Include file for the FreeCoAP server library
 */

#ifndef COAP_SERVER_H
#define COAP_SERVER_H

#include <time.h>
#include <netinet/in.h>
#include "coap_msg.h"

#define COAP_SERVER_MAX_TRANS     8                                             /**< Maximum number of active transactions per server */
#define COAP_SERVER_ADDR_BUF_LEN  128                                           /**< Buffer length for host addresses */

/**
 *  @brief Response type enumeration
 */
typedef enum
{
    COAP_SERVER_PIGGYBACKED = 0,
    COAP_SERVER_SEPARATE = 1
}
coap_server_resp_t;

/**
 *  @brief Transaction structure
 */
typedef struct
{
    int active;
    int timer_fd;
    struct timespec timeout;
    unsigned num_retrans;
    struct sockaddr_in6 client_sin;
    socklen_t client_sin_len;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN];
    coap_msg_t req;
    coap_msg_t resp;
}
coap_server_trans_t;

/**
 *  @brief Server structure
 */
typedef struct coap_server
{
    int sd;
    unsigned msg_id;
    struct sockaddr_in6 client_sin;
    socklen_t client_sin_len;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN];
    coap_server_trans_t trans[COAP_SERVER_MAX_TRANS];
    int (* handle)(struct coap_server *, coap_msg_t *, coap_msg_t *);
}
coap_server_t;

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] host Pointer to a string containing the host address of the server
 *  @param[in] port Port number of the server
 *  @param[in] handle Call-back function to handle client requests
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
int coap_server_create(coap_server_t *server, const char *host, unsigned port, int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *));

/**
 *  @brief Deinitialise a server structure
 *
 *  @param[in] server Pointer to a server structure
 */
void coap_server_destroy(coap_server_t *server);

/**
 *  @brief Get a new message ID value
 *
 *  @param[in] server Pointer to a server structure
 *
 *  @returns message ID value
 */
unsigned coap_server_get_next_msg_id(coap_server_t *server);

/**
 *  @brief Run the server
 *
 *  Listen for incoming requests. For each request received,
 *  call the handle call-back function in the server structure
 *  and send the response to the client.
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
int coap_server_run(coap_server_t *server);

#endif
