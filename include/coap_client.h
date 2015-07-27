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
 *  @file coap_client.h
 *
 *  @brief Include file for the FreeCoAP client library
 */

#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

#include <time.h>
#include <netinet/in.h>
#include "coap_msg.h"

#define COAP_CLIENT_ADDR_BUF_LEN  128                                           /**< Buffer length for host addresses */

/**
 *  @brief Client structure
 */
typedef struct
{
    int sd;
    int timer_fd;
    struct timespec timeout;
    unsigned num_retrans;
    struct sockaddr_in6 server_sin;
    socklen_t server_sin_len;
    char server_addr[COAP_CLIENT_ADDR_BUF_LEN];
}
coap_client_t;

/**
 *  @brief Initialise a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] host Pointer to a string containing the host address of the server
 *  @param[in] port Port number of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno On error
 */
int coap_client_create(coap_client_t *client, const char *host, unsigned port);

/**
 *  @brief Deinitialise a client structure
 *
 *  @param[in] client Pointer to a client structure
 */
void coap_client_destroy(coap_client_t *client);

/**
 *  @brief Send a request to the server and receive the response
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] req Pointer to a message structure containing the request
 *  @param[out] resp Pointer to a message structure to store the response
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno On Error
 */
int coap_client_exchange(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp);

#endif
