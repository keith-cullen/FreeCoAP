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
 *  @file coap_server.c
 *
 *  @brief Source file for the FreeCoAP server library
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/timerfd.h>
#include "coap_server.h"
#include "coap_log.h"

#define COAP_SERVER_ACK_TIMEOUT_SEC  2                                          /**< Minimum delay to wait before retransmitting a confirmable message */
#define COAP_SERVER_MAX_RETRANSMIT   4                                          /**< Maximum number of times a confirmable message can be retransmitted */

static int rand_init = 0;                                                       /**< Indicates if the random number generator has been initialised */

/****************************************************************************************************
 *                                        coap_server_trans                                         *
 ****************************************************************************************************/

/**
 *  @brief Deinitialise a transaction structure
 *
 *  @param[in] trans Pointer to a transaction structure
 */
static void coap_server_trans_destroy(coap_server_trans_t *trans)
{
    coap_log_debug("Destroyed transaction for address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    coap_msg_destroy(&trans->resp);
    coap_msg_destroy(&trans->req);
    close(trans->timer_fd);
    memset(trans, 0, sizeof(coap_server_trans_t));
}

/**
 *  @brief Mark the last time the transaction structure was used
 *
 *  @param trans Pointer to a transaction structure
 */
static void coap_server_trans_touch(coap_server_trans_t *trans)
{
    trans->last_use = time(NULL);
}

/**
 *  @brief Compare a received message with the request part of a transaction structure
 *
 *  @param[in] trans Pointer to a trasaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Comparison value
 *  @retval 0 The message does not match the transaction
 *  @retval 1 The message matches the transaction
 */
static int coap_server_trans_match_req(coap_server_trans_t *trans, coap_msg_t *msg)
{
    return ((trans->active) && (trans->req.msg_id == msg->msg_id));
}

/**
 *  @brief Compare a recevied message with the response part of a transaction structure
 *
 *  @param[in] trans Pointer to a trasaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Comparison value
 *  @retval 0 The message does not match the transaction
 *  @retval 1 The message matches the transaction
 */
static int coap_server_trans_match_resp(coap_server_trans_t *trans, coap_msg_t *msg)
{
    return ((trans->active) && (trans->resp.msg_id == msg->msg_id));
}

/**
 *  @brief Clear the request message in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 */
static void coap_server_trans_clear_req(coap_server_trans_t *trans)
{
    coap_msg_destroy(&trans->req);
}

/**
 *  @brief Clear the response message in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 */
static void coap_server_trans_clear_resp(coap_server_trans_t *trans)
{
    coap_msg_destroy(&trans->resp);
}

/**
 *  @brief Set the request message in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_set_req(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_destroy(&trans->req);
    return coap_msg_copy(&trans->req, msg);
}

/**
 *  @brief Set the response message in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_set_resp(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_destroy(&trans->resp);
    return coap_msg_copy(&trans->resp, msg);
}

/**
 *  @brief Initialise the acknowledgement timer in a transaction structure
 *
 *  The timer is initialised to a random duration between:
 *
 *  ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
 *  where:
 *  ACK_TIMEOUT = 2
 *  ACK_RANDOM_FACTOR = 1.5
 *
 *  @param[out] trans Pointer to a transaction structure
 */
static void coap_server_trans_init_ack_timeout(coap_server_trans_t *trans)
{
    if (!rand_init)
    {
        srand(time(NULL));
        rand_init = 1;
    }
    trans->timeout.tv_sec = COAP_SERVER_ACK_TIMEOUT_SEC;
    trans->timeout.tv_nsec = (rand() % 1000) * 1000000;
    coap_log_debug("Acknowledgement timeout initialised to: %lu sec, %lu nsec", trans->timeout.tv_sec, trans->timeout.tv_nsec);
}

/**
 *  @brief Double the value of the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a trans structure
 */
static void coap_server_trans_double_timeout(coap_server_trans_t *trans)
{
    unsigned msec = 2 * ((trans->timeout.tv_sec * 1000)
                      + (trans->timeout.tv_nsec / 1000000));
    trans->timeout.tv_sec = msec / 1000;
    trans->timeout.tv_nsec = (msec % 1000) * 1000000;
    coap_log_debug("Timeout doubled to: %lu sec, %lu nsec", trans->timeout.tv_sec, trans->timeout.tv_nsec);
}

/**
 *  @brief Clear the timer in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 */
static void coap_server_trans_clear_timer(coap_server_trans_t *trans)
{
    uint64_t r = 0;
    read(trans->timer_fd, &r, sizeof(r));
}

/**
 *  @brief Start the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_start_timer(coap_server_trans_t *trans)
{
    struct itimerspec its = {{0}};
    int ret = 0;

    its.it_value = trans->timeout;
    ret = timerfd_settime(trans->timer_fd, 0, &its, NULL);
    if (ret == -1)
    {
        return -errno;
    }
    return 0;
}

/**
 *  @brief Stop the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_stop_timer(coap_server_trans_t *trans)
{
    struct itimerspec its = {{0}};
    int ret = 0;

    ret = timerfd_settime(trans->timer_fd, 0, &its, NULL);
    if (ret == -1)
    {
        return -errno;
    }
    coap_server_trans_clear_timer(trans);
    return 0;
}

/**
 *  @brief Initialise and start the acknowledgement timer in a transaction structure
 *
 *  @param[out] trans Pointer to a trans structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_start_ack_timer(coap_server_trans_t *trans)
{
    trans->num_retrans = 0;
    coap_server_trans_init_ack_timeout(trans);
    return coap_server_trans_start_timer(trans);
}

/**
 *  @brief Stop the acknowledgement timer in a transaction structure
 *
 *  @param[in] trans Pointer to a transaction structure
 */
static int coap_server_trans_stop_ack_timer(coap_server_trans_t *trans)
{
    trans->num_retrans = 0;
    return coap_server_trans_stop_timer(trans);
}

/**
 *  @brief Update the acknowledgement timer in a transaction structure
 *
 *  Increase and restart the acknowledgement timer in a transaction structure
 *  and indicate if the maximum number of retransmits has been reached.
 *
 *  @param[in,out] trans Pointer to a trans structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_update_ack_timer(coap_server_trans_t *trans)
{
    int ret = 0;

    coap_server_trans_clear_timer(trans);
    if (trans->num_retrans >= COAP_SERVER_MAX_RETRANSMIT)
    {
        return -ETIMEDOUT;
    }
    coap_server_trans_double_timeout(trans);
    ret = coap_server_trans_start_timer(trans);
    if (ret < 0)
    {
        return ret;
    }
    trans->num_retrans++;
    return 0;
}

/**
 *  @brief Send a message to the client
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >= 0 Number of bytes sent
 *  @retval -errno Error
 */
static int coap_server_trans_send(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_server_t *server = NULL;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;

    server = trans->server;
    num = coap_msg_format(msg, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
    num = sendto(server->sd, buf, num, 0, (struct sockaddr *)&trans->client_sin, trans->client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    coap_server_trans_touch(trans);
    coap_log_debug("Sent to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    return num;
}

/**
 *  @brief Handle a format error in a received message
 *
 *  Special handling for the case where a received
 *  message could not be parsed due to a format error.
 *  Extract enough information from the received message
 *  to form a reset message.
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] buf Buffer containing the message
 *  @param[in] len length of the buffer
 */
static void coap_server_trans_handle_format_error(coap_server_trans_t *trans, char *buf, unsigned len)
{
    coap_msg_t msg = {0};
    unsigned msg_id = 0;
    unsigned type = 0;
    int ret = 0;

    /* extract enough information to form a reset message */
    ret = coap_msg_parse_type_msg_id(buf, len, &type, &msg_id);
    if ((ret == 0) && (type == COAP_MSG_CON))
    {
        coap_msg_create(&msg);
        ret = coap_msg_set_type(&msg, COAP_MSG_RST);
        if (ret < 0)
        {
            coap_msg_destroy(&msg);
            return;
        }
        ret = coap_msg_set_msg_id(&msg, msg_id);
        if (ret < 0)
        {
            coap_msg_destroy(&msg);
            return;
        }
        coap_server_trans_send(trans, &msg);
        coap_msg_destroy(&msg);
    }
}

/**
 *  @brief Receive a message from the client
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes received or error code
 *  @retval >= 0 Number of bytes received
 *  @retval -errno Error
 */
static ssize_t coap_server_trans_recv(coap_server_trans_t *trans, coap_msg_t *msg)
{
    struct sockaddr_in6 client_sin = {0};
    coap_server_t *server = NULL;
    socklen_t client_sin_len = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    server = trans->server;
    client_sin_len = sizeof(client_sin);
    num = recvfrom(server->sd, buf, sizeof(buf), 0, (struct sockaddr *)&client_sin, &client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    if ((client_sin_len != trans->client_sin_len)
     || (memcmp(&client_sin, &trans->client_sin, client_sin_len) != 0))
    {
        return -EINVAL;
    }
    ret = coap_msg_parse(msg, buf, num);
    if (ret == -EBADMSG)
    {
        coap_server_trans_handle_format_error(trans, buf, num);
    }
    if (ret < 0)
    {
        return ret;
    }
    coap_server_trans_touch(trans);
    coap_log_debug("Received from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    return num;
}

/**
 *  @brief Reject a received confirmable message
 *
 *  Send a reset message to the client.
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_reject_con(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_t rej = {0};
    int num = 0;
    int ret = 0;

    coap_log_info("Rejecting confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    coap_msg_create(&rej);
    ret = coap_msg_set_type(&rej, COAP_MSG_RST);
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    ret = coap_msg_set_msg_id(&rej, coap_msg_get_msg_id(msg));
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    num = coap_server_trans_send(trans, &rej);
    coap_msg_destroy(&rej);
    if (num < 0)
    {
        return num;
    }
    return 0;
}

/**
 *  @brief Reject a received non-confirmable message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int coap_server_trans_reject_non(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_log_info("Rejecting non-confirmable message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    return 0;
}

/**
 *  @brief Reject a received message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_reject(coap_server_trans_t *trans, coap_msg_t *msg)
{
    if (coap_msg_get_type(msg) == COAP_MSG_CON)
    {
        return coap_server_trans_reject_con(trans, msg);
    }
    return coap_server_trans_reject_non(trans, msg);
}

/**
 *  @brief Send an acknowledgement message to the client
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_send_ack(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_t ack = {0};
    int num = 0;
    int ret = 0;

    coap_log_info("Acknowledging confirmable message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    coap_msg_create(&ack);
    ret = coap_msg_set_type(&ack, COAP_MSG_ACK);
    if (ret < 0)
    {
        coap_msg_destroy(&ack);
        return ret;
    }
    ret = coap_msg_set_msg_id(&ack, coap_msg_get_msg_id(msg));
    if (ret < 0)
    {
        coap_msg_destroy(&ack);
        return ret;
    }
    num = coap_server_trans_send(trans, &ack);
    coap_msg_destroy(&ack);
    if (num < 0)
    {
        return num;
    }
    return 0;
}

/**
 *  @brief Handle an acknowledgement timeout
 *
 *  Update the acknowledgement timer in the transaction structure
 *  and if the maximum number of retransmits has not been reached
 *  then retransmit the last response to the client.
 *
 *  @param[in,out] server Pointer to a client structure
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_handle_ack_timeout(coap_server_trans_t *trans)
{
    int num = 0;
    int ret = 0;

    coap_log_debug("Transaction expired for address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    ret = coap_server_trans_update_ack_timer(trans);
    if (ret == 0)
    {
        coap_log_debug("Retransmitting to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
        num = coap_server_trans_send(trans, &trans->resp);
        if (num < 0)
        {
            return num;
        }
    }
    else if (ret == -ETIMEDOUT)
    {
        coap_log_debug("Stopped retransmitting to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
        coap_log_info("No acknowledgement received from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
        coap_server_trans_destroy(trans);
    }
    return 0;
}

/**
 *  @brief Initialise a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a struct sockaddr_in6
 *  @param[in] client_sin_len Length of the struct sockaddr_in6
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_trans_create(coap_server_trans_t *trans, coap_server_t *server, struct sockaddr_in6 *client_sin, socklen_t client_sin_len)
{
    const char *p = NULL;

    memset(trans, 0, sizeof(coap_server_trans_t));
    trans->server = server;
    trans->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (trans->timer_fd == -1)
    {
        memset(trans, 0, sizeof(coap_server_trans_t));
        return -errno;
    }
    memcpy(&trans->client_sin, client_sin, client_sin_len);
    trans->client_sin_len = client_sin_len;
    p = inet_ntop(AF_INET6, &client_sin->sin6_addr, trans->client_addr, sizeof(trans->client_addr));
    if (p == NULL)
    {
        close(trans->timer_fd);
        memset(trans, 0, sizeof(coap_server_trans_t));
        return -errno;
    }
    coap_server_trans_touch(trans);
    trans->active = 1;
    coap_log_debug("Created transaction for address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    return 0;
}

/****************************************************************************************************
 *                                           coap_server                                            *
 ****************************************************************************************************/

int coap_server_create(coap_server_t *server, const char *host, unsigned port, int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *))
{
    struct sockaddr_in6 server_sin = {0};
    unsigned char msg_id[2] = {0};
    const char *p = NULL;
    socklen_t server_sin_len = 0;
    char server_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    int opt_val = 0;
    int flags = 0;
    int ret = 0;

    if ((server == NULL) || (host == NULL))
    {
        return -EINVAL;
    }
    memset(server, 0, sizeof(coap_server_t));
    server->sd = socket(PF_INET6, SOCK_DGRAM, 0);
    if (server->sd == -1)
    {
        memset(server, 0, sizeof(coap_server_t));
        return -errno;
    }
    flags = fcntl(server->sd, F_GETFL, 0);
    if (flags == -1)
    {
        coap_server_destroy(server);
        return -errno;
    }
    ret = fcntl(server->sd, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1)
    {
        coap_server_destroy(server);
        return -errno;
    }
    opt_val = 1;
    ret = setsockopt(server->sd, SOL_SOCKET, SO_REUSEADDR, &opt_val, (socklen_t)sizeof(opt_val));
    if (ret == -1)
    {
        coap_server_destroy(server);
        return -errno;
    }
    server_sin.sin6_family = AF_INET6;
    server_sin.sin6_port = htons(port);
    ret = inet_pton(AF_INET6, host, &server_sin.sin6_addr);
    if (ret == 0)
    {
        coap_server_destroy(server);
        return -EINVAL;
    }
    else if (ret == -1)
    {
        coap_server_destroy(server);
        return -errno;
    }
    server_sin_len = sizeof(server_sin);
    ret = bind(server->sd, (struct sockaddr *)&server_sin, server_sin_len);
    if (ret == -1)
    {
        coap_server_destroy(server);
        return -errno;
    }
    coap_msg_gen_rand_str((char *)msg_id, sizeof(msg_id));
    server->msg_id = (((unsigned)msg_id[1]) << 8) | (unsigned)msg_id[0];
    server->handle = handle;
    p = inet_ntop(AF_INET6, &server_sin.sin6_addr, server_addr, sizeof(server_addr));
    if (p == NULL)
    {
        coap_server_destroy(server);
        return -errno;
    }
    coap_log_notice("Listening on address %s and port %d", server_addr, ntohs(server_sin.sin6_port));
    return 0;
}

void coap_server_destroy(coap_server_t *server)
{
    close(server->sd);
    memset(server, 0, sizeof(coap_server_t));
}

unsigned coap_server_get_next_msg_id(coap_server_t *server)
{
    unsigned char msg_id[2] = {0};

    server->msg_id++;
    while (server->msg_id > COAP_MSG_MAX_MSG_ID)
    {
        coap_msg_gen_rand_str((char *)msg_id, sizeof(msg_id));
        server->msg_id = (((unsigned)msg_id[1]) << 8) | (unsigned)msg_id[0];
    }
    return server->msg_id;
}

/**
 *  @brief Search for a transaction structure in a server structure that matches an endpoint
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a struct sockaddr_in6
 *  @param[in] client_sin_len Length of the struct sockaddr_in6
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No matching transaction structure found
 */
static coap_server_trans_t *coap_server_find_trans(coap_server_t *server, struct sockaddr_in6 *client_sin, socklen_t client_sin_len)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
    {
        trans = &server->trans[i];
        if ((trans->active)
         && (trans->client_sin_len == client_sin_len)
         && (memcmp(&trans->client_sin, client_sin, client_sin_len) == 0))
        {
            coap_log_debug("Found existing transaction at index %u", i);
            return trans;
        }
    }
    return NULL;
}

/**
 *  @brief Search for an empty transaction structure in a server structure
 *
 *  @param[in] server Pointer to a server structure
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No empty transaction structures available
 */
static coap_server_trans_t *coap_server_find_empty_trans(coap_server_t *server)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
    {
        trans = &server->trans[i];
        if (!trans->active)
        {
            coap_log_debug("Found empty transaction at index %u", i);
            return trans;
        }
    }
    return NULL;
}

/**
 *  @brief Search for oldest transaction structure in a server structure
 *
 *  Search for the transaction structure in a server structure that was
 *  used least recently.
 *
 *  @param[in] server Pointer to a server structure
 *
 *  @returns Pointer to a transaction structure
 */
static coap_server_trans_t *coap_server_find_oldest_trans(coap_server_t *server)
{
    coap_server_trans_t *oldest = NULL;
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;
    unsigned j = 0;
    time_t min_last_use = 0;

    for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
    {
        trans = &server->trans[i];
        if (trans->active)
        {
            if ((min_last_use == 0) || (trans->last_use < min_last_use))
            {
                oldest = trans;
                min_last_use = trans->last_use;
                j = i;
            }
        }
    }
    coap_log_debug("Found oldest transaction at index %u", j);
    return oldest != NULL ? oldest : &server->trans[0];
}

/**
 *  @brief Wait for a message to arrive or an acknowledgement
 *         timer in any of the active transactions to expire
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 */
static int coap_server_listen(coap_server_t *server)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;
    fd_set read_fds = {{0}};
    int max_fd = 0;
    int ret = 0;

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(server->sd, &read_fds);
        max_fd = server->sd;
        for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
        {
            trans = &server->trans[i];
            if (trans->active)
            {
                FD_SET(trans->timer_fd, &read_fds);
                if (trans->timer_fd > max_fd)
                {
                    max_fd = trans->timer_fd;
                }
            }
        }
        ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ret == -1)
        {
            return -errno;
        }
        if (FD_ISSET(server->sd, &read_fds))
        {
            return 0;
        }
        for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
        {
            trans = &server->trans[i];
            if ((trans->active) && (FD_ISSET(trans->timer_fd, &read_fds)))
            {
                ret = coap_server_trans_handle_ack_timeout(trans);
                if (ret < 0)
                {
                    return ret;
                }
            }
        }
    }
    return 0;
}

/**
 *  @brief Accept an incoming connection
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a struct sockaddr_in6
 *  @param[in] client_sin_len Length of the struct sockaddr_in6
 *
 *  Get the address and port number of the client.
 *  Do not read the received data.
 *
 *  @returns Number of bytes received or error code
 *  @retval 0 Success
 *  @retval -errno Error
 */
static ssize_t coap_server_accept(coap_server_t *server, struct sockaddr_in6 *client_sin, socklen_t *client_sin_len)
{
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;

    *client_sin_len = sizeof(struct sockaddr_in6);
    num = recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *)client_sin, client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    return 0;
}

/**
 *  @brief Determine whether a request warrants a piggy-backed
 *         response or a separate response
 *
 *  This function makes the decision on whether to send a separate
 *  response or a piggy backed response. It will eventually look-up
 *  the uri-path from the request message in a user supplied table
 *  to make the decision, the idea being that some resources will
 *  require time to retrieve and others will not.
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Response type
 *  @retval COAP_SERVER_PIGGYBACKED Piggy-backed response
 *  @retval COAP_SERVER_SEPARATE Separate response
 */ 
static int coap_server_get_resp_type(coap_server_t *server, coap_msg_t *msg)
{
//    return COAP_SERVER_PIGGYBACKED;
    return COAP_SERVER_SEPARATE;
}

/**
 *  @brief Receive a request from the client and send the response
 *
 *  @param[in,out] server Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -errno Error
 **/
static int coap_server_exchange(coap_server_t *server)
{
    struct sockaddr_in6 client_sin = {0};
    coap_server_trans_t *trans = NULL;
    coap_msg_t recv_msg = {0};
    coap_msg_t send_msg = {0};
    socklen_t client_sin_len = 0;
    unsigned msg_id = 0;
    int resp_type = 0;
    int num = 0;
    int ret = 0;

    /* accept incoming connection */
    ret = coap_server_accept(server, &client_sin, &client_sin_len);
    if (ret < 0)
    {
        return ret;
    }

    /* find or create transaction */
    trans = coap_server_find_trans(server, &client_sin, client_sin_len);
    if (trans == NULL)
    {
        trans = coap_server_find_empty_trans(server);
        if (trans == NULL)
        {
            trans = coap_server_find_oldest_trans(server);
            coap_server_trans_destroy(trans);
        }
        ret = coap_server_trans_create(trans, server, &client_sin, client_sin_len);
        if (ret < 0)
        {
            return ret;
        }
    }

    /* receive message */
    coap_msg_create(&recv_msg);
    num = coap_server_trans_recv(trans, &recv_msg);
    if (num < 0)
    {
        coap_msg_destroy(&recv_msg);
        return num;
    }

    /* check for duplicate request */
    if (coap_server_trans_match_req(trans, &recv_msg))
    {
        if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
        {
            /* message deduplication */
            /* acknowledge the (confirmable) request again */
            /* do not send the response again */
            coap_log_info("Received duplicate confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
            ret = coap_server_trans_send_ack(trans, &recv_msg);
            coap_msg_destroy(&recv_msg);
            return ret;
        }
        else if (coap_msg_get_type(&recv_msg) == COAP_MSG_NON)
        {
            /* message deduplication */
            /* do not acknowledge the (non-confirmable) request again */
            /* do not send the response again */
            coap_log_info("Received duplicate non-confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
            coap_msg_destroy(&recv_msg);
            return 0;
        }
    }

    /* check for an ack for a previous response */
    if (coap_server_trans_match_resp(trans, &recv_msg))
    {
        if (coap_msg_get_type(&recv_msg) == COAP_MSG_ACK)
        {
            /* the server must stop num_retransmitting its response */
            /* on any matching acknowledgement or reset message */
            coap_log_info("Received acknowledgement from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
            ret = coap_server_trans_stop_ack_timer(trans);
            coap_msg_destroy(&recv_msg);
            return ret;
        }
        else if (coap_msg_get_type(&recv_msg) == COAP_MSG_RST)
        {
            /* the server must stop retransmitting its response */
            /* on any matching acknowledgement or reset message */
            coap_log_info("Received reset from address %s and port %u", server->client_addr, ntohs(server->client_sin.sin6_port));
            coap_server_trans_destroy(trans);
            coap_msg_destroy(&recv_msg);
            return 0;
        }
    }

    /* check for a valid request */
    if ((coap_msg_get_type(&recv_msg) == COAP_MSG_ACK)
     || (coap_msg_get_type(&recv_msg) == COAP_MSG_RST)
     || (coap_msg_get_code_class(&recv_msg) != COAP_MSG_REQ))
    {
        ret = coap_server_trans_reject(trans, &recv_msg);
        coap_msg_destroy(&recv_msg);
        return ret;
    }

    /* clear details of the previous request/response */
    coap_server_trans_clear_req(trans);
    coap_server_trans_clear_resp(trans);

    if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
    {
        coap_log_info("Received confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    }
    else if (coap_msg_get_type(&recv_msg) == COAP_MSG_NON)
    {
        coap_log_info("Received non-confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    }

    /* determine response type */
    resp_type = coap_server_get_resp_type(server, &recv_msg);

    /* send an acknowledgement if necessary */
    if ((coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
     && (resp_type == COAP_SERVER_SEPARATE))
    {
        ret = coap_server_trans_send_ack(trans, &recv_msg);
        if (ret < 0)
        {
            coap_msg_destroy(&recv_msg);
            return ret;
        }
    }

    /* generate response */
    coap_log_info("Responding to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
    coap_msg_create(&send_msg);
    ret = (*server->handle)(server, &recv_msg, &send_msg);
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_msg_destroy(&recv_msg);
        return ret;
    }
    if ((coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
     && (resp_type == COAP_SERVER_PIGGYBACKED))
    {
        /* copy the message ID from the request to the response */
        msg_id = coap_msg_get_msg_id(&recv_msg);
    }
    else
    {
        /* generate a new message ID */
        msg_id = coap_server_get_next_msg_id(server);
    }
    ret = coap_msg_set_msg_id(&send_msg, msg_id);
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_msg_destroy(&recv_msg);
        return ret;
    }
    /* copy the token from the request to the response */
    ret = coap_msg_set_token(&send_msg, coap_msg_get_token(&recv_msg), coap_msg_get_token_len(&recv_msg));
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_msg_destroy(&recv_msg);
        return ret;
    }
    /* set the response type */
    /* we have already verified that the received message */
    /* is either a confirmable or a non-confirmable request */
    if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
    {
        if (resp_type == COAP_SERVER_PIGGYBACKED)
            ret = coap_msg_set_type(&send_msg, COAP_MSG_ACK);
        else
            ret = coap_msg_set_type(&send_msg, COAP_MSG_CON);
    }
    else
    {
        ret = coap_msg_set_type(&send_msg, COAP_MSG_NON);
    }
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_msg_destroy(&recv_msg);
        return ret;
    }

    /* send response */
    num = coap_server_trans_send(trans, &send_msg);
    if (num < 0)
    {
        coap_msg_destroy(&send_msg);
        return num;
    }

    /* record the request in the transaction structure */
    ret = coap_server_trans_set_req(trans, &recv_msg);
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_msg_destroy(&recv_msg);
        coap_server_trans_destroy(trans);
        return ret;
    }

    /* record the response in the transaction structure */
    ret = coap_server_trans_set_resp(trans, &send_msg);
    if (ret < 0)
    {
        coap_msg_destroy(&recv_msg);
        coap_msg_destroy(&send_msg);
        coap_server_trans_destroy(trans);
        return ret;
    }

    /* start the acknowledgement timer if an acknowledgement is expected */
    if (coap_msg_get_type(&send_msg) == COAP_MSG_CON)
    {
        coap_log_info("Expecting acknowledgement from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.sin6_port));
        ret = coap_server_trans_start_ack_timer(trans);
        if (ret < 0)
        {
            coap_msg_destroy(&recv_msg);
            coap_msg_destroy(&send_msg);
            coap_server_trans_destroy(trans);
            return ret;
        }
    }

    coap_msg_destroy(&send_msg);
    coap_msg_destroy(&recv_msg);
    return 0;
}

int coap_server_run(coap_server_t *server)
{
    int ret = 0;
 
    while (1)
    {
        ret = coap_server_listen(server);
        if (ret < 0)
        {
            coap_log_error("server listen: %s", strerror(-ret));
            return ret;
        }
        ret = coap_server_exchange(server);
        if (ret < 0)
        {
            coap_log_warn("server exchange: %s", strerror(-ret));
        }
    }
    return 0;
}
