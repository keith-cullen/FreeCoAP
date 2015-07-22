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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/timerfd.h>
#include "coap_server.h"

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
    printf("Closed transaction for address %s and port %u\n", trans->client_addr, ntohs(trans->client_sin.sin_port));
    coap_msg_destroy(&trans->resp);
    coap_msg_destroy(&trans->req);
    close(trans->timer_fd);
    memset(trans, 0, sizeof(coap_server_trans_t));
}

/**
 *  @brief Compare a received message with the request part of a transaction structure
 *
 *  @param[in] trans Pointer to a trasaction structure
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Comparison value
 *  @retval 0 The message does not match the transaction
 *  @retval 1 The message matches the transaction
 */
static int coap_server_trans_match_req(coap_server_trans_t *trans, coap_server_t *server, coap_msg_t *msg)
{
    return ((trans->active)
         && (trans->client_sin_len == server->client_sin_len)
         && (memcmp(&trans->client_sin, &server->client_sin, trans->client_sin_len) == 0)
         && (trans->req.msg_id == msg->msg_id));
}

/**
 *  @brief Compare a recevied message with the response part of a transaction structure
 *
 *  @param[in] trans Pointer to a trasaction structure
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Comparison value
 *  @retval 0 The message does not match the transaction
 *  @retval 1 The message matches the transaction
 */
static int coap_server_trans_match_resp(coap_server_trans_t *trans, coap_server_t *server, coap_msg_t *msg)
{
    return ((trans->active)
         && (trans->client_sin_len == server->client_sin_len)
         && (memcmp(&trans->client_sin, &server->client_sin, trans->client_sin_len) == 0)
         && (trans->resp.msg_id == msg->msg_id));
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
    printf("Acknowledgement timeout initialised to: %lu sec, %lu nsec\n",
           trans->timeout.tv_sec, trans->timeout.tv_nsec);
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
    printf("Timeout doubled to: %lu sec, %lu nsec\n",
           trans->timeout.tv_sec, trans->timeout.tv_nsec);
}

/**
 *  @brief Start the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
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
 *  @brief Initialise and start the acknowledgement timer in a transaction structure
 *
 *  @param[out] trans Pointer to a trans structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 */
static int coap_server_trans_start_ack_timer(coap_server_trans_t *trans)
{
    trans->num_retrans = 0;
    coap_server_trans_init_ack_timeout(trans);
    return coap_server_trans_start_timer(trans);
}

/**
 *  @brief Update the acknowledgement timer in a transaction structure
 *
 *  Increase and restart the acknowledgement timer in a transaction structure
 *  and indicate if the maximum number of retransmits has been reached.
 *
 *  @param[in,out] trans Pointer to a trans structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 */
static int coap_server_trans_update_ack_timer(coap_server_trans_t *trans)
{
    int ret = 0;

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
 *  @brief Clear the timer in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 */
static void coap_server_trans_clear_timeout(coap_server_trans_t *trans)
{
    uint64_t r = 0;
    read(trans->timer_fd, &r, sizeof(r));
}

/**
 *  @brief Resend a message to the client
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] server Pointer to a server structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >= 0 Number of bytes sent
 *  @retval -errno Error code
 */
static int coap_server_trans_resend(coap_server_trans_t *trans, coap_server_t *server)
{
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;

    num = coap_msg_format(&trans->resp, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
    num = sendto(server->sd, buf, num, 0, (struct sockaddr *)&trans->client_sin, trans->client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    printf("Resent to address %s and port %u\n", trans->client_addr, ntohs(trans->client_sin.sin_port));
    return num;
}

/**
 *  @brief Initialise a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] server Pointer to a server structure
 *  @param[in] req Pointer to a request message
 *  @param[in] resp Pointer to a response message
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno On error
 */
static int coap_server_trans_create(coap_server_trans_t *trans, coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    size_t len = 0;
    int ret = 0;

    memset(trans, 0, sizeof(coap_server_trans_t));
    trans->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (trans->timer_fd == -1)
    {
        memset(trans, 0, sizeof(coap_server_trans_t));
        return -errno;
    }
    ret = coap_server_trans_start_ack_timer(trans);
    if (ret < 0)
    {
        close(trans->timer_fd);
        memset(trans, 0, sizeof(coap_server_trans_t));
        return ret;
    }
    memcpy(&trans->client_sin, &server->client_sin, server->client_sin_len);
    trans->client_sin_len = server->client_sin_len;
    len = sizeof(trans->client_addr);
    strncpy(trans->client_addr, server->client_addr, len);
    trans->client_addr[len - 1] = '\0';
    trans->req = *req;
    trans->resp = *resp;
    trans->active = 1;
    printf("Recorded transaction for address %s and port %u\n", trans->client_addr, ntohs(trans->client_sin.sin_port));
    return 0;
}

/****************************************************************************************************
 *                                           coap_server                                            *
 ****************************************************************************************************/

int coap_server_create(coap_server_t *server, const char *host, unsigned port, int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *))
{
    struct sockaddr_in server_sin = {0};
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
    server->sd = socket(PF_INET, SOCK_DGRAM, 0);  /* PF_INET not AF_INET */
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
    server_sin.sin_family = AF_INET;
    server_sin.sin_port = htons(port);
    ret = inet_pton(AF_INET, host, &server_sin.sin_addr.s_addr);
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
    p = inet_ntop(AF_INET, &server_sin.sin_addr.s_addr, server_addr, sizeof(server_addr));
    if (p == NULL)
    {
        coap_server_destroy(server);
        return -errno;
    }
    printf("Listening on address %s and port %d\n", server_addr, ntohs(server_sin.sin_port));
    return 0;
}

void coap_server_destroy(coap_server_t *server)
{
    close(server->sd);
    memset(server, 0, sizeof(coap_server_t));
}

static void coap_server_clear_client(coap_server_t *server)
{
    memset(&server->client_sin, 0, sizeof(server->client_sin));
    server->client_sin_len = 0;
    memset(server->client_addr, 0, sizeof(server->client_addr));
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
 *  @brief Search for an empty transaction structure in the server structure
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
        if (trans->active == 0)
        {
            return trans;
        }
    }
    return NULL;
}

/**
 *  @brief Search a server structure for a transaction structue
 *         with a request part that matches a received message
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No matching transaction structure found
 */
static coap_server_trans_t *coap_server_find_trans_req(coap_server_t *server, coap_msg_t *msg)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
    {
        trans = &server->trans[i];
        if (coap_server_trans_match_req(trans, server, msg))
        {
            return trans;
        }
    }
    return NULL;
}

/**
 *  @brief Search a server structure for a transaction structue
 *         with a response part that matches a received message
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No matching transaction structure found
 */
static coap_server_trans_t *coap_server_find_trans_resp(coap_server_t *server, coap_msg_t *msg)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
    {
        trans = &server->trans[i];
        if (coap_server_trans_match_resp(trans, server, msg))
        {
            return trans;
        }
    }
    return NULL;
}

/**
 *  @brief Send a message to the client
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >= 0 Number of bytes sent
 *  @retval -errno Error code
 */
static int coap_server_send(coap_server_t *server, coap_msg_t *msg)
{
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;

    num = coap_msg_format(msg, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
    num = sendto(server->sd, buf, num, 0, (struct sockaddr *)&server->client_sin, server->client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    printf("Sent to address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
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
 *  @param[in] server Pointer to a server structure
 *  @param[in] buf Buffer containing the message
 *  @param[in] len length of the buffer
 */
static void coap_server_handle_format_error(coap_server_t *server, char *buf, unsigned len)
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
        coap_server_send(server, &msg);
        coap_msg_destroy(&msg);
    }
}

/**
 *  @brief Receive a message from the client
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes received or error code
 *  @retval >= 0 Number of bytes received
 *  @retval -errno Error code
 */
static ssize_t coap_server_recv(coap_server_t *server, coap_msg_t *msg)
{
    const char *p = NULL;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    server->client_sin_len = sizeof(struct sockaddr_in);
    num = recvfrom(server->sd, buf, sizeof(buf), 0, (struct sockaddr *)&server->client_sin, &server->client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    ret = coap_msg_parse(msg, buf, num);
    if (ret == -EBADMSG)
    {
        coap_server_handle_format_error(server, buf, num);
    }
    if (ret < 0)
    {
        return ret;
    }
    p = inet_ntop(AF_INET, &server->client_sin.sin_addr.s_addr, server->client_addr, sizeof(server->client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Received from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
    return num;
}

/**
 *  @brief Reject a received confirmable message
 *
 *  Send a reset message to the client.
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 */
static int coap_server_reject_con(coap_server_t *server, coap_msg_t *msg)
{
    coap_msg_t rej = {0};
    int num = 0;
    int ret = 0;

    printf("Rejecting confirmable request from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
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
    num = coap_server_send(server, &rej);
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
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Error code
 *  @retval 0 Success
 */
static int coap_server_reject_non(coap_server_t *server, coap_msg_t *msg)
{
    printf("Rejecting non-confirmable message from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
    return 0;
}

/**
 *  @brief Reject a received message
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 */
static int coap_server_reject(coap_server_t *server, coap_msg_t *msg)
{
    if (coap_msg_get_type(msg) == COAP_MSG_CON)
    {
        return coap_server_reject_con(server, msg);
    }
    return coap_server_reject_non(server, msg);
}

/**
 *  @brief Send an acknowledgement message to the client
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 */
static int coap_server_send_ack(coap_server_t *server, coap_msg_t *msg)
{
    coap_msg_t ack = {0};
    int num = 0;
    int ret = 0;

    printf("Acknowledging confirmable message from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
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
    num = coap_server_send(server, &ack);
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
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 */
static int coap_server_handle_ack_timeout(coap_server_t *server, coap_server_trans_t *trans)
{
    int num = 0;
    int ret = 0;

    coap_server_trans_clear_timeout(trans);
    printf("Transaction expired for address %s and port %u\n", trans->client_addr, ntohs(trans->client_sin.sin_port));
    ret = coap_server_trans_update_ack_timer(trans);
    if (ret == 0)
    {
        printf("Retransmitting to address %s and port %u\n", trans->client_addr, ntohs(trans->client_sin.sin_port));
        num = coap_server_trans_resend(trans, server);
        if (num < 0)
        {
            return num;
        }
    }
    else if (ret == -ETIMEDOUT)
    {
        printf("Stopped retransmitting to address %s and port %u\n", trans->client_addr, ntohs(trans->client_sin.sin_port));
        coap_server_trans_destroy(trans);
    }
    return 0;
}

/**
 *  @brief Wait for a message to arrive or an acknowledgement
 *         timer in any of the active transactions to expire
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
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
                ret = coap_server_handle_ack_timeout(server, trans);
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
 *  @returns Error code
 *  @retval 0 Success
 *  @retval -errno Error code
 **/
static int coap_server_exchange(coap_server_t *server)
{
    coap_server_trans_t *trans = NULL;
    coap_msg_t recv_msg = {0};
    coap_msg_t send_msg = {0};
    unsigned msg_id = 0;
    int resp_type = 0;
    int num = 0;
    int ret = 0;

    /* clear details of the previous client */
    coap_server_clear_client(server);

    /* receive message */
    coap_msg_create(&recv_msg);
    num = coap_server_recv(server, &recv_msg);
    if (num < 0)
    {
        coap_msg_destroy(&recv_msg);
        return num;
    }

    /* check for duplicate requests */
    trans = coap_server_find_trans_req(server, &recv_msg);
    if (trans != NULL)
    {
        if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
        {
            /* message deduplication */
            /* acknowledge the (confirmable) request again */
            /* do not send the response again */
            printf("Received duplicate confirmable request from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
            ret = coap_server_send_ack(server, &recv_msg);
            coap_msg_destroy(&recv_msg);
            return ret;
        }
        else if (coap_msg_get_type(&recv_msg) == COAP_MSG_NON)
        {
            /* message deduplication */
            /* do not acknowledge the (non-confirmable) request again */
            /* do not send the response again */
            printf("Received duplicate non-confirmable request from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
            coap_msg_destroy(&recv_msg);
            return 0;
        }
    }

    /* check for an ack for a previous response */
    trans = coap_server_find_trans_resp(server, &recv_msg);
    if (trans != NULL)
    {
        if (coap_msg_get_type(&recv_msg) == COAP_MSG_ACK)
        {
            /* the server must stop num_retransting its response */
            /* on any matching acknowledgement or reset message */
            printf("Received acknowledgement from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
            coap_server_trans_destroy(trans);
            coap_msg_destroy(&recv_msg);
            return 0;
        }
        else if (coap_msg_get_type(&recv_msg) == COAP_MSG_RST)
        {
            /* the server must stop num_retransting its response */
            /* on any matching acknowledgement or reset message */
            printf("Received reset from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
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
        ret = coap_server_reject(server, &recv_msg);
        coap_msg_destroy(&recv_msg);
        return ret;
    }

    if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
    {
        printf("Received confirmable request from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
    }
    else if (coap_msg_get_type(&recv_msg) == COAP_MSG_NON)
    {
        printf("Received non-confirmable request from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
    }

    resp_type = coap_server_get_resp_type(server, &recv_msg);

    /* send an acknowledgement if necessary */
    if ((coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
     && (resp_type == COAP_SERVER_SEPARATE))
    {
        ret = coap_server_send_ack(server, &recv_msg);
        if (ret < 0)
        {
            coap_msg_destroy(&recv_msg);
            return ret;
        }
    }

    /* generate response */
    printf("Responding to address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
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
    num = coap_server_send(server, &send_msg);
    if (num < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_msg_destroy(&recv_msg);
        return num;
    }

    /* record the transaction if an acknowledgement is expected */
    if (coap_msg_get_type(&send_msg) == COAP_MSG_CON)
    {
        trans = coap_server_find_empty_trans(server);
        if (trans == NULL)
        {
            coap_msg_destroy(&send_msg);
            coap_msg_destroy(&recv_msg);
            return -EBUSY;
        }
        printf("Expecting acknowledgement from address %s and port %u\n", server->client_addr, ntohs(server->client_sin.sin_port));
        ret = coap_server_trans_create(trans, server, &recv_msg, &send_msg);  /* performs shallow copy of send_msg and recv_msg */
        if (ret < 0)
        {
            coap_msg_destroy(&send_msg);
            coap_msg_destroy(&recv_msg);
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
            fprintf(stderr, "Error: Server listen exit %d\n", ret);
            return ret;
        }
        ret = coap_server_exchange(server);
        if (ret < 0)
        {
            fprintf(stderr, "Error: Server exchange exit %d\n", ret);
        }
    }
    return 0;
}
