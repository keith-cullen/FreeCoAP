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

#define COAP_SERVER_ADDR_BUF_LEN     128
#define COAP_SERVER_ACK_TIMEOUT_SEC  2
#define COAP_SERVER_MAX_RETRANSMIT   4

static int rand_init = 0;

/****************************************************************************************************
 *                                        coap_server_trans                                         *
 ****************************************************************************************************/

static void coap_server_trans_destroy(coap_server_trans_t *trans)
{
    coap_msg_destroy(&trans->resp);
    close(trans->timer_fd);
    memset(trans, 0, sizeof(coap_server_trans_t));
}

static int coap_server_trans_match(coap_server_trans_t *trans, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    return ((trans->active)
         && (trans->client_sin_len == client_sin_len)
         && (memcmp(&trans->client_sin, client_sin, trans->client_sin_len) == 0)
         && (trans->resp.msg_id == msg->msg_id));
}

/*  initialise timeout to a random duration between:
 *  ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
 *  where:
 *  ACK_TIMEOUT = 2
 *  ACK_RANDOM_FACTOR = 1.5
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

static void coap_server_trans_double_timeout(coap_server_trans_t *trans)
{
    unsigned msec = 2 * ((trans->timeout.tv_sec * 1000)
                      + (trans->timeout.tv_nsec / 1000000));
    trans->timeout.tv_sec = msec / 1000;
    trans->timeout.tv_nsec = (msec % 1000) * 1000000;
    printf("Timeout doubled to: %lu sec, %lu nsec\n",
           trans->timeout.tv_sec, trans->timeout.tv_nsec);
}

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

static int coap_server_trans_start_ack_timer(coap_server_trans_t *trans)
{
    trans->retransmit = 0;
    coap_server_trans_init_ack_timeout(trans);
    return coap_server_trans_start_timer(trans);
}

static int coap_server_trans_update_ack_timer(coap_server_trans_t *trans)
{
    int ret = 0;

    if (trans->retransmit >= COAP_SERVER_MAX_RETRANSMIT)
    {
        return -ETIMEDOUT;
    }
    coap_server_trans_double_timeout(trans);
    ret = coap_server_trans_start_timer(trans);
    if (ret < 0)
    {
        return ret;
    }
    trans->retransmit++;
    return 0;
}

static void coap_server_trans_clear_timeout(coap_server_trans_t *trans)
{
    uint64_t r = 0;
    read(trans->timer_fd, &r, sizeof(r));
}

static int coap_server_trans_create(coap_server_trans_t *trans, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
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
    memcpy(&trans->client_sin, client_sin, client_sin_len);
    trans->client_sin_len = client_sin_len;
    trans->resp = *msg;
    trans->active = 1;
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
    p = inet_ntop(AF_INET, &server_sin.sin_addr.s_addr, server_addr, sizeof(server_addr));
    if (p == NULL)
    {
        coap_server_destroy(server);
        return -errno;
    }
    coap_msg_gen_rand_str((char *)msg_id, sizeof(msg_id));
    server->msg_id = (((unsigned)msg_id[1]) << 8) | (unsigned)msg_id[0];
    server->handle = handle;
    printf("Listening on address %s and port %d\n", server_addr, ntohs(server_sin.sin_port));
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

static coap_server_trans_t *coap_server_find_trans(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_MAX_TRANS; i++)
    {
        trans = &server->trans[i];
        if (coap_server_trans_match(trans, client_sin, client_sin_len, msg))
        {
            return trans;
        }
    }
    return NULL;
}

/*  returns: {<0, on error
 *           {>0, num bytes sent, on success
 */
static int coap_server_send(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    const char *p = NULL;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;

    num = coap_msg_format(msg, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
    num = sendto(server->sd, buf, num, 0, (struct sockaddr *)client_sin, client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    p = inet_ntop(AF_INET, &client_sin->sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Sent to address %s and port %u\n", client_addr, ntohs(client_sin->sin_port));
    return num;
}

/*  special handling for the case where a received
 *  message could not be parsed due to a format error
 */
static void coap_server_handle_format_error(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, char *buf, unsigned len)
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
        ret = coap_msg_set_hdr(&msg, COAP_MSG_RST, 0, 0, 0, msg_id);
        if (ret == 0)
        {
            coap_server_send(server, client_sin, client_sin_len, &msg);
        }
        coap_msg_destroy(&msg);
    }
}

/*  returns: {<0, on error
 *           {>0, num bytes received, on success
 */
static ssize_t coap_server_recv(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t *client_sin_len, coap_msg_t *msg)
{
    const char *p = NULL;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    *client_sin_len = sizeof(struct sockaddr_in);
    num = recvfrom(server->sd, buf, sizeof(buf), 0, (struct sockaddr *)client_sin, client_sin_len);
    if (num == -1)
    {
        return -errno;
    }
    ret = coap_msg_parse(msg, buf, num);
    if (ret == -EBADMSG)
    {
        coap_server_handle_format_error(server, client_sin, *client_sin_len, buf, num);
    }
    if (ret < 0)
    {
        return ret;
    }
    p = inet_ntop(AF_INET, &client_sin->sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Received from address %s and port %u\n", client_addr, ntohs(client_sin->sin_port));
    return num;
}

static int coap_server_reject_con(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    const char *p = NULL;
    coap_msg_t rej = {0};
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    p = inet_ntop(AF_INET, &client_sin->sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Rejecting confirmable message from address %s and port %u\n", client_addr, ntohs(client_sin->sin_port));
    coap_msg_create(&rej);
    ret = coap_msg_set_hdr(&rej, COAP_MSG_RST, 0, 0, 0, coap_msg_get_msg_id(msg));
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    num = coap_server_send(server, client_sin, client_sin_len, &rej);
    coap_msg_destroy(&rej);
    if (num < 0)
    {
        return num;
    }
    return 0;
}

static int coap_server_reject_non(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    const char *p = NULL;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};

    p = inet_ntop(AF_INET, &client_sin->sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Rejecting non-confirmable message from address %s and port %u\n", client_addr, ntohs(client_sin->sin_port));
    return 0;
}

static int coap_server_reject(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    if (coap_msg_get_type(msg) == COAP_MSG_CON)
    {
        return coap_server_reject_con(server, client_sin, client_sin_len, msg);
    }
    return coap_server_reject_non(server, client_sin, client_sin_len, msg);
}

static int coap_server_send_ack(coap_server_t *server, struct sockaddr_in *client_sin, socklen_t client_sin_len, coap_msg_t *msg)
{
    const char *p = NULL;
    coap_msg_t ack = {0};
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    p = inet_ntop(AF_INET, &client_sin->sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Acknowledging confirmable message from address %s and port %u\n", client_addr, ntohs(client_sin->sin_port));
    coap_msg_create(&ack);
    ret = coap_msg_set_hdr(&ack, COAP_MSG_ACK, 0, 0, 0, msg->msg_id);
    if (ret < 0)
    {
        coap_msg_destroy(&ack);
        return ret;
    }
    num = coap_server_send(server, client_sin, client_sin_len, &ack);
    coap_msg_destroy(&ack);
    if (num < 0)
    {
        return num;
    }
    return 0;
}

static int coap_server_handle_ack_timeout(coap_server_t *server, coap_server_trans_t *trans)
{
    const char *p = NULL;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    coap_server_trans_clear_timeout(trans);
    p = inet_ntop(AF_INET, &trans->client_sin.sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        return -errno;
    }
    printf("Transaction expired for address %s and port %u\n", client_addr, ntohs(trans->client_sin.sin_port));
    ret = coap_server_trans_update_ack_timer(trans);
    if (ret == 0)
    {
        printf("Retransmitting to address %s and port %u\n", client_addr, ntohs(trans->client_sin.sin_port));
        num = coap_server_send(server, &trans->client_sin, trans->client_sin_len, &trans->resp);
        if (num < 0)
        {
            return num;
        }
    }
    else if (ret == -ETIMEDOUT)
    {
        printf("Stopped retransmitting to address %s and port %u\n", client_addr, ntohs(trans->client_sin.sin_port));
        coap_server_trans_destroy(trans);
    }
    return 0;
}

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

static int coap_server_exchange(coap_server_t *server)
{
    coap_server_trans_t *trans = NULL;
    struct sockaddr_in client_sin = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    const char *p = NULL;
    socklen_t client_sin_len = 0;
    char client_addr[COAP_SERVER_ADDR_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    /* receive message */
    coap_msg_create(&req);
    num = coap_server_recv(server, &client_sin, &client_sin_len, &req);
    if (num < 0)
    {
        coap_msg_destroy(&req);
        return num;
    }
    p = inet_ntop(AF_INET, &client_sin.sin_addr.s_addr, client_addr, sizeof(client_addr));
    if (p == NULL)
    {
        coap_msg_destroy(&req);
        return -errno;
    }

    /* check for previous exchange */
    trans = coap_server_find_trans(server, &client_sin, client_sin_len, &req);
    if (trans != NULL)
    {
        if (coap_msg_get_type(&req) == COAP_MSG_CON)
        {
            printf("Received duplicate confirmable message from address %s and port %u\n", client_addr, ntohs(client_sin.sin_port));
            /* message deduplication */
            /* acknowledge the (confirmable) request again */
            /* do not send the response again */
            ret = coap_server_send_ack(server, &client_sin, client_sin_len, &req);
            coap_msg_destroy(&req);
            return ret;
        }
        else if (coap_msg_get_type(&req) == COAP_MSG_NON)
        {
            printf("Received duplicate non-confirmable message from address %s and port %u\n", client_addr, ntohs(client_sin.sin_port));
            /* message deduplication */
            /* do not acknowledge the (non-confirmable) request again */
            /* do not send the response again */
            coap_msg_destroy(&req);
            return 0;
        }
        else if (coap_msg_get_type(&req) == COAP_MSG_ACK)
        {
            printf("Received acknowledgement from address %s and port %u\n", client_addr, ntohs(client_sin.sin_port));
            /* the server must stop retransmitting its response */
            /* on any matching acknowledgement or reset message */
            coap_server_trans_destroy(trans);
            coap_msg_destroy(&req);
            return 0;
        }
        else if (coap_msg_get_type(&req) == COAP_MSG_RST)
        {
            printf("Received reset from address %s and port %u\n", client_addr, ntohs(client_sin.sin_port));
            /* the server must stop retransmitting its response */
            /* on any matching acknowledgement or reset message */
            coap_server_trans_destroy(trans);
            coap_msg_destroy(&req);
            return 0;
        }
    }

    /* check for valid request */
    if ((coap_msg_get_type(&req) == COAP_MSG_ACK)
     || (coap_msg_get_type(&req) == COAP_MSG_RST)
     || (coap_msg_get_code_class(&req) != COAP_MSG_REQ))
    {
        ret = coap_server_reject(server, &client_sin, client_sin_len, &req);
        coap_msg_destroy(&req);
        return ret;
    }

    /* send acknowledgement if necessary */
    if (coap_msg_get_type(&req) == COAP_MSG_CON)
    {
        ret = coap_server_send_ack(server, &client_sin, client_sin_len, &req);
        if (ret < 0)
        {
            coap_msg_destroy(&req);
            return ret;
        }
    }

    /* generate response */
    printf("Responding to address %s and port %u\n", client_addr, ntohs(client_sin.sin_port));
    coap_msg_create(&resp);
    ret = (*server->handle)(server, &req, &resp);
    coap_msg_destroy(&req);
    if (ret < 0)
    {
        coap_msg_destroy(&resp);
        return ret;
    }

    /* send response */
    num = coap_server_send(server, &client_sin, client_sin_len, &resp);
    if (num < 0)
    {
        coap_msg_destroy(&resp);
        return num;
    }

    /* record the transaction if an acknowledgement is expected */
    if (coap_msg_get_type(&resp) == COAP_MSG_CON)
    {
        trans = coap_server_find_empty_trans(server);
        if (trans == NULL)
        {
            coap_msg_destroy(&resp);
            return -EBUSY;
        }
        printf("Expecting acknowledgement from address %s and port %u\n", client_addr, ntohs(client_sin.sin_port));
        ret = coap_server_trans_create(trans, &client_sin, client_sin_len, &resp);  /* performs shallow copy of resp */
        if (ret < 0)
        {
            coap_msg_destroy(&resp);
            return ret;
        }
    }
    else
    {
        coap_msg_destroy(&resp);
    }
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
