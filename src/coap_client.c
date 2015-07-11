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
#include "coap_client.h"

#define COAP_CLIENT_ACK_TIMEOUT_SEC   2
#define COAP_CLIENT_MAX_RETRANSMIT    4
#define COAP_CLIENT_RESP_TIMEOUT_SEC  30

static int rand_init = 0;

int coap_client_create(coap_client_t *client, const char *host, unsigned port)
{
    const char *p = NULL;
    int flags = 0;
    int ret = 0;

    if ((client == NULL) || (host == NULL))
    {
        return -EINVAL;
    }
    memset(client, 0, sizeof(coap_client_t));
    client->sd = socket(PF_INET, SOCK_DGRAM, 0);  /* PF_INET not AF_INET */
    if (client->sd == -1)
    {
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
    flags = fcntl(client->sd, F_GETFL, 0);
    if (flags == -1)
    {
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
    ret = fcntl(client->sd, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1)
    {
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
    client->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (client->timer_fd == -1)
    {
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
    client->server_sin.sin_family = AF_INET;
    client->server_sin.sin_port = htons(port);
    ret = inet_pton(AF_INET, host, &client->server_sin.sin_addr.s_addr);
    if (ret == 0)
    {
        coap_client_destroy(client);
        return -EINVAL;
    }
    else if (ret == -1)
    {
        coap_client_destroy(client);
        return -errno;
    }
    client->server_sin_len = sizeof(client->server_sin);
    ret = connect(client->sd, (struct sockaddr *)&client->server_sin, client->server_sin_len);
    if (ret == -1)
    {
        coap_client_destroy(client);
        return -errno;
    }
    p = inet_ntop(AF_INET, &client->server_sin.sin_addr.s_addr, client->server_addr, sizeof(client->server_addr));
    if (p == NULL)
    {
        coap_client_destroy(client);
        return -errno;
    }
    printf("Connected to address %s and port %d\n", client->server_addr, ntohs(client->server_sin.sin_port));
    return 0;
}

void coap_client_destroy(coap_client_t *client)
{
    close(client->timer_fd);
    close(client->sd);
    memset(client, 0, sizeof(coap_client_t));
}

/*  initialise timeout to a random duration between:
 *  ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
 *  where:
 *  ACK_TIMEOUT = 2
 *  ACK_RANDOM_FACTOR = 1.5
 */
static void coap_client_init_ack_timeout(coap_client_t *client)
{
    if (!rand_init)
    {
        srand(time(NULL));
        rand_init = 1;
    }
    client->timeout.tv_sec = COAP_CLIENT_ACK_TIMEOUT_SEC;
    client->timeout.tv_nsec = (rand() % 1000) * 1000000;
    printf("Acknowledgement timeout initialised to: %lu sec, %lu nsec\n",
           client->timeout.tv_sec, client->timeout.tv_nsec);
}

static void coap_client_init_resp_timeout(coap_client_t *client)
{
    client->timeout.tv_sec = COAP_CLIENT_RESP_TIMEOUT_SEC;
    client->timeout.tv_nsec = 0;
    printf("Response timeout initialised to: %lu sec, %lu nsec\n",
           client->timeout.tv_sec, client->timeout.tv_nsec);
}

static void coap_client_double_timeout(coap_client_t *client)
{
    unsigned msec = 2 * ((client->timeout.tv_sec * 1000)
                      + (client->timeout.tv_nsec / 1000000));
    client->timeout.tv_sec = msec / 1000;
    client->timeout.tv_nsec = (msec % 1000) * 1000000;
    printf("Timeout doubled to: %lu sec, %lu nsec\n",
           client->timeout.tv_sec, client->timeout.tv_nsec);
}

static int coap_client_start_timer(coap_client_t *client)
{
    struct itimerspec its = {{0}};
    int ret = 0;

    its.it_value = client->timeout;
    ret = timerfd_settime(client->timer_fd, 0, &its, NULL);
    if (ret == -1)
    {
        return -errno;
    }
    return 0;
}

static int coap_client_start_ack_timer(coap_client_t *client)
{
    client->num_retrans = 0;
    coap_client_init_ack_timeout(client);
    return coap_client_start_timer(client);
}

static int coap_client_update_ack_timer(coap_client_t *client)
{
    int ret = 0;

    if (client->num_retrans >= COAP_CLIENT_MAX_RETRANSMIT)
    {
        return -ETIMEDOUT;
    }
    coap_client_double_timeout(client);
    ret = coap_client_start_timer(client);
    if (ret < 0)
    {
        return ret;
    }
    client->num_retrans++;
    return 0;
}

static int coap_client_start_resp_timer(coap_client_t *client)
{
    coap_client_init_resp_timeout(client);
    return coap_client_start_timer(client);
}

static void coap_client_clear_timeout(coap_client_t *client)
{
    uint64_t r = 0;
    read(client->timer_fd, &r, sizeof(r));
}

/*  returns: {<0, on error
 *           {>0, num bytes sent, on success
 */
static int coap_client_send(coap_client_t *client, coap_msg_t *msg)
{
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;

    num = coap_msg_format(msg, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
    num = send(client->sd, buf, num, 0);
    if (num == -1)
    {
        return -errno;
    }
    printf("Sent to address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    return num;
}

/*  special handling for the case where a received
 *  message could not be parsed due to a format error
 */
static void coap_client_handle_format_error(coap_client_t *client, char *buf, unsigned len)
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
            coap_client_send(client, &msg);
        }
        coap_msg_destroy(&msg);
    }
}

/*  returns: {<0, on error
 *           {>0, num bytes received, on success
 */
static int coap_client_recv(coap_client_t *client, coap_msg_t *msg)
{
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int num = 0;
    int ret = 0;

    num = recv(client->sd, buf, sizeof(buf), 0);
    if (num == -1)
    {
        return -errno;
    }
    ret = coap_msg_parse(msg, buf, num);
    if (ret == -EBADMSG)
    {
        coap_client_handle_format_error(client, buf, num);
    }
    if (ret < 0)
    {
        return ret;
    }
    printf("Received from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    return num;
}

static int coap_client_reject_con(coap_client_t *client, coap_msg_t *msg)
{
    coap_msg_t rej = {0};
    int num = 0;
    int ret = 0;

    printf("Rejecting confirmable message from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    coap_msg_create(&rej);
    ret = coap_msg_set_hdr(&rej, COAP_MSG_RST, 0, 0, 0, coap_msg_get_msg_id(msg));
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    num = coap_client_send(client, &rej);
    coap_msg_destroy(&rej);
    if (num < 0)
    {
        return num;
    }
    return 0;
}

static int coap_client_reject_non(coap_client_t *client, coap_msg_t *msg)
{
    printf("Rejecting non-confirmable message from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    return 0;
}

static int coap_client_reject(coap_client_t *client, coap_msg_t *msg)
{
    if (coap_msg_get_type(msg) == COAP_MSG_CON)
    {
        return coap_client_reject_con(client, msg);
    }
    return coap_client_reject_non(client, msg);
}

static int coap_client_send_ack(coap_client_t *client, coap_msg_t *msg)
{
    coap_msg_t ack = {0};
    int num = 0;
    int ret = 0;

    printf("Acknowledging confirmable message from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    coap_msg_create(&ack);
    ret = coap_msg_set_hdr(&ack, COAP_MSG_ACK, 0, 0, 0, coap_msg_get_msg_id(msg));
    if (ret < 0)
    {
        coap_msg_destroy(&ack);
        return ret;
    }
    num = coap_client_send(client, &ack);
    coap_msg_destroy(&ack);
    if (num < 0)
    {
        return num;
    }
    return 0;
}

static int coap_client_handle_ack_timeout(coap_client_t *client, coap_msg_t *msg)
{
    int num = 0;
    int ret = 0;

    printf("Transaction expired for address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    ret = coap_client_update_ack_timer(client);
    if (ret == 0)
    {
        printf("Retransmitting to address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
        num = coap_client_send(client, msg);
        if (num < 0)
        {
            return num;
        }
    }
    else if (ret == -ETIMEDOUT)
    {
        printf("Stopped num_retransting to address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    }
    return ret;
}

static int coap_client_listen_ack(coap_client_t *client, coap_msg_t *msg)
{
    fd_set read_fds = {{0}};
    int max_fd = 0;
    int ret = 0;

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(client->sd, &read_fds);
        FD_SET(client->timer_fd, &read_fds);
        max_fd = client->sd;
        if (client->timer_fd > max_fd)
        {
            max_fd = client->timer_fd;
        }
        ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ret == -1)
        {
            return -errno;
        }
        if (FD_ISSET(client->sd, &read_fds))
        {
            break;
        }
        if (FD_ISSET(client->timer_fd, &read_fds))
        {
            coap_client_clear_timeout(client);
            ret = coap_client_handle_ack_timeout(client, msg);
            if (ret < 0)
            {
                return ret;
            }
        }
    }
    return 0;
}

static int coap_client_listen_resp(coap_client_t *client)
{
    fd_set read_fds = {{0}};
    int max_fd = 0;
    int ret = 0;

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(client->sd, &read_fds);
        FD_SET(client->timer_fd, &read_fds);
        max_fd = client->sd;
        if (client->timer_fd > max_fd)
        {
            max_fd = client->timer_fd;
        }
        ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ret == -1)
        {
            return -errno;
        }
        if (FD_ISSET(client->sd, &read_fds))
        {
            break;
        }
        if (FD_ISSET(client->timer_fd, &read_fds))
        {
            coap_client_clear_timeout(client);
            return -ETIMEDOUT;
        }
    }
    return 0;
}

static int coap_client_match_token(coap_msg_t *req, coap_msg_t *resp)
{
    return ((coap_msg_get_token_len(resp) == coap_msg_get_token_len(req))
         && (memcmp(coap_msg_get_token(resp), coap_msg_get_token(req), coap_msg_get_token_len(req)) == 0));
}

int coap_client_exchange(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    int num = 0;
    int ret = 0;

    num = coap_client_send(client, req);
    if (num < 0)
    {
        return num;
    }
    if (coap_msg_get_type(req) == COAP_MSG_CON)
    {
        /*  wait for piggy-backed response in ack message
         *  or ack message and separate response message
         */
        printf("Expecting acknowledgement from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
        coap_client_start_ack_timer(client);
        while (1)
        {
            ret = coap_client_listen_ack(client, req);
            if (ret < 0)
            {
                return ret;
            }
            num = coap_client_recv(client, resp);
            if (num == -EBADMSG)
            {
                coap_msg_reset(resp);
                continue;
            }
            else if (num < 0)
            {
                return num;
            }
            if (coap_msg_get_msg_id(resp) == coap_msg_get_msg_id(req))
            {
                if (coap_msg_get_type(resp) == COAP_MSG_RST)
                {
                    printf("Received reset from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
                    return -ECONNRESET;
                }
                else if (coap_msg_get_type(resp) == COAP_MSG_ACK)
                {
                    if (coap_msg_is_empty(resp))
                    {
                        printf("Received acknowledgement from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
                        /* received ack message, wait for separate response message */
                        break;
                    }
                    else if (coap_client_match_token(req, resp))
                    {
                        printf("Received acknowledgement and response from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
                        /* received response piggy-backed in ack message */
                        return 0;
                    }
                }
            }
            ret = coap_client_reject(client, resp);
            if (ret < 0 )
            {
                return ret;
            }
            coap_msg_reset(resp);
        }
    }
    /* wait for separate response message */
    printf("Expecting response from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
    coap_client_start_resp_timer(client);
    while (1)
    {
        ret = coap_client_listen_resp(client);
        if (ret < 0)
        {
            return ret;
        }
        num = coap_client_recv(client, resp);
        if (num == -EBADMSG)
        {
            coap_msg_reset(resp);
            continue;
        }
        else if (num < 0)
        {
            return num;
        }
        if ((coap_msg_get_msg_id(resp) == coap_msg_get_msg_id(req))
         && (coap_msg_get_type(resp) == COAP_MSG_ACK))
        {
            printf("Received duplicate acknowledgement from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
            /* message deduplication */
            /* ignore a duplicate ACK */
            /* continue waiting for the repsonse */
            coap_msg_reset(resp);
            continue;
        }
        if (coap_client_match_token(req, resp))
        {
            printf("Received response from address %s and port %u\n", client->server_addr, ntohs(client->server_sin.sin_port));
            if (coap_msg_get_type(resp) == COAP_MSG_CON)
            {
                return coap_client_send_ack(client, resp);
            }
            else if (coap_msg_get_type(resp) == COAP_MSG_NON)
            {
                return 0;
            }
        }
        ret = coap_client_reject(client, resp);
        if (ret < 0 )
        {
            return ret;
        }
        coap_msg_reset(resp);
    }
    return 0;
}
