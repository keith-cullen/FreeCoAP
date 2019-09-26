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
 *  @file connection.c
 *
 *  @brief Source file for the FreeCoAP HTTP/CoAP proxy connection module
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include "connection.h"
#include "http_msg.h"
#include "uri.h"
#include "cross.h"
#include "thread.h"
#include "lock.h"
#include "coap_log.h"

#define CONNECTION_DATA_BUF_SIZE       4096
#define CONNECTION_DATA_BUF_MAX_SIZE   (8 * CONNECTION_DATA_BUF_SIZE)
#define CONNECTION_DATA_BUF_MIN_SPACE  128
#define CONNECTION_INT_BUF_LEN         16
#define CONNECTION_BODY_LEN            8192
#define CONNECTION_COAP_BLOCK1_SIZE    32
#define CONNECTION_COAP_BLOCK2_SIZE    32

typedef enum
{
    CON_RET_TIMEDOUT = 1,
    CON_RET_CLOSED = 2,
}
con_ret_t;

#ifdef CONNECTION_STATS

#define STATS_BUF_LEN  256

typedef struct
{
    unsigned ok_con;
    unsigned fail_con;
    unsigned ok_trans;
    unsigned fail_trans;
    lock_t lock;
}
connection_stats_t;

connection_stats_t stats = {0};

#define stats_lock()        {lock_get(&stats.lock);}
#define stats_unlock()      {lock_put(&stats.lock);}
#define stats_ok_con()      {stats_lock(); stats.ok_con++;      stats_unlock();}
#define stats_fail_con()    {stats_lock(); stats.fail_con++;    stats_unlock();}
#define stats_ok_trans()    {stats_lock(); stats.ok_trans++;    stats_unlock();}
#define stats_fail_trans()  {stats_lock(); stats.fail_trans++;  stats_unlock();}

static int stats_init(void)
{
    memset(&stats, 0, sizeof(connection_stats_t));
    return lock_create(&stats.lock);
}

static void stats_log(void)
{
    stats_lock();

    coap_log_info("OK connections:      %u", stats.ok_con);
    coap_log_info("Failed connections:  %u", stats.fail_con);
    coap_log_info("OK transactions:     %u", stats.ok_trans);
    coap_log_info("Failed transactions: %u", stats.fail_trans);
    fflush(stdout);

    stats_unlock();
}

#else  /* !CONNECTION_STATS */

#define stats_ok_con()
#define stats_fail_con()
#define stats_ok_trans()
#define stats_fail_trans()
#define stats_log()

static int stats_init(void)
{
    return 0;
}

#endif  /* CONNECTION_STATS */

int connection_init(void)
{
    return stats_init();
}

/*  return: { 0, success
 *          {<0, error
 */
static int connection_coap_client_create(connection_t *con, uri_t *uri)
{
    int ret = 0;

    coap_log_info("[%u] <%u> %s Connecting to CoAP server host %s and port %s",
                  con->listener_index, con->con_index, con->addr,
                  uri_get_host(uri), uri_get_port(uri));

    ret = coap_client_create(&con->coap_client,
                            uri_get_host(uri),
                            uri_get_port(uri),
                            param_get_coap_client_key_file_name(con->param),
                            param_get_coap_client_cert_file_name(con->param),
                            param_get_coap_client_trust_file_name(con->param),
                            NULL,
                            NULL);
    if (ret < 0)
    {
        coap_log_error("[%u] <%u> %s Failed to connect to CoAP server host %s and port %s: %s",
                       con->listener_index, con->con_index, con->addr,
                       uri_get_host(uri), uri_get_port(uri),
                       strerror(-ret));
        return ret;
    }
    con->coap_client_host = strdup(uri->host);
    if (con->coap_client_host == NULL)
    {
        coap_client_destroy(&con->coap_client);
        coap_log_error("[%u] <%u> %s Out-of-memory",
                       con->listener_index, con->con_index, con->addr);
        return -ENOMEM;
    }
    con->coap_client_port = strdup(uri->port);
    if (con->coap_client_port == NULL)
    {
        free(con->coap_client_host);
        con->coap_client_host = NULL;
        coap_client_destroy(&con->coap_client);
        coap_log_error("[%u] <%u> %s Out-of-memory",
                       con->listener_index, con->con_index, con->addr);
        return -ENOMEM;
    }
    con->coap_client_active = 1;
    return 0;
}

static void connection_coap_client_destroy(connection_t *con)
{
    coap_log_info("[%u] <%u> %s Disconnecting from CoAP server host %s and port %s",
                  con->listener_index, con->con_index, con->addr,
                  con->coap_client_host, con->coap_client_port);
    con->coap_client_active = 0;
    free(con->coap_client_port);
    con->coap_client_port = NULL;
    free(con->coap_client_host);
    con->coap_client_host = NULL;
    coap_client_destroy(&con->coap_client);
}

/*  return: { CON_RET_CLOSED,   socket closed remotely
 *          { CON_RET_TIMEDOUT, timeout
 *          { 0,                success
 *          {<0,                error
 */
static int connection_recv(connection_t *con, http_msg_t *msg)
{
    struct timeval tv = {0};
    ssize_t num = 0;
    fd_set readfds = {{0}};
    int ret = 0;
    int sd = 0;

    tv.tv_sec = tls_sock_get_timeout(con->sock);
    tv.tv_usec = 0;
    sd = tls_sock_get_sd(con->sock);
    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(sd, &readfds);
        errno = 0;
        ret = select(sd + 1, &readfds, NULL, NULL, &tv);
        if (ret == 0)
        {
            coap_log_info("[%u] <%u> %s Timed out waiting to read from socket connected to HTTP client",
                          con->listener_index, con->con_index, con->addr);
            return CON_RET_TIMEDOUT;
        }
        else if (ret == -1)
        {
            coap_log_error("[%u] <%u> %s Call to select returned: -1, errno: %d (%s)",
                           con->listener_index, con->con_index, con->addr, errno, strerror(errno));
            return -errno;
        }
        num = tls_sock_read(con->sock, data_buf_get_next(&con->recv_buf), data_buf_get_space(&con->recv_buf));
        if (num < 0)
        {
            coap_log_error("[%u] <%u> %s Failed to read from socket connected to HTTP client: %s",
                           con->listener_index, con->con_index, con->addr, sock_strerror(num));
            return -1;
        }
        if (num == 0)
        {
            coap_log_info("[%u] <%u> %s Socket connection to HTTP client closed remotely",
                          con->listener_index, con->con_index, con->addr);
            return CON_RET_CLOSED;
        }
        data_buf_add(&con->recv_buf, num);
        num = http_msg_parse(msg, data_buf_get_data(&con->recv_buf), data_buf_get_count(&con->recv_buf));
        if (num > 0)
        {
            data_buf_consume(&con->recv_buf, num);
            coap_log_debug("[%u] <%u> %s Received from HTTP client: %s %s %s",
                           con->listener_index, con->con_index, con->addr,
                           http_msg_get_start(msg, 0),
                           http_msg_get_start(msg, 1),
                           http_msg_get_start(msg, 2));
            return 0;  /* success */
        }
        else if (num == -EAGAIN)
        {
            coap_log_debug("[%u] <%u> %s Received incomplete request message from HTTP client",
                           con->listener_index, con->con_index, con->addr);
            if (data_buf_get_space(&con->recv_buf) < CONNECTION_DATA_BUF_MIN_SPACE)
            {
                coap_log_debug("[%u] <%u> %s Increasing size of receive buffer",
                               con->listener_index, con->con_index, con->addr);
                ret = data_buf_expand(&con->recv_buf);
                if (ret == -EINVAL)
                {
                    coap_log_error("[%u] <%u> %s Request message from HTTP client too long",
                                   con->listener_index, con->con_index, con->addr);
                    return ret;
                }
                else if (ret == -ENOMEM)
                {
                    coap_log_error("[%u] <%u> %s Out of memory",
                                   con->listener_index, con->con_index, con->addr);
                    return ret;
                }
            }
        }
        else
        {
            coap_log_error("[%u] <%u> %s Failed to parse request message from HTTP client: %s",
                           con->listener_index, con->con_index, con->addr, http_msg_strerror(ret));
            return num;
        }
    }
    return 0;
}

/*  return: { CON_RET_CLOSED, socket closed remotely
 *          { 0,              success
 *          {<0,              error
 */
static int connection_send(connection_t *con, http_msg_t *msg)
{
    ssize_t num = 0;
    size_t len = 0;
    int ret = 0;

    while (1)
    {
        len = http_msg_generate(msg, data_buf_get_data(&con->send_buf), data_buf_get_space(&con->send_buf));
        if (len <= data_buf_get_space(&con->send_buf))
        {
            break;
        }
        coap_log_debug("[%u] <%u> %s Increasing size of send buffer",
                       con->listener_index, con->con_index, con->addr);
        ret = data_buf_expand(&con->send_buf);
        if (ret == -EINVAL)
        {
            coap_log_error("[%u] <%u> %s Response message to HTTP client too long",
                           con->listener_index, con->con_index, con->addr);
            return ret;
        }
        else if (ret == -ENOMEM)
        {
            coap_log_error("[%u] <%u> %s Out of memory",
                           con->listener_index, con->con_index, con->addr);
            return ret;
        }
    }
    num = tls_sock_write_full(con->sock, data_buf_get_data(&con->send_buf), len);
    if (num < 0)
    {
        coap_log_error("[%u] <%u> %s Failed to write to socket conected to HTTP client: %s",
                       con->listener_index, con->con_index, con->addr, sock_strerror(num));
        return -1;
    }
    if (num == 0)
    {
        coap_log_error("[%u] <%u> %s Socket connection to HTTP client closed remotely",
                       con->listener_index, con->con_index, con->addr);
        return CON_RET_CLOSED;
    }
    coap_log_debug("[%u] <%u> %s Sent to HTTP client: %s %s %s",
                   con->listener_index, con->con_index, con->addr,
                   http_msg_get_start(msg, 0),
                   http_msg_get_start(msg, 1),
                   http_msg_get_start(msg, 2));
    return 0;
}

/*  return: { 0, success
 *          {<0, error
 */
static int connection_gen_error_resp(connection_t *con, http_msg_t *msg, unsigned code)
{
    const char *str = NULL;
    char int_buf[CONNECTION_INT_BUF_LEN] = {0};
    int ret = 0;

    snprintf(int_buf, sizeof(int_buf), "%u", code);
    str = cross_http_resp_code_to_str(code);
    ret = http_msg_set_start(msg, "HTTP/1.1", int_buf, str);
    if (ret < 0)
    {
        coap_log_error("[%u] <%u> %s Failed to set start line in response message to HTTP client: %s",
                       con->listener_index, con->con_index, con->addr, http_msg_strerror(ret));
        return ret;
    }
    return 0;
}

/*  return: { 0, success
 *          {<0, error
 */
static int connection_coap_exchange(connection_t *con, coap_msg_t *req_msg, coap_msg_t *resp_msg)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;
    unsigned block_size = 0;
    unsigned block_more = 0;
    unsigned block_num = 0;
    ssize_t num = 0;
    int ret = 0;

    if (coap_msg_get_code_detail(req_msg) == COAP_MSG_GET)
    {
        /* execute regular exchange */
        coap_log_info("[%u] <%u> %s Sending GET request to CoAP server host %s and port %s",
                      con->listener_index, con->con_index, con->addr,
                      con->coap_client_host, con->coap_client_port);
        ret = coap_client_exchange(&con->coap_client, req_msg, resp_msg);
        if (ret < 0)
        {
            return ret;
        }
        ret = coap_msg_parse_block_op(&block_num, &block_more, &block_size, resp_msg, COAP_MSG_BLOCK2);
        if (ret == 1)  /* not found */
        {
            return 0;
        }
        if (ret < 0)
        {
            return ret;
        }
        /* continue using block transfer */
        coap_log_info("[%u] <%u> %s Continuing GET request using blockwise transfer to CoAP server host %s and port %s",
                      con->listener_index, con->con_index, con->addr,
                      con->coap_client_host, con->coap_client_port);
        num = coap_client_exchange_blockwise(&con->coap_client,
                                             req_msg, resp_msg,
                                             block_size,
                                             block_size,
                                             con->body, con->body_len,
                                             /* have_resp */ 1);
        if (num < 0)
        {
            return num;
        }
        con->body_end = num;
    }
    else if (coap_msg_get_code_detail(req_msg) == COAP_MSG_PUT)
    {
        if (con->body_end > 0)
        {
            /* execute blockwise exchange */
            coap_log_info("[%u] <%u> %s Sending PUT request using blockwise transfer to CoAP server host %s and port %s",
                          con->listener_index, con->con_index, con->addr,
                          con->coap_client_host, con->coap_client_port);
            num = coap_client_exchange_blockwise(&con->coap_client,
                                                 req_msg, resp_msg,
                                                 CONNECTION_COAP_BLOCK1_SIZE,
                                                 CONNECTION_COAP_BLOCK2_SIZE,
                                                 con->body, con->body_end,
                                                 /* have_resp */ 0);
            if (num < 0)
            {
                return num;
            }
            con->body_end = num;
            return 0;
        }
        /* execute regular exchange */
        coap_log_info("[%u] <%u> %s Sending PUT request to CoAP server host %s and port %s",
                      con->listener_index, con->con_index, con->addr,
                      con->coap_client_host, con->coap_client_port);
        ret = coap_client_exchange(&con->coap_client, req_msg, resp_msg);
        if (ret < 0)
        {
            return ret;
        }
        code_class = coap_msg_get_code_class(resp_msg);
        code_detail = coap_msg_get_code_detail(resp_msg);
        if ((code_class == COAP_MSG_CLIENT_ERR)
         && (code_detail == COAP_MSG_REQ_ENT_TOO_LARGE))
        {
            /* retry using block transfer */
            memcpy(con->body, coap_msg_get_payload(req_msg), coap_msg_get_payload_len(req_msg));
            con->body_end = coap_msg_get_payload_len(req_msg);
            coap_msg_clear_payload(req_msg);
            coap_log_info("[%u] <%u> %s Resending PUT request using blockwise transfer to CoAP server host %s and port %s",
                          con->listener_index, con->con_index, con->addr,
                          con->coap_client_host, con->coap_client_port);
            num = coap_client_exchange_blockwise(&con->coap_client,
                                                 req_msg, resp_msg,
                                                 CONNECTION_COAP_BLOCK1_SIZE,
                                                 CONNECTION_COAP_BLOCK2_SIZE,
                                                 con->body, con->body_end,
                                                 /* have_resp */ 0);
            if (num < 0)
            {
                return num;
            }
            con->body_end = num;
        }
    }
    else if (coap_msg_get_code_detail(req_msg) == COAP_MSG_POST)
    {
        if (con->body_end > 0)
        {
            /* execute blockwise exchange */
            coap_log_info("[%u] <%u> %s Sending POST request using blockwise transfer to CoAP server host %s and port %s",
                          con->listener_index, con->con_index, con->addr,
                          con->coap_client_host, con->coap_client_port);
            num = coap_client_exchange_blockwise(&con->coap_client,
                                                 req_msg, resp_msg,
                                                 CONNECTION_COAP_BLOCK1_SIZE,
                                                 CONNECTION_COAP_BLOCK2_SIZE,
                                                 con->body, con->body_end,
                                                 /* have_resp */ 0);
            if (num < 0)
            {
                return num;
            }
            con->body_end = num;
            return 0;
        }
        /* execute regular exchange */
        coap_log_info("[%u] <%u> %s Sending POST request to CoAP server host %s and port %s",
                      con->listener_index, con->con_index, con->addr,
                      con->coap_client_host, con->coap_client_port);
        ret = coap_client_exchange(&con->coap_client, req_msg, resp_msg);
        if (ret < 0)
        {
            return ret;
        }
        code_class = coap_msg_get_code_class(resp_msg);
        code_detail = coap_msg_get_code_detail(resp_msg);
        if ((code_class == COAP_MSG_CLIENT_ERR)
         && (code_detail == COAP_MSG_REQ_ENT_TOO_LARGE))
        {
            /* retry using block transfer */
            memcpy(con->body, coap_msg_get_payload(req_msg), coap_msg_get_payload_len(req_msg));
            con->body_end = coap_msg_get_payload_len(req_msg);
            coap_msg_clear_payload(req_msg);
            coap_log_info("[%u] <%u> %s Resending POST request using blockwise transfer to CoAP server host %s and port %s",
                          con->listener_index, con->con_index, con->addr,
                          con->coap_client_host, con->coap_client_port);
            num = coap_client_exchange_blockwise(&con->coap_client,
                                                 req_msg, resp_msg,
                                                 CONNECTION_COAP_BLOCK1_SIZE,
                                                 CONNECTION_COAP_BLOCK2_SIZE,
                                                 con->body, con->body_end,
                                                 /* have_resp */ 0);
            if (num < 0)
            {
                return num;
            }
            con->body_end = num;
        }
    }
    return 0;
}

/*  return: { 0, success
 *          {<0, error
 */
static int connection_process(connection_t *con, http_msg_t *req_msg, http_msg_t *resp_msg)
{
    coap_msg_t coap_resp_msg = {0};
    coap_msg_t coap_req_msg = {0};
    unsigned code = 0;
    uri_t uri = {0};
    int ret = 0;

    coap_msg_create(&coap_req_msg);
    ret = cross_req_http_to_coap(&coap_req_msg, con->body, con->body_len, &con->body_end, req_msg, &code);
    if (ret < 0)
    {
        coap_log_error("[%u] <%u> %s Failed to convert HTTP message to CoAP message: %s",
                       con->listener_index, con->con_index, con->addr, strerror(-ret));
        coap_msg_destroy(&coap_req_msg);
        return connection_gen_error_resp(con, resp_msg, code);
    }
    uri_create(&uri);
    ret = uri_parse(&uri, http_msg_get_start(req_msg, 1));
    if (ret < 0)
    {
        coap_log_error("[%u] <%u> %s Failed to parse request URI in request message from HTTP client: %s",
                       con->listener_index, con->con_index, con->addr, strerror(-ret));
        uri_destroy(&uri);
        coap_msg_destroy(&coap_req_msg);
        return ret;
    }
    if (!con->coap_client_active)
    {
        /* first exchange with a CoAP server */
        ret = connection_coap_client_create(con, &uri);
        if (ret < 0)
        {
            uri_destroy(&uri);
            coap_msg_destroy(&coap_req_msg);
            return ret;
        }
    }
    else if ((strcasecmp(uri_get_host(&uri), con->coap_client_host) != 0)
          || (strcmp(uri_get_port(&uri), con->coap_client_port) != 0))
    {
        /* subsequent exchange with a different CoAP server */
        connection_coap_client_destroy(con);
        ret = connection_coap_client_create(con, &uri);
        if (ret < 0)
        {
            uri_destroy(&uri);
            coap_msg_destroy(&coap_req_msg);
            return ret;
        }
    }
    else
    {
        /* subsequent exchange with the same CoAP server */
        coap_log_debug("[%u] <%u> %s Maintaining connection to CoAP server host %s and port %s",
                       con->listener_index, con->con_index, con->addr,
                       con->coap_client_host, con->coap_client_port);
    }
    uri_destroy(&uri);
    coap_msg_create(&coap_resp_msg);
    ret = connection_coap_exchange(con, &coap_req_msg, &coap_resp_msg);
    coap_msg_destroy(&coap_req_msg);
    if (ret < 0)
    {
        coap_log_error("[%u] <%u> %s CoAP client exchange failed: %s",
                       con->listener_index, con->con_index, con->addr, strerror(-ret));
        switch (ret)
        {
        case -ETIMEDOUT:
            /* If the proxy services the request by interacting with a third party
             * (such as the CoAP origin server) and is unable to obtain a result within
             * a reasonable time frame, a 504 (Gateway Timeout) response is returned.
             */
            ret = connection_gen_error_resp(con, resp_msg, 504);
            break;
        case -EBADMSG:
            /* If a result can be obtained but is not understood, a 502 (Bad Gateway)
             * response is returned.
             */
            ret = connection_gen_error_resp(con, resp_msg, 502);
            break;
        default:
            /* If the proxy is unable or unwilling to service a request with a CoAP URI,
             * a 501 (Not Implemented) response is returned to the client.
             */
            ret = connection_gen_error_resp(con, resp_msg, 501);
            break;
        }
        coap_msg_destroy(&coap_resp_msg);
        return ret;
    }
    ret = cross_resp_coap_to_http(resp_msg, &coap_resp_msg, con->body, con->body_end, &code);
    coap_msg_destroy(&coap_resp_msg);
    if (ret < 0)
    {
        coap_log_error("[%u] <%u> %s Failed to convert CoAP message to HTTP message: %s",
                       con->listener_index, con->con_index, con->addr, strerror(-ret));
        return connection_gen_error_resp(con, resp_msg, code);
    }
    return 0;
}

/*  return: { CON_RET_CLOSED,   socket closed remotely
 *          { CON_RET_TIMEDOUT, timeout
 *          { 0,                success
 *          {<0,                error
 */
static int __connection_exchange(connection_t *con, http_msg_t *req_msg, http_msg_t *resp_msg)
{
    int ret = 0;

    /* receive request */
    ret = connection_recv(con, req_msg);
    if (ret != 0)  /* this must be if (ret != 0) and not if (ret < 0) */
    {
        return ret;  /* timeout or error */
    }

    /* process request and generate response */
    ret = connection_process(con, req_msg, resp_msg);
    if (ret < 0)
    {
        return ret;
    }

    /* send response */
    ret = connection_send(con, resp_msg);
    if (ret != 0)  /* this must be if (ret != 0) and not if (ret < 0) */
    {
        return ret;
    }

    return 0;
}

/*  return: { CON_RET_CLOSED,   socket closed remotely
 *          { CON_RET_TIMEDOUT, timeout
 *          { 0,                success
 *          {<0,                error
 */
static int connection_exchange(connection_t *con)
{
    http_msg_t resp_msg = {{0}};
    http_msg_t req_msg = {{0}};
    int status = 0;

    coap_log_notice("[%u] <%u> %s Transaction with HTTP client started",
                    con->listener_index, con->con_index, con->addr);

    memset(con->body, 0, con->body_len);
    con->body_end = 0;

    http_msg_create(&req_msg);
    http_msg_create(&resp_msg);

    status = __connection_exchange(con, &req_msg, &resp_msg);

    if (status == CON_RET_TIMEDOUT)
    {
        coap_log_notice("[%u] <%u> %s Transaction with HTTP client timed out",
                        con->listener_index, con->con_index, con->addr);
    }
    else if (status == CON_RET_CLOSED)
    {
        coap_log_notice("[%u] <%u> %s Transaction with HTTP client closed remotely",
                        con->listener_index, con->con_index, con->addr);
    }
    else if (status == 0)
    {
        coap_log_notice("[%u] <%u> %s Transaction with HTTP client successful",
                        con->listener_index, con->con_index, con->addr);
        stats_ok_trans();
    }
    else if (status < 0)
    {
        coap_log_notice("[%u] <%u> %s Transaction with HTTP client failed",
                        con->listener_index, con->con_index, con->addr);
        stats_fail_trans();
    }

    http_msg_destroy(&resp_msg);
    http_msg_destroy(&req_msg);

    con->num_exchanges++;

    return status;
}

void *connection_thread_func(void *data)
{
    connection_t *con = (connection_t *)data;
    int status = 0;

    thread_block_signals();
    coap_log_notice("[%u] <%u> %s Connection with HTTP client started",
                    con->listener_index, con->con_index, con->addr);
    while (status == 0)
    {
        status = connection_exchange(con);
    }
    if (status < 0)
    {
        coap_log_notice("[%u] <%u> %s Connection with HTTP client failed",
                        con->listener_index, con->con_index, con->addr);
        stats_fail_con();
    }
    else
    {
        coap_log_notice("[%u] <%u> %s Connection with HTTP client successful",
                        con->listener_index, con->con_index, con->addr);
        stats_ok_con();
    }
    connection_delete(con);
    stats_log();
    return NULL;
}

connection_t *connection_new(tls_sock_t *sock, unsigned listener_index, unsigned con_index, param_t *param)
{
    connection_t *con = NULL;
    int ret = 0;

    con = (connection_t *)calloc(1, sizeof(connection_t));
    if (con == NULL)
    {
        coap_log_error("Out of memory");
        return NULL;
    }
    con->listener_index = listener_index;
    con->con_index = con_index;
    tls_sock_get_addr_string(sock, con->addr, sizeof(con->addr));
    con->sock = sock;
    ret = data_buf_create(&con->recv_buf, CONNECTION_DATA_BUF_SIZE, CONNECTION_DATA_BUF_MAX_SIZE);
    if (ret == -EINVAL)
    {
        coap_log_error("[%u] <%u> Attempt to create data buffer with invalid size",
                       listener_index, con_index);
        free(con);
        return NULL;
    }
    else if (ret == -ENOMEM)
    {
        coap_log_error("[%u] <%u> Out of memory",
                       listener_index, con_index);
        free(con);
        return NULL;
    }
    ret = data_buf_create(&con->send_buf, CONNECTION_DATA_BUF_SIZE, CONNECTION_DATA_BUF_MAX_SIZE);
    if (ret == -EINVAL)
    {
        coap_log_error("[%u] <%u> Attempt to create data buffer with invalid size",
                       listener_index, con_index);
        data_buf_destroy(&con->recv_buf);
        free(con);
        return NULL;
    }
    else if (ret == -ENOMEM)
    {
        coap_log_error("[%u] <%u> Out of memory",
                       listener_index, con_index);
        data_buf_destroy(&con->recv_buf);
        free(con);
        return NULL;
    }
    con->param = param;
    con->body = (char *)malloc(CONNECTION_BODY_LEN);
    if (con->body == NULL)
    {
        coap_log_error("[%u] <%u> Out of memory",
                       listener_index, con_index);
        data_buf_destroy(&con->send_buf);
        data_buf_destroy(&con->recv_buf);
        free(con);
        return NULL;
    }
    con->body_len = CONNECTION_BODY_LEN;
    con->body_end = 0;
    return con;
}

void connection_delete(connection_t *con)
{
    if (con->coap_client_active)
    {
        connection_coap_client_destroy(con);
    }
    data_buf_destroy(&con->send_buf);
    data_buf_destroy(&con->recv_buf);
    free(con->body);
    tls_sock_close(con->sock);
    free(con->sock);
    free(con);
}
