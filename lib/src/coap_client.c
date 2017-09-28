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
 *  @file coap_client.c
 *
 *  @brief Source file for the FreeCoAP client library
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/select.h>
#include <linux/types.h>
#include "coap_client.h"
#include "coap_log.h"
#ifdef COAP_DTLS_EN
#include "dtls_debug.h"
#endif

#define COAP_CLIENT_ACK_TIMEOUT_SEC   2                                         /**< Minimum delay to wait before retransmitting a confirmable message */
#define COAP_CLIENT_MAX_RETRANSMIT    4                                         /**< Maximum number of times a confirmable message can be retransmitted */
#define COAP_CLIENT_RESP_TIMEOUT_SEC  30                                        /**< Maximum amount of time to wait for a response */

#ifdef COAP_DTLS_EN

#define COAP_CLIENT_DTLS_RETRANS_TIMEOUT  100                                   /**< Retransmission timeout (msec) for the DTLS handshake */
#define COAP_CLIENT_DTLS_TOTAL_TIMEOUT    5000                                  /**< Total timeout (msec) for the DTLS handshake */
                                                                                /**< DTLS priorities */
#endif

static int rand_init = 0;                                                       /**< Indicates whether or not the random number generator has been initialised */

#ifdef COAP_DTLS_EN

/****************************************************************************************************
 *                                         coap_client_dtls                                         *
 ****************************************************************************************************/

/**
 *  @brief Listen for a packet from the server with a timeout
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] ms Timeout value in msec
 *
 *  @returns Operation status
 *  @retval 1 Success
 *  @retval 0 Timeout
 *  @retval <0 Error
 */
static int coap_client_dtls_listen_timeout(coap_client_t *client, unsigned ms)
{
    struct timeval tv = {0};
    fd_set read_fds = {{0}};
    int ret = 0;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(client->sd, &read_fds);
        ret = select(client->sd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0)
        {
            return -errno;
        }
        if (ret == 0)
        {
            return 0;  /* timeout */
        }
        if (FD_ISSET(client->sd, &read_fds))
        {
            return 1;  /* success */
        }
    }
}

/**
 *  @brief Send encrypted data to the network
 *
 *  @param[in] ctx Pointer to a DTLS context structure
 *  @param[in] sess Pointer to a DTLS session structure
 *  @param[in] data Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes sent or error code
 *  @retval >=0 Number of bytes sent
 *  @retval <0 Error
 */
static int coap_client_dtls_write(dtls_context_t *ctx, session_t *sess, uint8_t *data, size_t len)
{
    coap_client_t *client = NULL;

    client = (coap_client_t *)dtls_get_app_data(ctx);
    return sendto(client->sd, data, len, 0, (struct sockaddr *)&client->server_sin, client->server_sin_len);
}

/**
 *  @brief Receive application data from the DTLS library
 *
 *  @param[in] ctx Pointer to a DTLS context structure
 *  @param[in] sess Pointer to a DTLS session structure
 *  @param[in] data Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes received
 */
static int coap_client_dtls_read(dtls_context_t *ctx, session_t *sess, uint8_t *data, size_t len)
{
    coap_client_t *client = NULL;

    client = (coap_client_t *)dtls_get_app_data(ctx);
    client->app_start = (char *)data;
    client->app_len = len;
    return len;
}

/**
 *  @brief Handle events generated by the DTLS library
 *
 *  @param[in] ctx Pointer to a DTLS context structure
 *  @param[in] sess Pointer to a DTLS session structure
 *  @param[in] level Severity level of the event
 *  @param[in] code Code for the event
 *
 *  @returns 0
 */
static int coap_client_dtls_event(dtls_context_t *ctx, session_t *sess, dtls_alert_level_t level, unsigned short code)
{
    coap_client_t *client = NULL;

    client = (coap_client_t *)dtls_get_app_data(ctx);
    if ((level == 0) && (code == DTLS_EVENT_CONNECTED))
    {
        client->state = COAP_CLIENT_DTLS_CONNECTED;
    }
    else if (level > 0)
    {
        client->state = COAP_CLIENT_DTLS_ALERT;
    }
    return 0;
}

/**
 *  @brief Pass the ECDSA keys to the DTLS library
 *
 *  @param[in] ctx Pointer to a DTLS context structure
 *  @param[in] sess Pointer to a DTLS session structure
 *  @param[out] res Double pointer to return the ECDSA keys
 *
 *  @returns 0
 */
static int coap_client_dtls_get_ecdsa_key(dtls_context_t *ctx, const session_t *sess, const dtls_ecdsa_key_t **res)
{
    coap_client_t *client = NULL;

    client = (coap_client_t *)dtls_get_app_data(ctx);
    *res = &client->ecdsa_key;

    return 0;
}

/**
 *  @brief Convert one component (x or y) of an ECDSA public key to a string representation
 *
 *  @param[out] buf Pointer to a buffer to hold the string
 *  @param[in] buf_len Length of the buffer to hold the string
 *  @param[in] data Pointer to a buffer that holds the key component
 *  @param[in] data_len Length of the buffer that holds the key component
 */
static void coap_client_dtls_ecdsa_comp_to_str(char *buf, size_t buf_len, const unsigned char *data, size_t data_len)
{
    unsigned i = 0;
    size_t cur_len = 0;
    char *cur = NULL;

    cur = buf;
    cur_len = buf_len;
    for (i = 0; i < data_len - 1; i++)
    {
        snprintf(cur, cur_len, "0x%02x, ", data[i]);
        cur += 6;
        cur_len = (cur_len < 6) ? 0 : cur_len - 6;
    }
    snprintf(cur, cur_len, "0x%02x", data[i]);
}

/**
 *  @brief Verify the ECDSA public key received from the server
 *
 *  @param[in] ctx Pointer to a DTLS context structure
 *  @param[in] sess Pointer to a DTLS session structure
 *  @param[in] ecdsa_pub_key_x Buffer containing the x component of the ECDSA public key
 *  @param[in] ecdsa_pub_key_y Buffer containing the y component of the ECDSA public key
 *  @param[in] key_size Size of the ecdsa_pub_key_x and ecdsa_pub_key_y buffers
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_dtls_verify_ecdsa_key(dtls_context_t *ctx, const session_t *sess,
                                             const unsigned char *ecdsa_pub_key_x,
                                             const unsigned char *ecdsa_pub_key_y,
                                             size_t key_size)
{
    const unsigned char *ecdsa_access_x = NULL;
    const unsigned char *ecdsa_access_y = NULL;
    coap_client_t *client = NULL;
    unsigned i = 0;
    char buf[256] = {0};

    client = (coap_client_t *)dtls_get_app_data(ctx);

    coap_client_dtls_ecdsa_comp_to_str(buf, sizeof(buf), ecdsa_pub_key_x, key_size);
    coap_log_debug("server ecdsa_pub_key_x[%zd]: [%s]",  key_size, buf);
    coap_client_dtls_ecdsa_comp_to_str(buf, sizeof(buf), ecdsa_pub_key_y, key_size);
    coap_log_debug("server ecdsa_pub_key_y[%zd]: [%s]",  key_size, buf);

    if (key_size != client->ecdsa_size)
    {
        return -EPERM;
    }
    for (i = 0; i < client->ecdsa_access_num; i++)
    {
        ecdsa_access_x = client->ecdsa_access_x + (i * client->ecdsa_size);
        ecdsa_access_y = client->ecdsa_access_y + (i * client->ecdsa_size);
        if ((memcmp((void *)ecdsa_pub_key_x, (void *)ecdsa_access_x, client->ecdsa_size) == 0)
         && (memcmp((void *)ecdsa_pub_key_y, (void *)ecdsa_access_y, client->ecdsa_size) == 0))
        {
            return 0;
        }
    }
    return -EPERM;
}

/**
 *  @brief Set of callback functions for the DTLS library
 */
static dtls_handler_t coap_client_dtls_cb =
{
    .write = coap_client_dtls_write,
    .read = coap_client_dtls_read,
    .event = coap_client_dtls_event,
    .get_ecdsa_key = coap_client_dtls_get_ecdsa_key,
    .verify_ecdsa_key = coap_client_dtls_verify_ecdsa_key
};

/**
 *  @brief Send application data to the DTLS library
 *
 *  @param[in] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes received or error code
 *  @retval >=0 Number of bytes received
 *  @retval <0 Error
 */
static ssize_t coap_client_dtls_send(coap_client_t *client, const char *buf, size_t len)
{
    int ret = 0;

    errno = 0;
    ret = dtls_write(client->ctx, &client->sess, (uint8_t *)buf, len);
    if (errno != 0)
    {
        return -errno;
    }
    if (client->state == COAP_CLIENT_DTLS_ALERT)
    {
        return -ECONNRESET;
    }
    if (ret < 0)
    {
        return -1;
    }
    return len;
}

/**
 *  @brief Receive encrypted data from the network
 *
 *  @param[in] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes received or error code
 *  @retval >=0 Number of bytes received
 *  @retval <0 Error
 */
static ssize_t coap_client_dtls_recv(coap_client_t *client, char *buf, size_t len)
{
    ssize_t num = 0;
    int ret = 0;

    num = recv(client->sd, buf, len, 0);
    if (num < 0)
    {
        return -errno;
    }
    client->app_start = NULL;
    client->app_len = 0;
    errno = 0;
    ret = dtls_handle_message(client->ctx, &client->sess, (uint8_t *)buf, num);
    if (errno != 0)
    {
        return -errno;
    }
    if (client->state == COAP_CLIENT_DTLS_ALERT)
    {
        return -ECONNRESET;
    }
    if (ret < 0)
    {
        return -1;
    }
    if (client->app_start == NULL)
    {
        return -EAGAIN;
    }
    memmove(buf, client->app_start, client->app_len);
    return client->app_len;
}

/**
 *  @brief Perform a DTLS handshake with the server
 *
 *  @param[in,out] client Pointer to a client structure
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_dtls_handshake(coap_client_t *client)
{
    ssize_t num = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};
    int ret = 0;
    int i = 0;

    ret = dtls_connect(client->ctx, &client->sess);
    if (ret < 0)
    {
        return -1;
    }
    for (i = 0; i < COAP_CLIENT_DTLS_TOTAL_TIMEOUT / COAP_CLIENT_DTLS_RETRANS_TIMEOUT; i++)
    {
        if (client->state != COAP_CLIENT_DTLS_UNCONNECTED)
        {
            break;
        }
        ret = coap_client_dtls_listen_timeout(client, COAP_CLIENT_DTLS_RETRANS_TIMEOUT);
        if (ret < 0)
        {
            return ret;
        }
        num = coap_client_dtls_recv(client, buf, sizeof(buf));
        if ((num < 0) && (num != -EAGAIN))
        {
            return num;
        }
    }
    if (client->state == COAP_CLIENT_DTLS_ALERT)
    {
        return -ECONNRESET;
    }
    if (client->state != COAP_CLIENT_DTLS_CONNECTED)
    {
        return -ETIMEDOUT;
    }
    return 0;
}

/**
 *  @brief Initialise the DTLS members of a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] ecdsa_priv_key Buffer containing the ECDSA private key
 *  @param[in] ecdsa_pub_key_x Buffer containing the x component of the ECDSA public key
 *  @param[in] ecdsa_pub_key_y Buffer containing the y component of the ECDSA public key
 *  @param[in] ecdsa_access_x Buffer containing the x components of the ECDSA access control list
 *  @param[in] ecdsa_access_y Buffer containing the y components of the ECDSA access control list
 *  @param[in] ecdsa_access_num Number of entries in the ECDSA access control list
 *  @param[in] ecdsa_size Size of an ECDSA component
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_dtls_create(coap_client_t *client,
                                   const unsigned char *ecdsa_priv_key,
                                   const unsigned char *ecdsa_pub_key_x,
                                   const unsigned char *ecdsa_pub_key_y,
                                   const unsigned char *ecdsa_access_x,
                                   const unsigned char *ecdsa_access_y,
                                   unsigned ecdsa_access_num,
                                   unsigned ecdsa_size)
{
    static int dtls_lib_init_done = 0;
    int ret = 0;

    if (!dtls_lib_init_done)
    {
        dtls_init();
        dtls_set_log_level(DTLS_LOG_EMERG);
        dtls_lib_init_done = 1;
    }
    client->ctx = dtls_new_context(client);
    if (client->ctx == NULL)
    {
        coap_log_error("Failed to create DTLS context");
        return -1;
    }
    client->ecdsa_key.curve = DTLS_ECDH_CURVE_SECP256R1;
    client->ecdsa_key.priv_key = ecdsa_priv_key;
    client->ecdsa_key.pub_key_x = ecdsa_pub_key_x;
    client->ecdsa_key.pub_key_y = ecdsa_pub_key_y;
    client->ecdsa_access_x = ecdsa_access_x;
    client->ecdsa_access_y = ecdsa_access_y;
    client->ecdsa_access_num = ecdsa_access_num;
    client->ecdsa_size = ecdsa_size;
    client->sess.size = client->server_sin_len;
    memcpy(&client->sess.addr.sin6, &client->server_sin, client->server_sin_len);
    client->sess.ifindex = 0;
    dtls_set_handler(client->ctx, &coap_client_dtls_cb);
    ret = coap_client_dtls_handshake(client);
    if (ret < 0)
    {
        coap_log_warn("Failed to complete DTLS handshake");
        dtls_free_context(client->ctx);
        return ret;
    }
    return 0;
}

/**
 *  @brief Deinitialise the DTLS members of a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 */
static void coap_client_dtls_destroy(coap_client_t *client)
{
    dtls_close(client->ctx, &client->sess);
    dtls_free_context(client->ctx);
}

#endif  /* COAP_DTLS_EN */

/****************************************************************************************************
 *                                           coap_client                                            *
 ****************************************************************************************************/

#ifdef COAP_DTLS_EN
int coap_client_create(coap_client_t *client,
                       const char *host,
                       const char *port,
                       const unsigned char *ecdsa_priv_key,
                       const unsigned char *ecdsa_pub_key_x,
                       const unsigned char *ecdsa_pub_key_y,
                       const unsigned char *ecdsa_access_x,
                       const unsigned char *ecdsa_access_y,
                       unsigned ecdsa_access_num,
                       unsigned ecdsa_size)
#else
int coap_client_create(coap_client_t *client,
                       const char *host,
                       const char *port)
#endif
{
    struct addrinfo hints = {0};
    struct addrinfo *list = NULL;
    struct addrinfo *node = NULL;
    int flags = 0;
    int ret = 0;

    if ((client == NULL) || (host == NULL) || (port == NULL))
    {
        return -EINVAL;
    }
    memset(client, 0, sizeof(coap_client_t));
    /* resolve host and port */
    hints.ai_flags = 0;
    hints.ai_family = COAP_IPV_AF_INET;  /* preferred socket domain */
    hints.ai_socktype = SOCK_DGRAM;      /* preferred socket type */
    hints.ai_protocol = 0;               /* preferred protocol (3rd argument to socket()) - 0 specifies that any protocol will do */
    hints.ai_addrlen = 0;                /* must be 0 */
    hints.ai_addr = NULL;                /* must be NULL */
    hints.ai_canonname = NULL;           /* must be NULL */
    hints.ai_next = NULL;                /* must be NULL */
    ret = getaddrinfo(host, port, &hints, &list);
    if (ret < 0)
    {
        return -EBUSY;
    }
    for (node = list; node != NULL; node = node->ai_next)
    {
        if ((node->ai_family == COAP_IPV_AF_INET)
         && (node->ai_socktype == SOCK_DGRAM))
        {
            client->sd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
            if (client->sd < 0)
            {
                continue;
            }
            ret = connect(client->sd, node->ai_addr, node->ai_addrlen);
            if (ret < 0)
            {
                close(client->sd);
                continue;
            }
            memcpy(&client->server_sin, node->ai_addr, node->ai_addrlen);
            client->server_sin_len = node->ai_addrlen;
            break;
        }
    }
    freeaddrinfo(list);
    if (node == NULL)
    {
        memset(client, 0, sizeof(coap_client_t));
        return -EBUSY;
    }
    flags = fcntl(client->sd, F_GETFL, 0);
    if (flags < 0)
    {
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
    ret = fcntl(client->sd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
    {
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
    strncpy(client->server_host, host, sizeof(client->server_host) - 1);
    strncpy(client->server_port, port, sizeof(client->server_port) - 1);
    client->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (client->timer_fd < 0)
    {
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return -errno;
    }
#ifdef COAP_DTLS_EN
    ret = coap_client_dtls_create(client,
                                  ecdsa_priv_key,
                                  ecdsa_pub_key_x,
                                  ecdsa_pub_key_y,
                                  ecdsa_access_x,
                                  ecdsa_access_y,
                                  ecdsa_access_num,
                                  ecdsa_size);
    if (ret < 0)
    {
        close(client->timer_fd);
        close(client->sd);
        memset(client, 0, sizeof(coap_client_t));
        return ret;
    }
#endif
    coap_log_notice("Connected to host %s and port %s", client->server_host, client->server_port);
    return 0;
}

void coap_client_destroy(coap_client_t *client)
{
#ifdef COAP_DTLS_EN
    coap_client_dtls_destroy(client);
#endif
    close(client->timer_fd);
    close(client->sd);
    memset(client, 0, sizeof(coap_client_t));
}

/**
 *  @brief Initialise the acknowledgement timer in a client structure
 *
 *  The timer is initialised to a random duration between:
 *
 *  ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
 *  where:
 *  ACK_TIMEOUT = 2
 *  ACK_RANDOM_FACTOR = 1.5
 *
 *  @param[out] client Pointer to a client structure
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
    coap_log_debug("Acknowledgement timeout initialised to: %lu sec, %lu nsec", client->timeout.tv_sec, client->timeout.tv_nsec);
}

/**
 *  @brief Initialise the response timer in a client structure
 *
 *  The timer is initialised to a constant value.
 *
 *  @param[out] client Pointer to a client structure
 */
static void coap_client_init_resp_timeout(coap_client_t *client)
{
    client->timeout.tv_sec = COAP_CLIENT_RESP_TIMEOUT_SEC;
    client->timeout.tv_nsec = 0;
    coap_log_debug("Response timeout initialised to: %lu sec, %lu nsec", client->timeout.tv_sec, client->timeout.tv_nsec);
}

/**
 *  @brief Double the value of the timer in a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 */
static void coap_client_double_timeout(coap_client_t *client)
{
    unsigned msec = 2 * ((client->timeout.tv_sec * 1000)
                      + (client->timeout.tv_nsec / 1000000));
    client->timeout.tv_sec = msec / 1000;
    client->timeout.tv_nsec = (msec % 1000) * 1000000;
    coap_log_debug("Timeout doubled to: %lu sec, %lu nsec", client->timeout.tv_sec, client->timeout.tv_nsec);
}

/**
 *  @brief Start the timer in a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_start_timer(coap_client_t *client)
{
    struct itimerspec its = {{0}};
    int ret = 0;

    its.it_value = client->timeout;
    ret = timerfd_settime(client->timer_fd, 0, &its, NULL);
    if (ret < 0)
    {
        return -errno;
    }
    return 0;
}

/**
 *  @brief Initialise and start the acknowledgement timer in a client structure
 *
 *  @param[out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_start_ack_timer(coap_client_t *client)
{
    client->num_retrans = 0;
    coap_client_init_ack_timeout(client);
    return coap_client_start_timer(client);
}

/**
 *  @brief Update the acknowledgement timer in a client structure
 *
 *  Increase and restart the acknowledgement timer in a client structure
 *  and indicate if the maximum number of retransmits has been reached.
 *
 *  @param[in,out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
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

/**
 *  @brief Initialise and start the response timer in a client structure
 *
 *  @param[out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_start_resp_timer(coap_client_t *client)
{
    coap_client_init_resp_timeout(client);
    return coap_client_start_timer(client);
}

/**
 *  @brief Send a message to the server
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >0 Number of bytes sent
 *  @retval <0 Error
 */
static ssize_t coap_client_send(coap_client_t *client, coap_msg_t *msg)
{
    ssize_t num = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};

    num = coap_msg_format(msg, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
#ifdef COAP_DTLS_EN
    num = coap_client_dtls_send(client, buf, num);
    if (num < 0)
    {
        return num;
    }
#else
    num = send(client->sd, buf, num, 0);
    if (num < 0)
    {
        return -errno;
    }
#endif
    coap_log_debug("Sent to host %s and port %s", client->server_host, client->server_port);
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
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] buf Buffer containing the message
 *  @param[in] len length of the buffer
 */
static void coap_client_handle_format_error(coap_client_t *client, char *buf, size_t len)
{
    coap_msg_t msg = {0};
    unsigned msg_id = 0;
    unsigned type = 0;
    int ret = 0;

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
        coap_client_send(client, &msg);
        coap_msg_destroy(&msg);
    }
}

/**
 *  @brief Receive a message from the server
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes received or error code
 *  @retval >0 Number of bytes received
 *  @retval <0 Error
 */
static ssize_t coap_client_recv(coap_client_t *client, coap_msg_t *msg)
{
    ssize_t num = 0;
    ssize_t ret = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};

#ifdef COAP_DTLS_EN
    num = coap_client_dtls_recv(client, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
#else
    num = recv(client->sd, buf, sizeof(buf), 0);
    if (num < 0)
    {
        return -errno;
    }
#endif
    ret = coap_msg_parse(msg, buf, num);
    if (ret < 0)
    {
        if (ret == -EBADMSG)
        {
            coap_client_handle_format_error(client, buf, num);
        }
        return ret;
    }
    coap_log_debug("Received from host %s and port %s", client->server_host, client->server_port);
    return num;
}

/**
 *  @brief Reject a received confirmable message
 *
 *  Send a reset message to the server.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_reject_con(coap_client_t *client, coap_msg_t *msg)
{
    coap_msg_t rej = {0};
    int num = 0;
    int ret = 0;

    coap_log_info("Rejecting confirmable message from host %s and port %s", client->server_host, client->server_port);
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
    num = coap_client_send(client, &rej);
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
 *  @param[in] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int coap_client_reject_non(coap_client_t *client, coap_msg_t *msg)
{
    coap_log_info("Rejecting non-confirmable message from host %s and port %s", client->server_host, client->server_port);
    return 0;
}

/**
 *  @brief Reject a received acknowledgement message
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int coap_client_reject_ack(coap_client_t *client, coap_msg_t *msg)
{
    coap_log_info("Rejecting acknowledgement message from host %s and port %s", client->server_host, client->server_port);
    return 0;
}

/**
 *  @brief Reject a received reset message
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int coap_client_reject_reset(coap_client_t *client, coap_msg_t *msg)
{
    coap_log_info("Rejecting reset message from host %s and port %s", client->server_host, client->server_port);
    return 0;
}

/**
 *  @brief Reject a received message
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_reject(coap_client_t *client, coap_msg_t *msg)
{
    if (coap_msg_get_type(msg) == COAP_MSG_CON)
    {
        return coap_client_reject_con(client, msg);
    }
    else if (coap_msg_get_type(msg) == COAP_MSG_NON)
    {
        return coap_client_reject_non(client, msg);
    }
    else if (coap_msg_get_type(msg) == COAP_MSG_ACK)
    {
        return coap_client_reject_ack(client, msg);
    }
    else if (coap_msg_get_type(msg) == COAP_MSG_RST)
    {
        return coap_client_reject_reset(client, msg);
    }
    return 0;  /* should never arrive here */
}

/**
 *  @brief Send an acknowledgement message to the server
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_send_ack(coap_client_t *client, coap_msg_t *msg)
{
    coap_msg_t ack = {0};
    int num = 0;
    int ret = 0;

    coap_log_info("Acknowledging confirmable message from host %s and port %s", client->server_host, client->server_port);
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
    num = coap_client_send(client, &ack);
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
 *  Update the acknowledgement timer in the client structure
 *  and if the maximum number of retransmits has not been
 *  reached then retransmit the last request to the server.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_handle_ack_timeout(coap_client_t *client, coap_msg_t *msg)
{
    ssize_t num = 0;
    int ret = 0;

    coap_log_debug("Transaction expired for host %s and port %s", client->server_host, client->server_port);
    ret = coap_client_update_ack_timer(client);
    if (ret == 0)
    {
        coap_log_debug("Retransmitting to host %s and port %s", client->server_host, client->server_port);
        num = coap_client_send(client, msg);
        if (num < 0)
        {
            return num;
        }
    }
    else if (ret == -ETIMEDOUT)
    {
        coap_log_debug("Stopped retransmitting to host %s and port %s", client->server_host, client->server_port);
        coap_log_info("No acknowledgement received from host %s and port %s", client->server_host, client->server_port);
    }
    return ret;
}

/**
 *  @brief Wait for a message to arrive or the acknowledgement timer to expire
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
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
        if (ret < 0)
        {
            return -errno;
        }
        if (FD_ISSET(client->sd, &read_fds))
        {
            return 0;
        }
        if (FD_ISSET(client->timer_fd, &read_fds))
        {
            ret = coap_client_handle_ack_timeout(client, msg);
            if (ret < 0)
            {
                return ret;
            }
        }
    }
    return 0;
}

/**
 *  @brief Wait for a message to arrive or the response timer to expire
 *
 *  @param[in] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
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
        if (ret < 0)
        {
            return -errno;
        }
        if (FD_ISSET(client->sd, &read_fds))
        {
            break;
        }
        if (FD_ISSET(client->timer_fd, &read_fds))
        {
            return -ETIMEDOUT;
        }
    }
    return 0;
}

/**
 *  @brief Compare the token values in a request message and a response message
 *
 *  @param[in] req Pointer to the request message
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Comparison value
 *  @retval 0 the tokens are not equal
 *  @retval 1 the tokens are equal
 */
static int coap_client_match_token(coap_msg_t *req, coap_msg_t *resp)
{
    return ((coap_msg_get_token_len(resp) == coap_msg_get_token_len(req))
         && (memcmp(coap_msg_get_token(resp), coap_msg_get_token(req), coap_msg_get_token_len(req)) == 0));
}

/**
 *  @brief Check that all of the options in a message are acceptable
 *
 *  For a proxy, options are acceptable if they are safe to forward or recognized or both.
 *  For a server, options are acceptable if they are elective or recognized or both.
 *
 *  @param[in] msg Pointer to message structure
 *
 *  @returns Operation status or bad option number
 *  @retval 0 Success
 *  @retval >0 Bad option number
 */
static unsigned coap_client_check_options(coap_msg_t *msg)
{
#ifdef COAP_PROXY
    return coap_msg_check_unsafe_ops(msg);
#else  /* !COAP_PROXY */
    return coap_msg_check_critical_ops(msg);
#endif  /* COAP_PROXY */
}

/**
 *  @brief Handle a received piggy-backed response message
 *
 *  An acknowledgement has been received that contains
 *  the same token as the request. Check the response
 *  contained within it.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_handle_piggybacked_response(coap_client_t *client, coap_msg_t *resp)
{
    unsigned op_num = 0;

    op_num = coap_client_check_options(resp);
    if (op_num != 0)
    {
        coap_log_info("Found bad option number %u in message from host %s and port %s", op_num, client->server_host, client->server_port);
        coap_client_reject(client, resp);
        return -EBADMSG;
    }
    coap_log_info("Received acknowledgement and response from host %s and port %s", client->server_host, client->server_port);
    return 0;
}

/**
 *  @brief Handle a received separate response message
 *
 *  A separate response has been received that contains
 *  the same token as the request. Check the response
 *  and send an acknowledgement if necessary.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_handle_sep_response(coap_client_t *client, coap_msg_t *resp)
{
    unsigned op_num = 0;

    if (coap_msg_get_type(resp) == COAP_MSG_CON)
    {
        coap_log_info("Received confirmable response from host %s and port %s", client->server_host, client->server_port);
        op_num = coap_client_check_options(resp);
        if (op_num != 0)
        {
            coap_log_info("Found bad option number %u in message from host %s and port %s", op_num, client->server_host, client->server_port);
            coap_client_reject(client, resp);
            return -EBADMSG;
        }
        return coap_client_send_ack(client, resp);
    }
    else if (coap_msg_get_type(resp) == COAP_MSG_NON)
    {
        coap_log_info("Received non-confirmable response from host %s and port %s", client->server_host, client->server_port);
        op_num = coap_client_check_options(resp);
        if (op_num != 0)
        {
            coap_log_info("Found bad option number %u in message from host %s and port %s", op_num, client->server_host, client->server_port);
            coap_client_reject(client, resp);
            return -EBADMSG;
        }
        return 0;
    }
    coap_client_reject(client, resp);
    return -EBADMSG;
}

/**
 *  @brief Handle a separate response to a confirmable request
 *
 *  An acknowledgement has been received. Receive the
 *  response and send an acknowledgement back to the server.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_exchange_sep(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    ssize_t num = 0;
    int ret = 0;

    /* wait for a separate response to a confirmable request */
    coap_log_info("Expecting response from host %s and port %s", client->server_host, client->server_port);
    coap_client_start_resp_timer(client);
    while (1)
    {
        ret = coap_client_listen_resp(client);
        if (ret < 0)
        {
            return ret;
        }
        num = coap_client_recv(client, resp);
        if (num < 0)
        {
            return num;
        }
        if (coap_msg_get_msg_id(resp) == coap_msg_get_msg_id(req))
        {
            if (coap_msg_get_type(resp) == COAP_MSG_ACK)
            {
                /* message deduplication */
                coap_log_info("Received duplicate acknowledgement from host %s and port %s", client->server_host, client->server_port);
                continue;
            }
            else if (coap_msg_get_type(resp) == COAP_MSG_RST)
            {
                return -ECONNRESET;
            }
            coap_client_reject(client, resp);
            return -EBADMSG;
        }
        if (coap_client_match_token(req, resp))
        {
             return coap_client_handle_sep_response(client, resp);
        }
        /* message deduplication */
        /* we might have received a duplicate message that was already received from the same server */
        /* reject the message and continue listening */
        ret = coap_client_reject(client, resp);
        if (ret < 0 )
        {
            return ret;
        }
    }
    return 0;
}

/**
 *  @brief Handle the response to a confirmable request
 *
 *  A confirmable request has been sent to the server.
 *  Receive the acknowledgement and response. Send an
 *  acknowledgement if necessary.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_client_exchange_con(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    ssize_t num = 0;
    int ret = 0;

    /*  wait for piggy-backed response in ack message
     *  or ack message and separate response message
     */
    coap_log_info("Expecting acknowledgement from host %s and port %s", client->server_host, client->server_port);
    coap_client_start_ack_timer(client);
    while (1)
    {
        ret = coap_client_listen_ack(client, req);
        if (ret < 0)
        {
            return ret;
        }
        num = coap_client_recv(client, resp);
        if (num < 0)
        {
            return num;
        }
        if (coap_msg_get_msg_id(resp) == coap_msg_get_msg_id(req))
        {
            if (coap_msg_get_type(resp) == COAP_MSG_ACK)
            {
                if (coap_msg_is_empty(resp))
                {
                    /* received ack message, wait for separate response message */
                    coap_log_info("Received acknowledgement from host %s and port %s", client->server_host, client->server_port);
                    return coap_client_exchange_sep(client, req, resp);
                }
                else if (coap_client_match_token(req, resp))
                {
                    return coap_client_handle_piggybacked_response(client, resp);
                }
            }
            else if (coap_msg_get_type(resp) == COAP_MSG_RST)
            {
                return -ECONNRESET;
            }
            coap_client_reject(client, resp);
            return -EBADMSG;
        }
        else if (coap_client_match_token(req, resp))
        {
            /* RFC7252
             * as the underlying datagram transport may not be sequence-preserving,
             * the Confirmable message carrying the response may actually arrive
             * before or after the Acknowledgement message for the request; for
             * the purposes of terminating the retransmission sequence, this also
             * serves as an acknowledgement.
             */
             return coap_client_handle_sep_response(client, resp);
        }
        /* message deduplication */
        /* we might have received a duplicate message that was already received from the same server */
        /* reject the message and continue listening */
        ret = coap_client_reject(client, resp);
        if (ret < 0 )
        {
            return ret;
        }
    }
    return 0;
}

/**
 *  @brief Handle the response to a non-confirmable request
 *
 *  A non-confirmable request has been sent to the server.
 *  Receive the response.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 **/
static int coap_client_exchange_non(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    ssize_t num = 0;
    int ret = 0;

    coap_log_info("Expecting response from host %s and port %s", client->server_host, client->server_port);
    coap_client_start_resp_timer(client);
    while (1)
    {
        ret = coap_client_listen_resp(client);
        if (ret < 0)
        {
            return ret;
        }
        num = coap_client_recv(client, resp);
        if (num < 0)
        {
            return num;
        }
        if (coap_msg_get_msg_id(resp) == coap_msg_get_msg_id(req))
        {
            if (coap_msg_get_type(resp) == COAP_MSG_RST)
            {
                return -ECONNRESET;
            }
            coap_client_reject(client, resp);
            return -EBADMSG;
        }
        if (coap_client_match_token(req, resp))
        {
             return coap_client_handle_sep_response(client, resp);
        }
        /* message deduplication */
        /* we might have received a duplicate message that was already received from the same server */
        /* reject the message and continue listening */
        ret = coap_client_reject(client, resp);
        if (ret < 0 )
        {
            return ret;
        }
    }
    return 0;
}

int coap_client_exchange(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned char msg_id_buf[2] = {0};
    unsigned msg_id = 0;
    ssize_t num = 0;
    char token[4] = {0};
    int ret = 0;

    /* check for a valid request */
    if ((coap_msg_get_type(req) == COAP_MSG_ACK)
     || (coap_msg_get_type(req) == COAP_MSG_RST)
     || (coap_msg_get_code_class(req) != COAP_MSG_REQ))
    {
        return -EINVAL;
    }

    /* generate the message ID */
    coap_msg_gen_rand_str((char *)msg_id_buf, sizeof(msg_id_buf));
    msg_id = (((unsigned)msg_id_buf[1]) << 8) | (unsigned)msg_id_buf[0];
    ret = coap_msg_set_msg_id(req, msg_id);
    if (ret < 0)
    {
        return ret;
    }

    /* generate the token */
    coap_msg_gen_rand_str(token, sizeof(token));
    ret = coap_msg_set_token(req, token, sizeof(token));
    if (ret < 0)
    {
        return ret;
    }

    if (coap_msg_get_type(req) == COAP_MSG_CON)
    {
        coap_log_info("Sending confirmable request to host %s and port %s", client->server_host, client->server_port);
    }
    else if (coap_msg_get_type(req) == COAP_MSG_NON)
    {
        coap_log_info("Sending non-confirmable request to host %s and port %s", client->server_host, client->server_port);
    }

    num = coap_client_send(client, req);
    if (num < 0)
    {
        return num;
    }

    if (coap_msg_get_type(req) == COAP_MSG_CON)
    {
        return coap_client_exchange_con(client, req, resp);
    }
    else if (coap_msg_get_type(req) == COAP_MSG_NON)
    {
        return coap_client_exchange_non(client, req, resp);
    }
    return -EINVAL;
}
