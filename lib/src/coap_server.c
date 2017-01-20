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
#include <netdb.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/select.h>
#include <linux/types.h>
#ifdef COAP_DTLS_EN
#include <gnutls/x509.h>
#endif
#include "coap_server.h"
#include "coap_log.h"

#define COAP_SERVER_ACK_TIMEOUT_SEC       2                                     /**< Minimum delay to wait before retransmitting a confirmable message */
#define COAP_SERVER_MAX_RETRANSMIT        4                                     /**< Maximum number of times a confirmable message can be retransmitted */

#ifdef COAP_DTLS_EN

#define COAP_SERVER_DTLS_MTU              COAP_MSG_MAX_BUF_LEN                  /**< Maximum transmission unit excluding the UDP and IPv6 headers */
#define COAP_SERVER_DTLS_RETRANS_TIMEOUT  100                                   /**< Retransmission timeout (msec) for the DTLS handshake */
#define COAP_SERVER_DTLS_TOTAL_TIMEOUT    5000                                  /**< Total timeout (msec) for the DTLS handshake */
#define COAP_SERVER_DTLS_NUM_DH_BITS      1024                                  /**< DTLS Diffie-Hellman key size */
#define COAP_SERVER_DTLS_PRIORITIES       "PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE"
                                                                                /**< DTLS priorities */
#endif

static int rand_init = 0;                                                       /**< Indicates if the random number generator has been initialised */

/****************************************************************************************************
 *                                         coap_server_path                                         *
 ****************************************************************************************************/

/**
 *  @brief Allocate a URI path structure
 *
 *  @param[in] str String representation of a URI path
 *
 *  @returns New URI path structure
 *  @retval NULL Out-of-memory
 */
static coap_server_path_t *coap_server_path_new(const char *str)
{
    coap_server_path_t *path = NULL;

    path = (coap_server_path_t *)malloc(sizeof(coap_server_path_t));
    if (path == NULL)
    {
        return NULL;
    }
    path->str = strdup(str);
    if (path->str == NULL)
    {
        free(path);
        return NULL;
    }
    path->next = NULL;
    return path;
}

/**
 *  @brief Free a URI path structure
 *
 *  @param[in,out] path Pointer to a URI path structure
 */
static void coap_server_path_delete(coap_server_path_t *path)
{
    free(path->str);
    free(path);
}

/**
 *  @brief Initialise a URI path list structure
 *
 *  @param[out] list Pointer to a URI path list structure
 */
static void coap_server_path_list_create(coap_server_path_list_t *list)
{
    memset(list, 0, sizeof(coap_server_path_list_t));
}

/**
 *  @brief Deinitialise a URI path list structure
 *
 *  @param[in,out] list Pointer to a URI path list structure
 */
static void coap_server_path_list_destroy(coap_server_path_list_t *list)
{
    coap_server_path_t *prev = NULL;
    coap_server_path_t *path = NULL;

    path = list->first;
    while (path != NULL)
    {
        prev = path;
        path = path->next;
        coap_server_path_delete(prev);
    }
    memset(list, 0, sizeof(coap_server_path_list_t));
}

/**
 *  @brief Add a URI path to a URI path list structure
 *
 *  @param[in,out] list Pointer to a URI path list structure
 *  @param[in] str String representation of a URI path
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_path_list_add(coap_server_path_list_t *list, const char *str)
{
    coap_server_path_t *path = NULL;

    path = coap_server_path_new(str);
    if (path == NULL)
    {
        return -ENOMEM;
    }
    if (list->first == NULL)
    {
        list->first = path;
        list->last = path;
    }
    else
    {
        list->last->next = path;
        list->last = path;
    }
    return 0;
}

/**
 *  @brief Search a URI path list structure for a URI path
 *
 *  @param[in] list Pointer to a URI path list structure
 *  @param[in] str String representation of a URI path
 *
 *  @returns Comparison value
 *  @retval 0 The URI path list structure does not contain the URI path
 *  @retval 1 The URI path list structure does contain the URI path
 */
static int coap_server_path_list_match(coap_server_path_list_t *list, const char *str)
{
    coap_server_path_t *path = NULL;

    path = list->first;
    while (path != NULL)
    {
        coap_log_debug("Comparing URI path: '%s' with list URI path: '%s'", str, path->str);
        if (strcmp(path->str, str) == 0)
        {
            coap_log_debug("Matched URI path: '%s' with list URI path: '%s'", str, path->str);
            return 1;
        }
        path = path->next;
    }
    return 0;
}

#ifdef COAP_DTLS_EN

/****************************************************************************************************
 *                                      coap_server_trans_dtls                                      *
 ****************************************************************************************************/

/**
 *  @brief Listen for a packet from the client with a timeout
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] ms Timeout value in msec
 *
 *  @returns Operation status
 *  @retval 1 Success
 *  @retval 0 Timeout
 *  @retval <0 Error
 */
static int coap_server_trans_dtls_listen_timeout(coap_server_trans_t *trans, unsigned ms)
{
    coap_server_t *server = NULL;
    struct timeval tv = {0};
    fd_set read_fds = {{0}};
    int ret = 0;

    server = trans->server;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(server->sd, &read_fds);
        ret = select(server->sd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0)
        {
            return -errno;
        }
        if (ret == 0)
        {
            return 0;  /* timeout */
        }
        if (FD_ISSET(server->sd, &read_fds))
        {
            return 1;  /* success */
        }
    }
}

/**
 *  @brief Receive data from the client
 *
 *  This is a call-back function that the
 *  GnuTLS library uses to receive data.
 *
 *  @param[in,out] data Pointer to a transaction structure
 *  @param[out] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes received or error
 *  @retval 0 Number of bytes received
 *  @retval -1 Error
 */
static ssize_t coap_server_trans_dtls_pull_func(gnutls_transport_ptr_t data, void *buf, size_t len)
{
    coap_ipv_sockaddr_in_t client_sin = {0};
    coap_server_trans_t *trans = NULL;
    coap_server_t *server = NULL;
    socklen_t client_sin_len = 0;
    ssize_t num = 0;

    trans = (coap_server_trans_t *)data;
    server = trans->server;
    client_sin_len = sizeof(client_sin);
    num = recvfrom(server->sd, buf, len, MSG_PEEK, (struct sockaddr *)&client_sin, &client_sin_len);  /* peek data */
    if (num < 0)
    {
        return -1;
    }
    if ((client_sin_len != trans->client_sin_len)
     || (memcmp(&client_sin, &trans->client_sin, trans->client_sin_len) != 0))
    {
        errno = EINVAL;
        return -1;
    }
    return recvfrom(server->sd, buf, num, 0, (struct sockaddr *)&client_sin, &client_sin_len);  /* consume data */
}

/**
 *  @brief Wait for receive data from the client
 *
 *  This is a call-back function that the GnuTLS
 *  library uses to wait for receive data.
 *
 *  @param[in,out] data Pointer to a transaction structure
 *  @param[in] ms Timeout in msec
 *
 *  @returns Number of bytes received or error
 *  @retval >0 Number of bytes received
 *  @retval 0 Timeout
 *  @retval -1 Error
 */
static int coap_server_trans_dtls_pull_timeout_func(gnutls_transport_ptr_t data, unsigned ms)
{
    coap_ipv_sockaddr_in_t client_sin = {0};
    coap_server_trans_t *trans = NULL;
    coap_server_t *server = NULL;
    socklen_t client_sin_len = 0;
    ssize_t num = 0;
    char buf[COAP_SERVER_DTLS_MTU] = {0};
    int ret = 0;

    trans = (coap_server_trans_t *)data;
    server = trans->server;
    ret = coap_server_trans_dtls_listen_timeout(trans, ms);
    if (ret == 0)
    {
        return 0;  /* timeout */
    }
    if (ret < 0)
    {
        return -1;
    }
    client_sin_len = sizeof(client_sin);
    num = recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *)&client_sin, &client_sin_len);  /* peek data */
    if (num < 0)
    {
        return -1;
    }
    if ((client_sin_len != trans->client_sin_len)
     || (memcmp(&client_sin, &trans->client_sin, trans->client_sin_len) != 0))
    {
        errno = EINVAL;
        return -1;
    }
    return num;  /* success */
}

/**
 *  @brief Send data to the client
 *
 *  This is a call-back function that the
 *  GnuTLS library uses to send data.
 *
 *  @param[in] data Pointer to a transaction structure
 *  @param[in] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes sent or error
 *  @retval >0 Number of bytes sent
 *  @retval -1 Error
 */
static ssize_t coap_server_trans_dtls_push_func(gnutls_transport_ptr_t data, const void *buf, size_t len)
{
    coap_server_trans_t *trans = NULL;
    coap_server_t *server = NULL;

    trans = (coap_server_trans_t *)data;
    server = trans->server;
    return sendto(server->sd, buf, len, 0, (struct sockaddr *)&trans->client_sin, trans->client_sin_len);
}

/**
 *  @brief Perform a DTLS handshake with the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_dtls_handshake(coap_server_trans_t *trans)
{
    gnutls_cipher_algorithm_t cipher = 0;
    gnutls_mac_algorithm_t mac = 0;
    gnutls_kx_algorithm_t kx = 0;
    const char *cipher_suite = NULL;
    int ret = 0;
    int i = 0;

    for (i = 0; i < COAP_SERVER_DTLS_TOTAL_TIMEOUT / COAP_SERVER_DTLS_RETRANS_TIMEOUT; i++)
    {
        errno = 0;
        ret = gnutls_handshake(trans->session);
        if ((errno != 0) && (errno != EAGAIN))
        {
            return -errno;
        }
        if (ret == GNUTLS_E_SUCCESS)
        {
            coap_log_info("Completed DTLS handshake");
            /* determine which cipher suite was negotiated */
            kx = gnutls_kx_get(trans->session);
            cipher = gnutls_cipher_get(trans->session);
            mac = gnutls_mac_get(trans->session);
            cipher_suite = gnutls_cipher_suite_get_name(kx, cipher, mac);
            if (cipher_suite != NULL)
                coap_log_info("Cipher suite is TLS_%s", cipher_suite);
            else
                coap_log_info("Cipher suite is unknown");
            return 0;  /* success */
        }
        if (ret == GNUTLS_E_TIMEDOUT)
        {
            break;
        }
        if ((ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
         || (ret == GNUTLS_E_FATAL_ALERT_RECEIVED))
        {
            return -ECONNRESET;
        }
        if (ret != GNUTLS_E_AGAIN)
        {
            return -1;
        }
        ret = coap_server_trans_dtls_listen_timeout(trans, COAP_SERVER_DTLS_RETRANS_TIMEOUT);
        if (ret < 0)
        {
            return ret;
        }
    }
    return -ETIMEDOUT;
}

#ifdef COAP_CLIENT_AUTH

/**
 *  @brief Verify the clients's certificate
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_dtls_verify_peer_cert(coap_server_trans_t *trans)
{
    gnutls_certificate_type_t cert_type = 0;
    const gnutls_datum_t *cert_list = NULL;
    gnutls_x509_crt_t cert = {0};
    unsigned cert_list_size = 0;
    unsigned status = 0;
    time_t expiration_time = 0;
    time_t activation_time = 0;
    time_t current_time = 0;
    int ret = 0;

    ret = gnutls_certificate_verify_peers2(trans->session, &status);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("The peer certificate was not verified");
        return -1;
    }
    if (status & GNUTLS_CERT_INVALID)
    {
        coap_log_error("The peer certificate is not trusted");
        return -1;
    }
    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    {
        coap_log_error("No issuer found for the peer certificate");
        return -1;
    }
    if (status & GNUTLS_CERT_SIGNER_NOT_CA)
    {
        coap_log_error("The issuer for the peer certificate is not a certificate authority");
        return -1;
    }
    if (status & GNUTLS_CERT_REVOKED)
    {
        coap_log_error("The peer certificate has been revoked");
        return -1;
    }
    cert_type = gnutls_certificate_type_get(trans->session);
    if (cert_type != GNUTLS_CRT_X509)
    {
        coap_log_error("The peer certificate is not an X509 certificate");
        return -1;
    }
    ret = gnutls_x509_crt_init(&cert);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("Unable to initialise gnutls_x509_crt_t object");
        return -1;
    }
    cert_list = gnutls_certificate_get_peers(trans->session, &cert_list_size);
    if (cert_list == NULL)
    {
        coap_log_error("No peer certificate found");
        gnutls_x509_crt_deinit(cert);
        return -1;
    }
    /* We only check the first (leaf) certificate in the chain */
    ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("Unable to parse certificate");
        gnutls_x509_crt_deinit(cert);
        return -1;
    }
    current_time = time(NULL);
    expiration_time = gnutls_x509_crt_get_expiration_time(cert);
    if ((expiration_time == -1) || (expiration_time < current_time))
    {
        coap_log_error("The peer certificate has expired");
        gnutls_x509_crt_deinit(cert);
        return -1;
    }
    activation_time = gnutls_x509_crt_get_activation_time(cert);
    if ((activation_time == -1) || (activation_time > current_time))
    {
        coap_log_error("The peer certificate is not yet activated");
        gnutls_x509_crt_deinit(cert);
        return -1;
    }
    coap_log_info("Peer certificate validated");
    gnutls_x509_crt_deinit(cert);
    return 0;
}

#endif  /* COAP_CLIENT_AUTH */

/**
 *  @brief Initialise the DTLS members of a transaction structure
 *
 *  Perform a DTLS handshake with the client.
 *
 *  @param[out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -1 Error
 */
static int coap_server_trans_dtls_create(coap_server_trans_t *trans)
{
    coap_server_t *server = NULL;
    int ret = 0;

    server = trans->server;
    ret = gnutls_init(&trans->session, GNUTLS_SERVER | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("Failed to initialise DTLS session");
        return -1;
    }
    ret = gnutls_credentials_set(trans->session, GNUTLS_CRD_CERTIFICATE, server->cred);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_deinit(trans->session);
        coap_log_error("Failed to assign credentials to DTLS session");
        return -1;
    }
    ret = gnutls_priority_set(trans->session, server->priority);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_deinit(trans->session);
        coap_log_error("Failed to assign priorities to DTLS session");
        return -1;
    }
    gnutls_transport_set_ptr(trans->session, trans);
    gnutls_transport_set_pull_function(trans->session, coap_server_trans_dtls_pull_func);
    gnutls_transport_set_pull_timeout_function(trans->session, coap_server_trans_dtls_pull_timeout_func);
    gnutls_transport_set_push_function(trans->session, coap_server_trans_dtls_push_func);
    gnutls_dtls_set_mtu(trans->session, COAP_SERVER_DTLS_MTU);
    gnutls_dtls_set_timeouts(trans->session, COAP_SERVER_DTLS_RETRANS_TIMEOUT, COAP_SERVER_DTLS_TOTAL_TIMEOUT);
#ifdef COAP_CLIENT_AUTH
    gnutls_certificate_server_set_request(trans->session, GNUTLS_CERT_REQUIRE);
#endif
    ret = coap_server_trans_dtls_handshake(trans);
    if (ret < 0)
    {
        gnutls_deinit(trans->session);
        coap_log_warn("Failed to complete DTLS handshake");
        return ret;
    }
#ifdef COAP_CLIENT_AUTH
    ret = coap_server_trans_dtls_verify_peer_cert(trans);
    if (ret < 0)
    {
        gnutls_deinit(trans->session);
        return ret;
    }
#endif
    return 0;
}

/**
 *  @brief Deinitialise the DTLS members of a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void coap_server_trans_dtls_destroy(coap_server_trans_t *trans)
{
    gnutls_bye(trans->session, GNUTLS_SHUT_WR);
    gnutls_deinit(trans->session);
}

#endif  /* COAP_DTLS_EN */

/****************************************************************************************************
 *                                        coap_server_trans                                         *
 ****************************************************************************************************/

/**
 *  @brief Deinitialise a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void coap_server_trans_destroy(coap_server_trans_t *trans)
{
    coap_log_debug("Destroyed transaction for address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
#ifdef COAP_DTLS_EN
    coap_server_trans_dtls_destroy(trans);
#endif
    coap_msg_destroy(&trans->resp);
    coap_msg_destroy(&trans->req);
    close(trans->timer_fd);
    memset(trans, 0, sizeof(coap_server_trans_t));
}

/**
 *  @brief Mark the last time the transaction structure was used
 *
 *  @param[out] trans Pointer to a transaction structure
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
    return ((coap_msg_get_ver(&trans->req) != 0)
         && (coap_msg_get_msg_id(&trans->req) == coap_msg_get_msg_id(msg)));
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
    return ((coap_msg_get_ver(&trans->resp) != 0)
         && (coap_msg_get_msg_id(&trans->resp) == coap_msg_get_msg_id(msg)));
}

/**
 *  @brief Clear the request message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void coap_server_trans_clear_req(coap_server_trans_t *trans)
{
    coap_msg_destroy(&trans->req);
}

/**
 *  @brief Clear the response message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void coap_server_trans_clear_resp(coap_server_trans_t *trans)
{
    coap_msg_destroy(&trans->resp);
}

/**
 *  @brief Set the request message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_set_req(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_reset(&trans->req);
    return coap_msg_copy(&trans->req, msg);
}

/**
 *  @brief Set the response message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_set_resp(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_reset(&trans->resp);
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
 *  @brief Start the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_start_timer(coap_server_trans_t *trans)
{
    struct itimerspec its = {{0}};
    int ret = 0;

    its.it_value = trans->timeout;
    ret = timerfd_settime(trans->timer_fd, 0, &its, NULL);
    if (ret < 0)
    {
        return -errno;
    }
    return 0;
}

/**
 *  @brief Stop the timer in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_stop_timer(coap_server_trans_t *trans)
{
    struct itimerspec its = {{0}};
    int ret = 0;

    ret = timerfd_settime(trans->timer_fd, 0, &its, NULL);
    if (ret < 0)
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
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
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
 *  @param[out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
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
 *  @retval <0 Error
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
 *  @brief Send a message to the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >0 Number of bytes sent
 *  @retval <0 Error
 */
static ssize_t coap_server_trans_send(coap_server_trans_t *trans, coap_msg_t *msg)
{
#ifndef COAP_DTLS_EN
    coap_server_t *server = NULL;
#endif
    ssize_t num = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};

    num = coap_msg_format(msg, buf, sizeof(buf));
    if (num < 0)
    {
        return num;
    }
#ifdef COAP_DTLS_EN
    errno = 0;
    num = gnutls_record_send(trans->session, buf, num);
    if (errno != 0)
    {
        return -errno;
    }
    if ((num == 0)
     || (num == GNUTLS_E_WARNING_ALERT_RECEIVED)
     || (num == GNUTLS_E_FATAL_ALERT_RECEIVED))
    {
        return -ECONNRESET;
    }
    if (num == GNUTLS_E_AGAIN)
    {
        return -EAGAIN;
    }
    if (num < 0)
    {
        return -1;
    }
#else
    server = trans->server;
    num = sendto(server->sd, buf, num, 0, (struct sockaddr *)&trans->client_sin, trans->client_sin_len);
    if (num < 0)
    {
        return -errno;
    }
#endif
    coap_server_trans_touch(trans);
    coap_log_debug("Sent to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
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
 *  @param[in,out] trans Pointer to a transaction structure
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
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes received or error code
 *  @retval >0 Number of bytes received
 *  @retval <0 Error
 */
static ssize_t coap_server_trans_recv(coap_server_trans_t *trans, coap_msg_t *msg)
{
#ifndef COAP_DTLS_EN
    coap_ipv_sockaddr_in_t client_sin = {0};
    coap_server_t *server = NULL;
    socklen_t client_sin_len = 0;
#endif
    ssize_t num = 0;
    ssize_t ret = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};

#ifdef COAP_DTLS_EN
    errno = 0;
    num = gnutls_record_recv(trans->session, buf, sizeof(buf));
    if (errno != 0)
    {
        return -errno;
    }
    if ((num == 0)
     || (num == GNUTLS_E_WARNING_ALERT_RECEIVED)
     || (num == GNUTLS_E_FATAL_ALERT_RECEIVED))
    {
        return -ECONNRESET;
    }
    if (num == GNUTLS_E_AGAIN)
    {
        return -EAGAIN;
    }
    if (num < 0)
    {
        return -1;
    }
#else
    server = trans->server;
    client_sin_len = sizeof(client_sin);
    num = recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *)&client_sin, &client_sin_len);
    if (num < 0)
    {
        return -errno;
    }
    if ((client_sin_len != trans->client_sin_len)
     || (memcmp(&client_sin, &trans->client_sin, client_sin_len) != 0))
    {
        return -EINVAL;
    }
    num = recvfrom(server->sd, buf, num, 0, (struct sockaddr *)&client_sin, &client_sin_len);
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
            coap_server_trans_handle_format_error(trans, buf, num);
        }
        return ret;
    }
    coap_server_trans_touch(trans);
    coap_log_debug("Received from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    return num;
}

/**
 *  @brief Reject a received confirmable message
 *
 *  Send a reset message to the client.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_reject_con(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_t rej = {0};
    ssize_t num = 0;
    int ret = 0;

    coap_log_info("Rejecting confirmable message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
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
    coap_log_info("Rejecting non-confirmable message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    return 0;
}

/**
 *  @brief Reject a received acknowledgement message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int coap_server_trans_reject_ack(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_log_info("Rejecting acknowledgement message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    return 0;
}

/**
 *  @brief Reject a received reset message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int coap_server_trans_reject_reset(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_log_info("Rejecting reset message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    return 0;
}

/**
 *  @brief Reject a received message
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_reject(coap_server_trans_t *trans, coap_msg_t *msg)
{
    if (coap_msg_get_type(msg) == COAP_MSG_CON)
    {
        return coap_server_trans_reject_con(trans, msg);
    }
    else if (coap_msg_get_type(msg) == COAP_MSG_NON)
    {
        return coap_server_trans_reject_non(trans, msg);
    }
    else if (coap_msg_get_type(msg) == COAP_MSG_ACK)
    {
        return coap_server_trans_reject_ack(trans, msg);
    }
    else if (coap_msg_get_type(msg) == COAP_MSG_RST)
    {
        return coap_server_trans_reject_reset(trans, msg);
    }
    return 0;  /* should never arrive here */
}

/**
 *  @brief Reject a request message containing a bad option
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *  @param[in] op_num Option number of the bad option
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_reject_bad_option(coap_server_trans_t *trans, coap_msg_t *msg, unsigned op_num)
{
    coap_msg_t rej = {0};
    char payload[COAP_SERVER_DIAG_PAYLOAD_LEN] = {0};
    ssize_t num = 0;
    int ret = 0;

    coap_log_info("Found bad option number %u in message from address %s and port %u", op_num, trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    if (coap_msg_get_type(msg) == COAP_MSG_NON)
    {
        return coap_server_trans_reject_non(trans, msg);
    }
    /* confirmable request containing a bad option */
    /* send a piggy-backed response containing 4.02 Bad Option */
    coap_log_info("Sending 'Bad Option' response to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    coap_msg_create(&rej);
    ret = coap_msg_set_type(&rej, COAP_MSG_ACK);
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    ret = coap_msg_set_code(&rej, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
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
    ret = coap_msg_set_token(&rej, coap_msg_get_token(msg), coap_msg_get_token_len(msg));
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    snprintf(payload, sizeof(payload), "Bad option number: %u", op_num);
    ret = coap_msg_set_payload(&rej, payload, strlen(payload));
    if (ret < 0)
    {
        coap_msg_destroy(&rej);
        return ret;
    }
    num = coap_server_trans_send(trans, &rej);
    if (num < 0)
    {
        coap_msg_destroy(&rej);
        return num;
    }
    coap_msg_destroy(&rej);
    return 0;
}

/**
 *  @brief Send an acknowledgement message to the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_send_ack(coap_server_trans_t *trans, coap_msg_t *msg)
{
    coap_msg_t ack = {0};
    ssize_t num = 0;
    int ret = 0;

    coap_log_info("Acknowledging confirmable message from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
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
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_handle_ack_timeout(coap_server_trans_t *trans)
{
    ssize_t num = 0;
    int ret = 0;

    coap_log_debug("Transaction expired for address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    ret = coap_server_trans_update_ack_timer(trans);
    if (ret == 0)
    {
        coap_log_debug("Retransmitting to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
        num = coap_server_trans_send(trans, &trans->resp);
        if (num < 0)
        {
            return num;
        }
    }
    else if (ret == -ETIMEDOUT)
    {
        coap_log_debug("Stopped retransmitting to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
        coap_log_info("No acknowledgement received from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
        coap_server_trans_destroy(trans);
        ret = 0;
    }
    return ret;
}

/**
 *  @brief Initialise a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a socket structure
 *  @param[in] client_sin_len Length of the socket structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_trans_create(coap_server_trans_t *trans, coap_server_t *server, coap_ipv_sockaddr_in_t *client_sin, socklen_t client_sin_len)
{
    const char *p = NULL;
#ifdef COAP_DTLS_EN
    int ret = 0;
#endif

    memset(trans, 0, sizeof(coap_server_trans_t));
    trans->active = 1;
    coap_server_trans_touch(trans);
    trans->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (trans->timer_fd < 0)
    {
        memset(trans, 0, sizeof(coap_server_trans_t));
        return -errno;
    }
    memcpy(&trans->client_sin, client_sin, client_sin_len);
    trans->client_sin_len = client_sin_len;
    p = inet_ntop(COAP_IPV_AF_INET, &client_sin->COAP_IPV_SIN_ADDR, trans->client_addr, sizeof(trans->client_addr));
    if (p == NULL)
    {
        close(trans->timer_fd);
        memset(trans, 0, sizeof(coap_server_trans_t));
        return -errno;
    }
    coap_msg_create(&trans->req);
    coap_msg_create(&trans->resp);
    trans->server = server;
#ifdef COAP_DTLS_EN
    ret = coap_server_trans_dtls_create(trans);
    if (ret < 0)
    {
        coap_msg_destroy(&trans->resp);
        coap_msg_destroy(&trans->req);
        close(trans->timer_fd);
        memset(trans, 0, sizeof(coap_server_trans_t));
        return ret;
    }
#endif
    coap_log_debug("Created transaction for address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    return 0;
}

#ifdef COAP_DTLS_EN

/****************************************************************************************************
 *                                         coap_server_dtls                                         *
 ****************************************************************************************************/

/**
 *  @brief Initialise the DTLS members of a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] key_file_name String containing the DTLS key file name
 *  @param[in] cert_file_name String containing the DTLS certificate file name
 *  @param[in] trust_file_name String containing the DTLS trust file name
 *  @param[in] crl_file_name String containing the DTLS certificate revocation list file name
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -1 Error
 */
static int coap_server_dtls_create(coap_server_t *server,
                                   const char *key_file_name,
                                   const char *cert_file_name,
                                   const char *trust_file_name,
                                   const char *crl_file_name)
{
    int ret = 0;

    ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("Failed to initialise DTLS library");
        return -1;
    }
    ret = gnutls_certificate_allocate_credentials(&server->cred);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_global_deinit();
        coap_log_error("Failed to allocate DTLS credentials");
        return -1;
    }
    if ((trust_file_name != NULL) && (strlen(trust_file_name) != 0))
    {
        ret = gnutls_certificate_set_x509_trust_file(server->cred, trust_file_name, GNUTLS_X509_FMT_PEM);
        if (ret == 0)
        {
            gnutls_certificate_free_credentials(server->cred);
            gnutls_global_deinit();
            coap_log_error("Failed to assign X.509 trust file to DTLS credentials");
            return -1;
        }
    }
    if ((crl_file_name != NULL) && (strlen(crl_file_name) != 0))
    {
        ret = gnutls_certificate_set_x509_crl_file(server->cred, crl_file_name, GNUTLS_X509_FMT_PEM);
        if (ret < 0)
        {
            gnutls_certificate_free_credentials(server->cred);
            gnutls_global_deinit();
            coap_log_error("Failed to assign X.509 certificate revocation list to DTLS credentials");
            return -1;
        }
    }
    ret = gnutls_certificate_set_x509_key_file(server->cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_certificate_free_credentials(server->cred);
        gnutls_global_deinit();
        coap_log_error("Failed to assign X.509 certificate file and key file to DTLS credentials");
        return -1;
    }
    ret = gnutls_dh_params_init(&server->dh_params);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_certificate_free_credentials(server->cred);
        gnutls_global_deinit();
        coap_log_error("Failed to initialise Diffie-Hellman parameters for DTLS credentials");
        return -1;
    }
    ret = gnutls_dh_params_generate2(server->dh_params, COAP_SERVER_DTLS_NUM_DH_BITS);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_dh_params_deinit(server->dh_params);
        gnutls_certificate_free_credentials(server->cred);
        gnutls_global_deinit();
        coap_log_error("Failed to generate Diffie-Hellman parameters for DTLS credentials");
        return -1;
    }
    gnutls_certificate_set_dh_params(server->cred, server->dh_params);
    ret = gnutls_priority_init(&server->priority, COAP_SERVER_DTLS_PRIORITIES, NULL);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_dh_params_deinit(server->dh_params);
        gnutls_certificate_free_credentials(server->cred);
        gnutls_global_deinit();
        coap_log_error("Failed to initialise priorities for DTLS session");
        return -1;
    }
    return 0;
}

/**
 *  @brief Deinitialise the DTLS members of a server structure
 *
 *  @param[in,out] trans Pointer to a server structure
 */
static void coap_server_dtls_destroy(coap_server_t *server)
{
    gnutls_priority_deinit(server->priority);
    gnutls_certificate_free_credentials(server->cred);
    gnutls_dh_params_deinit(server->dh_params);
    gnutls_global_deinit();
}

#endif  /* COAP_DTLS_EN */

/****************************************************************************************************
 *                                           coap_server                                            *
 ****************************************************************************************************/

#ifdef COAP_DTLS_EN
int coap_server_create(coap_server_t *server,
                       int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *),
                       const char *host,
                       const char *port,
                       const char *key_file_name,
                       const char *cert_file_name,
                       const char *trust_file_name,
                       const char *crl_file_name)
#else
int coap_server_create(coap_server_t *server,
                       int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *),
                       const char *host,
                       const char *port)
#endif
{
    unsigned char msg_id[2] = {0};
    struct addrinfo hints = {0};
    struct addrinfo *list = NULL;
    struct addrinfo *node = NULL;
    int opt_val = 0;
    int flags = 0;
    int ret = 0;

    if ((server == NULL) || (host == NULL) || (port == NULL))
    {
        return -EINVAL;
    }
    memset(server, 0, sizeof(coap_server_t));
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
            server->sd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
            if (server->sd < 0)
            {
                continue;
            }
            opt_val = 1;
            ret = setsockopt(server->sd, SOL_SOCKET, SO_REUSEADDR, &opt_val, (socklen_t)sizeof(opt_val));
            if (ret < 0)
            {
                close(server->sd);
                freeaddrinfo(list);
                return -EBUSY;
            }
            ret = bind(server->sd, node->ai_addr, node->ai_addrlen);
            if (ret < 0)
            {
                close(server->sd);
                continue;
            }
            break;
        }
    }
    freeaddrinfo(list);
    if (node == NULL)
    {
        memset(server, 0, sizeof(coap_server_t));
        return -EBUSY;
    }
    flags = fcntl(server->sd, F_GETFL, 0);
    if (flags < 0)
    {
        close(server->sd);
        memset(server, 0, sizeof(coap_server_t));
        return -errno;
    }
    ret = fcntl(server->sd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
    {
        close(server->sd);
        memset(server, 0, sizeof(coap_server_t));
        return -errno;
    }
    coap_msg_gen_rand_str((char *)msg_id, sizeof(msg_id));
    server->msg_id = (((unsigned)msg_id[1]) << 8) | (unsigned)msg_id[0];
    coap_server_path_list_create(&server->sep_list);
    server->handle = handle;
#ifdef COAP_DTLS_EN
    ret = coap_server_dtls_create(server, key_file_name, cert_file_name, trust_file_name, crl_file_name);
    if (ret < 0)
    {
        coap_server_path_list_destroy(&server->sep_list);
        close(server->sd);
        memset(server, 0, sizeof(coap_server_t));
        return ret;
    }
#endif
    coap_log_notice("Listening on address %s and port %s", host, port);
    return 0;
}

void coap_server_destroy(coap_server_t *server)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_NUM_TRANS; i++)
    {
        trans = &server->trans[i];
        if (trans->active)
        {
            coap_server_trans_destroy(trans);
        }
    }
#ifdef COAP_DTLS_EN
    coap_server_dtls_destroy(server);
#endif
    coap_server_path_list_destroy(&server->sep_list);
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
static unsigned coap_server_check_options(coap_msg_t *msg)
{
#ifdef COAP_PROXY
    return coap_msg_check_unsafe_ops(msg);
#else  /* !COAP_PROXY */
    return coap_msg_check_critical_ops(msg);
#endif  /* COAP_PROXY */
}

/**
 *  @brief Search for a transaction structure in a server structure that matches an endpoint
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a socket structure
 *  @param[in] client_sin_len Length of the socket structure
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No matching transaction structure found
 */
static coap_server_trans_t *coap_server_find_trans(coap_server_t *server, coap_ipv_sockaddr_in_t *client_sin, socklen_t client_sin_len)
{
    coap_server_trans_t *trans = NULL;
    unsigned i = 0;

    for (i = 0; i < COAP_SERVER_NUM_TRANS; i++)
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

    for (i = 0; i < COAP_SERVER_NUM_TRANS; i++)
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
 *  @brief Search for the oldest transaction structure in a server structure
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

    for (i = 0; i < COAP_SERVER_NUM_TRANS; i++)
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
 *  @retval <0 Error
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
        for (i = 0; i < COAP_SERVER_NUM_TRANS; i++)
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
        if (ret < 0)
        {
            return -errno;
        }
        if (FD_ISSET(server->sd, &read_fds))
        {
            return 0;
        }
        for (i = 0; i < COAP_SERVER_NUM_TRANS; i++)
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
 *  @param[out] client_sin Pointer to a socket structure
 *  @param[out] client_sin_len Length of the socket structure
 *
 *  Get the address and port number of the client.
 *  Do not read the received data.
 *
 *  @returns Number of bytes received or error code
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_accept(coap_server_t *server, coap_ipv_sockaddr_in_t *client_sin, socklen_t *client_sin_len)
{
    ssize_t num = 0;
    char buf[COAP_MSG_MAX_BUF_LEN] = {0};

    *client_sin_len = sizeof(coap_ipv_sockaddr_in_t);
    num = recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *)client_sin, client_sin_len);
    if (num < 0)
    {
        return -errno;
    }
    return 0;
}

int coap_server_add_sep_resp_uri_path(coap_server_t *server, const char *str)
{
    return coap_server_path_list_add(&server->sep_list, str);
}

/**
 *  @brief Determine whether a request warrants a piggy-backed
 *         response or a separate response
 *
 *  This function makes the decision on whether to send a separate
 *  response or a piggy-backed response by searching for the URI
 *  path taken from the request message structure in a user supplied
 *  URI path list. The idea being that some resources will consistently
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
    coap_msg_op_t *op = NULL;
    size_t val_len = 0;
    size_t add = 0;
    size_t len = 0;
    char val_buf[COAP_MSG_OP_URI_PATH_MAX_LEN] = {0};
    char buf[COAP_MSG_OP_URI_PATH_MAX_LEN] = {0};
    char *val = NULL;
    char *p = NULL;
    int match = 0;

    p = buf;
    len = sizeof(buf) - 1;
    op = coap_msg_get_first_op(msg);
    while (op != NULL)
    {
        if (coap_msg_op_get_num(op) == COAP_MSG_OP_URI_PATH_NUM)
        {
            strncpy(p, "/", len);
            add = (1 < len) ? 1 : len;
            p += add;
            len -= add;

            val = coap_msg_op_get_val(op);
            val_len = coap_msg_op_get_len(op);
            if (val_len > sizeof(val_buf) - 1)
                val_len = sizeof(val_buf) - 1;
            memcpy(val_buf, val, val_len);
            strncpy(p, val_buf, len);
            add = (val_len < len) ? val_len : len;
            p += add;
            len -= add;
        }
        op = coap_msg_op_get_next(op);
    }
    if (p == buf)
    {
        buf[0] = '/';
    }
    match = coap_server_path_list_match(&server->sep_list, buf);
    return match ? COAP_SERVER_SEPARATE : COAP_SERVER_PIGGYBACKED;
}

/**
 *  @brief Receive a request from the client and send the response
 *
 *  @param[in,out] server Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int coap_server_exchange(coap_server_t *server)
{
    coap_ipv_sockaddr_in_t client_sin = {0};
    coap_server_trans_t *trans = NULL;
    coap_msg_t recv_msg = {0};
    coap_msg_t send_msg = {0};
    socklen_t client_sin_len = 0;
    unsigned op_num = 0;
    unsigned msg_id = 0;
    ssize_t num = 0;
    int resp_type = 0;
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
#ifdef COAP_DTLS_EN
        /* if DTLS is enabled then coap_server_trans_create has consumed */
        /* the received data as part of the handshake, we need to wait for */
        /* more data to arrive and identify the sender */
        return 0;
#endif
    }

    /* receive message */
    coap_msg_create(&recv_msg);
    num = coap_server_trans_recv(trans, &recv_msg);
    if (num < 0)
    {
        coap_msg_destroy(&recv_msg);
        coap_server_trans_destroy(trans);
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
            coap_log_info("Received duplicate confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
            ret = coap_server_trans_send_ack(trans, &recv_msg);
            coap_msg_destroy(&recv_msg);
            if (ret < 0)
            {
                coap_server_trans_destroy(trans);
                return ret;
            }
            return 0;
        }
        else if (coap_msg_get_type(&recv_msg) == COAP_MSG_NON)
        {
            /* message deduplication */
            /* do not acknowledge the (non-confirmable) request again */
            /* do not send the response again */
            coap_log_info("Received duplicate non-confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
            coap_msg_destroy(&recv_msg);
            return 0;
        }
    }

    /* check for an ack for a previous response */
    if (coap_server_trans_match_resp(trans, &recv_msg))
    {
        if (coap_msg_get_type(&recv_msg) == COAP_MSG_ACK)
        {
            /* the server must stop retransmitting its response */
            /* on any matching acknowledgement or reset message */
            coap_log_info("Received acknowledgement from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
            ret = coap_server_trans_stop_ack_timer(trans);
            coap_msg_destroy(&recv_msg);
            if (ret < 0)
            {
                coap_server_trans_destroy(trans);
                return ret;
            }
            return 0;
        }
        else if (coap_msg_get_type(&recv_msg) == COAP_MSG_RST)
        {
            /* the server must stop retransmitting its response */
            /* on any matching acknowledgement or reset message */
            coap_log_info("Received reset from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
            ret = coap_server_trans_stop_ack_timer(trans);
            coap_msg_destroy(&recv_msg);
            if (ret < 0)
            {
                coap_server_trans_destroy(trans);
                return ret;
            }
            return 0;
        }
    }

    /* check for a valid request */
    if ((coap_msg_get_type(&recv_msg) == COAP_MSG_ACK)
     || (coap_msg_get_type(&recv_msg) == COAP_MSG_RST)
     || (coap_msg_get_code_class(&recv_msg) != COAP_MSG_REQ))
    {
        coap_server_trans_reject(trans, &recv_msg);
        coap_msg_destroy(&recv_msg);
        coap_server_trans_destroy(trans);
        return -EBADMSG;
    }

    if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
    {
        coap_log_info("Received confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    }
    else if (coap_msg_get_type(&recv_msg) == COAP_MSG_NON)
    {
        coap_log_info("Received non-confirmable request from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    }

    /* check options */
    op_num = coap_server_check_options(&recv_msg);
    if (op_num != 0)
    {
        ret = coap_server_trans_reject_bad_option(trans, &recv_msg, op_num);
        coap_msg_destroy(&recv_msg);
        coap_server_trans_destroy(trans);
        return ret;
    }

    /* clear details of the previous request/response */
    coap_server_trans_clear_req(trans);
    coap_server_trans_clear_resp(trans);

    /* determine response type */
    if (coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
    {
        resp_type = coap_server_get_resp_type(server, &recv_msg);
        if (resp_type == COAP_SERVER_SEPARATE)
        {
            coap_log_info("Request URI path requires a separate response to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
        }
        else
        {
            coap_log_info("Request URI path requires a piggy-backed response to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
        }
    }

    /* send an acknowledgement if necessary */
    if ((coap_msg_get_type(&recv_msg) == COAP_MSG_CON)
     && (resp_type == COAP_SERVER_SEPARATE))
    {
        ret = coap_server_trans_send_ack(trans, &recv_msg);
        if (ret < 0)
        {
            coap_server_trans_destroy(trans);
            coap_msg_destroy(&recv_msg);
            return ret;
        }
    }

    /* generate response */
    coap_log_info("Responding to address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
    coap_msg_create(&send_msg);
    ret = (*server->handle)(server, &recv_msg, &send_msg);
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_server_trans_destroy(trans);
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
        coap_server_trans_destroy(trans);
        coap_msg_destroy(&recv_msg);
        return ret;
    }
    /* copy the token from the request to the response */
    ret = coap_msg_set_token(&send_msg, coap_msg_get_token(&recv_msg), coap_msg_get_token_len(&recv_msg));
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_server_trans_destroy(trans);
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
        coap_server_trans_destroy(trans);
        coap_msg_destroy(&recv_msg);
        return ret;
    }

    /* send response */
    num = coap_server_trans_send(trans, &send_msg);
    if (num < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_server_trans_destroy(trans);
        coap_msg_destroy(&recv_msg);
        return num;
    }

    /* record the request in the transaction structure */
    ret = coap_server_trans_set_req(trans, &recv_msg);
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_server_trans_destroy(trans);
        coap_msg_destroy(&recv_msg);
        return ret;
    }

    /* record the response in the transaction structure */
    ret = coap_server_trans_set_resp(trans, &send_msg);
    if (ret < 0)
    {
        coap_msg_destroy(&send_msg);
        coap_server_trans_destroy(trans);
        coap_msg_destroy(&recv_msg);
        return ret;
    }

    /* start the acknowledgement timer if an acknowledgement is expected */
    if (coap_msg_get_type(&send_msg) == COAP_MSG_CON)
    {
        coap_log_info("Expecting acknowledgement from address %s and port %u", trans->client_addr, ntohs(trans->client_sin.COAP_IPV_SIN_PORT));
        ret = coap_server_trans_start_ack_timer(trans);
        if (ret < 0)
        {
            coap_msg_destroy(&send_msg);
            coap_server_trans_destroy(trans);
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
            return ret;
        }
        ret = coap_server_exchange(server);
        if (ret < 0)
        {
            if ((ret == -ETIMEDOUT) || (ret == -ECONNRESET))
            {
                coap_log_notice("%s", strerror(-ret));
            }
            else if (ret != -1)  /* a return value of -1 indicates a DTLS error */
            {
                return ret;
            }
        }
    }
    return 0;
}
