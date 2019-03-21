/*
 * Copyright (c) 2010 Keith Cullen.
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
 *  @file tls_sock.c
 *
 *  @brief Source file for the FreeCoAP TLS/IPv6 socket library
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gnutls/x509.h>
#include "tls_sock.h"
#include "coap_log.h"

static int tls_sock_open_(tls_sock_t *s, const char *common_name, int timeout);
static int tls_sock_handshake(tls_sock_t *s);
static int tls_sock_verify_peer_cert(tls_sock_t *s, const char *common_name);

static int set_non_blocking(int sd)
{
    int flags = 0;
    int ret = 0;

    flags = fcntl(sd, F_GETFL, 0);
    if (flags == -1)
    {
        return -1;
    }
    ret = fcntl(sd, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1)
    {
        return -1;
    }
    return 0;
}

int tls_sock_open_from_sockaddr_in(tls_sock_t *s, tls_client_t *client, const char *common_name, int timeout, sock_sockaddr_in_t *sin)
{
    int ret = 0;

    memset(s, 0, sizeof(tls_sock_t));

    if (timeout < 0)
    {
        return SOCK_ARG_ERROR;
    }

    s->type = TLS_SOCK_CLIENT;
    s->u.client = client;

    /* open a socket */
    s->sd = socket(SOCK_PF_INET, SOCK_STREAM, 0);
    if (s->sd == -1)
    {
        return SOCK_OPEN_ERROR;
    }

    memcpy(&s->sin, sin, sizeof(sock_sockaddr_in_t));

    /* connect to server */
    ret = connect(s->sd, (struct sockaddr *)&s->sin, sizeof(s->sin));
    if (ret < 0)
    {
        close(s->sd);
        return SOCK_CONNECT_ERROR;
    }

    return tls_sock_open_(s, common_name, timeout);
}

int tls_sock_open(tls_sock_t *s, tls_client_t *client, const char *host, const char *port, const char *common_name, int timeout)
{
    struct addrinfo hints = {0};
    struct addrinfo *list = NULL;
    struct addrinfo *node = NULL;
    int ret = 0;

    memset(s, 0, sizeof(tls_sock_t));

    if (timeout < 0)
    {
        return SOCK_ARG_ERROR;
    }

    /* resolve host and port */
    /* (currently only checks the first value returned) */
    hints.ai_flags = 0;
    hints.ai_family = SOCK_AF_INET;   /* preferred socket domain */
    hints.ai_socktype = SOCK_STREAM;  /* preferred socket type */
    hints.ai_protocol = 0;            /* preferred protocol (3rd argument to socket()) - 0 specifies that any protocol will do */
    hints.ai_addrlen = 0;             /* must be 0 */
    hints.ai_addr = NULL;             /* must be NULL */
    hints.ai_canonname = NULL;        /* must be NULL */
    hints.ai_next = NULL;             /* must be NULL */
    ret = getaddrinfo(host, port, &hints, &list);
    if (ret < 0)
    {
        return SOCK_ADDR_ERROR;
    }
    ret = SOCK_CONNECT_ERROR;  /* default error */
    node = list;
    while (node != NULL)
    {
        if ((node->ai_family == SOCK_AF_INET) && (node->ai_socktype == SOCK_STREAM))
        {
            ret = tls_sock_open_from_sockaddr_in(s, client, common_name, timeout, (sock_sockaddr_in_t *)node->ai_addr);
            if ((ret == SOCK_OK) || (ret != SOCK_CONNECT_ERROR))
            {
                break;
            }
        }
        node = node->ai_next;
    }
    freeaddrinfo(list);
    return ret;
}

int tls_sock_open_(tls_sock_t *s, const char *common_name, int timeout)
{
    gnutls_datum_t data = {0};
    char addr[SOCK_INET_ADDRSTRLEN] = {0};
    int ret = 0;

    /* initialise timeout value */
    s->timeout = timeout;

    /* set non-blocking status */
    ret = set_non_blocking(s->sd);
    if (ret < 0)
    {
        close(s->sd);
        return SOCK_TLS_CONFIG_ERROR;
    }

    /* initialise tls session */
    ret = gnutls_init(&s->session, s->type);
    if (ret != GNUTLS_E_SUCCESS)
    {
        close(s->sd);
        return SOCK_TLS_CONFIG_ERROR;
    }
    ret = gnutls_priority_set(s->session, tls_get_priority_cache());
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_deinit(s->session);
        close(s->sd);
        return SOCK_TLS_CONFIG_ERROR;
    }

    if (s->type == TLS_SOCK_CLIENT)  /* attempt to resume cached client session */
    {
        ret = gnutls_credentials_set(s->session, GNUTLS_CRD_CERTIFICATE, tls_client_get_cred(s->u.client));
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_deinit(s->session);
            close(s->sd);
            return SOCK_TLS_CONFIG_ERROR;
        }

        tls_sock_get_addr_string_(addr, sizeof(addr), s->sin.SOCK_SIN_ADDR);
        data = tls_client_get(s->u.client, addr);
        if (data.size != 0)
        {
            ret = gnutls_session_set_data(s->session, data.data, data.size);
            if (ret != GNUTLS_E_SUCCESS)
            {
                gnutls_deinit(s->session);
                close(s->sd);
                return SOCK_TLS_CACHE_ERROR;
            }
        }
    }
    else if (s->type == TLS_SOCK_SERVER)  /* initialise the server cache */
    {
        ret = gnutls_credentials_set(s->session, GNUTLS_CRD_CERTIFICATE, tls_server_get_cred(s->u.server));
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_deinit(s->session);
            close(s->sd);
            return SOCK_TLS_CONFIG_ERROR;
        }

        gnutls_db_set_ptr(s->session, s->u.server);
        gnutls_db_set_store_function(s->session, tls_server_set);
        gnutls_db_set_retrieve_function(s->session, tls_server_get);
        gnutls_db_set_remove_function(s->session, tls_server_delete);

#ifdef TLS_CLIENT_AUTH
        /* request client authentication */
        gnutls_certificate_server_set_request(s->session, GNUTLS_CERT_REQUIRE);
#endif
    }

    gnutls_transport_set_ptr(s->session, (gnutls_transport_ptr_t)(unsigned long)(s->sd));

    /* tls handshake */
    ret = tls_sock_handshake(s);
    if (ret != SOCK_OK)
    {
        gnutls_deinit(s->session);
        close(s->sd);
        return ret;
    }

    if (s->type == TLS_SOCK_CLIENT)
    {
        /* verify server's certificate */
        ret = tls_sock_verify_peer_cert(s, common_name);
        if (ret != SOCK_OK)
        {
            gnutls_bye(s->session, GNUTLS_SHUT_RDWR);
            gnutls_deinit(s->session);
            close(s->sd);
            return ret;
        }
    }
#ifdef TLS_CLIENT_AUTH
    else if (s->type == TLS_SOCK_SERVER)
    {
        /* verify client's certificate */
        ret = tls_sock_verify_peer_cert(s, common_name);
        if (ret != SOCK_OK)
        {
            gnutls_bye(s->session, GNUTLS_SHUT_RDWR);
            gnutls_deinit(s->session);
            close(s->sd);
            return ret;
        }
    }
#endif

    return SOCK_OK;
}

/* must be able to handle a rehandshake */
int tls_sock_handshake(tls_sock_t *s)
{
    struct timeval tv = {0};
    fd_set readfds = {{0}};
    fd_set errfds = {{0}};
    int ret = 0;

    /* tls handshake */
    tv.tv_sec = s->timeout;
    tv.tv_usec = 0;
    while (1)
    {
        ret = gnutls_handshake(s->session);
        if (ret == GNUTLS_E_SUCCESS)
        {
            return SOCK_OK;
        }
        if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
        {
            return SOCK_TLS_WARNING_ALERT;
        }
        if (ret == GNUTLS_E_INTERRUPTED)
        {
            return SOCK_INTR;
        }
        if (ret != GNUTLS_E_AGAIN)
        {
            return SOCK_TLS_HANDSHAKE_ERROR;
        }
        FD_ZERO(&readfds);
        FD_SET(s->sd, &readfds);
        FD_ZERO(&errfds);
        FD_SET(s->sd, &errfds);
        ret = select(s->sd + 1, &readfds, NULL, &errfds, &tv);
        if (ret == 0)
        {
            return SOCK_TIMEOUT;
        }
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                return SOCK_INTR;
            }
            return SOCK_TLS_HANDSHAKE_ERROR;
        }
    }
}

int tls_sock_verify_peer_cert(tls_sock_t *s, const char *common_name)
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

    ret = gnutls_certificate_verify_peers2(s->session, &status);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("The peer certificate was not verified");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    if (status & GNUTLS_CERT_INVALID)
    {
        coap_log_error("The peer certificate is not trusted");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    {
        coap_log_error("No issuer found for the peer certificate");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    if (status & GNUTLS_CERT_SIGNER_NOT_CA)
    {
        coap_log_error("The issuer for the peer certificate is not a certificate authority");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    if (status & GNUTLS_CERT_REVOKED)
    {
        coap_log_error("The peer certificate has been revoked");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    cert_type = gnutls_certificate_type_get(s->session);
    if (cert_type != GNUTLS_CRT_X509)
    {
        coap_log_error("The peer certificate is not an X509 certificate");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    ret = gnutls_x509_crt_init(&cert);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("Unable to initialise gnutls_x509_crt_t object");
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    cert_list = gnutls_certificate_get_peers(s->session, &cert_list_size);
    if (cert_list == NULL)
    {
        coap_log_error("No peer certificate found");
        gnutls_x509_crt_deinit(cert);
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    /* We only check the first (leaf) certificate in the chain */
    ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
    if (ret != GNUTLS_E_SUCCESS)
    {
        coap_log_error("Unable to parse certificate");
        gnutls_x509_crt_deinit(cert);
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    current_time = time(NULL);
    expiration_time = gnutls_x509_crt_get_expiration_time(cert);
    if ((expiration_time == -1) || (expiration_time < current_time))
    {
        coap_log_error("The peer certificate has expired");
        gnutls_x509_crt_deinit(cert);
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    activation_time = gnutls_x509_crt_get_activation_time(cert);
    if ((activation_time == -1) || (activation_time > current_time))
    {
        coap_log_error("The peer certificate is not yet activated");
        gnutls_x509_crt_deinit(cert);
        return SOCK_PEER_CERT_VERIFY_ERROR;
    }
    if (common_name != NULL)
    {
        ret = gnutls_x509_crt_check_hostname(cert, common_name);
        if (ret == 0)
        {
            coap_log_error("The peer certificate's owner does not match: '%s'", common_name);
            gnutls_x509_crt_deinit(cert);
            return SOCK_PEER_CERT_VERIFY_ERROR;
        }
    }
    coap_log_info("Peer certificate validated");
    gnutls_x509_crt_deinit(cert);
    return SOCK_OK;
}

/* send and receive close notifiy */
void tls_sock_close(tls_sock_t *s)
{
    struct timeval tv = {0};
    gnutls_datum_t datum = {0};
    fd_set readfds = {{0}};
    fd_set errfds = {{0}};
    char addr[SOCK_INET_ADDRSTRLEN] = {0};
    int success = 0;
    int ret = 0;

    if (s->type == TLS_SOCK_CLIENT)
    {
        gnutls_session_get_data2(s->session, &datum);
    }

    tv.tv_sec = s->timeout;
    tv.tv_usec = 0;
    while (1)
    {
        /* send and receive close notify alerts */
        ret = gnutls_bye(s->session, GNUTLS_SHUT_RDWR);
        if (ret == GNUTLS_E_SUCCESS)
        {
            success = 1;
            break;
        }
        if (ret == GNUTLS_E_INTERRUPTED)
        {
            break;
        }
        if (ret != GNUTLS_E_AGAIN)
        {
            break;
        }
        FD_ZERO(&readfds);
        FD_SET(s->sd, &readfds);
        FD_ZERO(&errfds);
        FD_SET(s->sd, &errfds);
        ret = select(s->sd + 1, &readfds, NULL, &errfds, &tv);
        if (ret <= 0)
        {
            break;
        }
    }
    if (s->type == TLS_SOCK_CLIENT)
    {
        if (datum.size > 0)
        {
            if (success)  /* only cache session if both sides sent close notify alerts */
            {
                tls_sock_get_addr_string_(addr, sizeof(addr), s->sin.SOCK_SIN_ADDR);
                tls_client_set(s->u.client, addr, datum);
            }
            gnutls_free(datum.data);
        }
    }
    sleep(1);
    gnutls_deinit(s->session);
    close(s->sd);
    memset(s, 0, sizeof(tls_sock_t));
}

int tls_sock_rehandshake(tls_sock_t *s)
{
    gnutls_alert_description_t alert = {0};
    int ret = 0;

    if (s->type == TLS_SOCK_SERVER)
    {
        /* if this funcion is called by a client it will return -50, 'The request is invalid.' */
        ret = gnutls_rehandshake(s->session);
        if (ret == GNUTLS_E_SUCCESS)
        {
            /* tls handshake */
            ret = tls_sock_handshake(s);
            if (ret == SOCK_OK)
            {
                return SOCK_OK;
            }
            if (ret == SOCK_INTR)
            {
                return SOCK_INTR;
            }
            if (ret == SOCK_TLS_WARNING_ALERT)
            {
                alert = gnutls_alert_get(s->session);
                if (alert == GNUTLS_A_NO_RENEGOTIATION)  /* remote host respectfully refused */
                {
                    return SOCK_TLS_REHANDSHAKE_REFUSED_ERROR;
                }
                /* we don't know what the warning alert is telling us so report an error */
            }
        }
    }
    return SOCK_TLS_HANDSHAKE_ERROR;
}

void tls_sock_get_addr_string_(char *out, size_t out_len, sock_in_addr_t sin_addr)
{
    inet_ntop(SOCK_AF_INET, &sin_addr, out, out_len);
}

/*  return { > 0, number of bytes read
 *         {   0, connection closed
 *         { < 0, error
 */
ssize_t tls_sock_read(tls_sock_t *s, void *buf, size_t len)
{
    struct timeval tv = {0};
    fd_set readfds = {{0}};
    fd_set errfds = {{0}};
    ssize_t num = 0;
    int ret = 0;

    tv.tv_sec = s->timeout;
    tv.tv_usec = 0;
    while (1)
    {
        num = gnutls_record_recv(s->session, buf, len);
        if (num > 0)  /* data was read successfully */
        {
            return num;
        }
        if (num == 0)  /* EOF */
        {
            return 0;
        }
        if (num == GNUTLS_E_REHANDSHAKE)
        {
            /* if a client receives GNUTLS_E_REHANDSHAKE then it can respond by */
            /* ignoring the rehandshake request, */
            /* sending a GNUTLS_E_WARNING_ALERT_RECEIVED alert */
            /* or by performing a handshake */

            /* if a server receives GNUTLS_E_REHANDSHAKE then it can respond by */
            /* performing a handshake */
            /* or terminating the connection */

            /* gnutls_alert_send(s->session, GNUTLS_E_WARNING_ALERT_RECEIVED, GNUTLS_A_NO_RENEGOTIATION); */

            ret = tls_sock_handshake(s);
            if (ret != SOCK_OK)
            {
                return ret;
            }
        }
        else if (num == GNUTLS_E_INTERRUPTED)
        {
            return SOCK_INTR;
        }
        else if (num != GNUTLS_E_AGAIN)
        {
            return SOCK_READ_ERROR;
        }
        FD_ZERO(&readfds);
        FD_SET(s->sd, &readfds);
        FD_ZERO(&errfds);
        FD_SET(s->sd, &errfds);
        ret = select(s->sd + 1, &readfds, NULL, &errfds, &tv);
        if (ret == 0)
        {
            return SOCK_TIMEOUT;
        }
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                return SOCK_INTR;
            }
            return SOCK_READ_ERROR;
        }
    }
}

/*  return { > 0, number of bytes read
 *         {   0, connection closed
 *         { < 0, error
 */
ssize_t tls_sock_read_full(tls_sock_t *s, void *buf, size_t len)
{
    ssize_t num_bytes = 0;
    size_t total_bytes = 0;

    while (total_bytes < len)
    {
        num_bytes = tls_sock_read(s, (char *)buf + total_bytes, len - total_bytes);
        if (num_bytes <= 0)
        {
            return num_bytes;
        }
        total_bytes += num_bytes;
    }
    return total_bytes;
}

/*  return { > 0, number of bytes read
 *         {   0, connection closed
 *         { < 0, error
 */
ssize_t tls_sock_write(tls_sock_t *s, void *buf, size_t len)
{
    struct timeval tv = {0};
    fd_set writefds = {{0}};
    fd_set errfds = {{0}};
    ssize_t num = 0;
    int ret = 0;

    tv.tv_sec = s->timeout;
    tv.tv_usec = 0;
    while (1)
    {
        num = gnutls_record_send(s->session, buf, len);
        if (num > 0)  /* data was written successfully */
        {
            return num;
        }
        if (num == 0)  /* EOF */
        {
            return 0;
        }
        if (num == GNUTLS_E_INTERRUPTED)
        {
            return SOCK_INTR;
        }
        if (num != GNUTLS_E_AGAIN)
        {
            return SOCK_WRITE_ERROR;
        }
        FD_ZERO(&writefds);
        FD_SET(s->sd, &writefds);
        FD_ZERO(&errfds);
        FD_SET(s->sd, &errfds);
        ret = select(s->sd + 1, NULL, &writefds, &errfds, &tv);
        if (ret == 0)
        {
            return SOCK_TIMEOUT;
        }
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                return SOCK_INTR;
            }
            return SOCK_WRITE_ERROR;
        }
    }
}

/*  return { > 0, number of bytes read
 *         {   0, connection closed
 *         { < 0, error
 */
ssize_t tls_sock_write_full(tls_sock_t *s, void *buf, size_t len)
{
    ssize_t num_bytes = 0;
    size_t total_bytes = 0;

    while (total_bytes < len)
    {
        num_bytes = tls_sock_write(s, (char *)buf + total_bytes, len - total_bytes);
        if (num_bytes <= 0)
        {
            return num_bytes;
        }
        total_bytes += num_bytes;
    }
    return total_bytes;
}

int tls_ssock_open(tls_ssock_t *ss, tls_server_t *server, const char *port, int timeout, int backlog)
{
    int opt_val = 0;
    int ret = 0;

    memset(ss, 0, sizeof(tls_ssock_t));

    if (timeout < 0)
    {
        return SOCK_ARG_ERROR;
    }

    ss->server = server;

    /* open a socket */
    ss->sd = socket(SOCK_PF_INET, SOCK_STREAM, 0);
    if (ss->sd == -1)
    {
        return SOCK_OPEN_ERROR;
    }

    /* allow bind to reuse the port */
    opt_val = 1;
    ret = setsockopt(ss->sd, SOL_SOCKET, SO_REUSEADDR, &opt_val, (socklen_t)sizeof(opt_val));
    if (ret < 0)
    {
        close(ss->sd);
        return SOCK_CONFIG_ERROR;
    }

    /* initialise the sin structure */
    memset(&ss->sin, 0, sizeof(ss->sin));
    ss->sin.SOCK_SIN_FAMILY = SOCK_AF_INET;
    ss->sin.SOCK_IN_ADDR = SOCK_INADDR_ANY;
    ss->sin.SOCK_SIN_PORT = htons((in_port_t)atoi(port));

    /* bind to address */
    ret = bind(ss->sd, (struct sockaddr *)&ss->sin, (socklen_t)sizeof(ss->sin));
    if (ret < 0)
    {
        close(ss->sd);
        return SOCK_BIND_ERROR;
    }

    /* start listening */
    ret = listen(ss->sd, backlog);
    if (ret < 0)
    {
        close(ss->sd);
        return SOCK_LISTEN_ERROR;
    }

    /* initialise timeout value */
    ss->timeout = timeout;

    /* set non-blocking status */
    ret = set_non_blocking(ss->sd);
    if (ret < 0)
    {
        close(ss->sd);
        return SOCK_CONFIG_ERROR;
    }

    return SOCK_OK;
}

void tls_ssock_close(tls_ssock_t *ss)
{
    close(ss->sd);
    memset(ss, 0, sizeof(tls_ssock_t));
}

int tls_ssock_accept(tls_ssock_t *ss, tls_sock_t *s)
{
    struct timeval tv = {0};
    socklen_t addrlen = 0;
    fd_set readfds = {{0}};
    int ret = 0;

    memset(s, 0, sizeof(tls_sock_t));
    addrlen = (socklen_t)sizeof(s->sin);

    tv.tv_sec = ss->timeout;
    tv.tv_usec = 0;
    while (1)
    {
        s->sd = accept(ss->sd, (struct sockaddr *)&s->sin, &addrlen);
        if (s->sd > 0)
        {
            break;
        }
        if (s->sd == -1)
        {
            if (errno == EINTR)
            {
                return SOCK_INTR;
            }
            if (errno != EAGAIN)
            {
                return SOCK_ACCEPT_ERROR;
            }
        }
        FD_ZERO(&readfds);
        FD_SET(ss->sd, &readfds);
        ret = select(ss->sd + 1, &readfds, NULL, NULL, &tv);
        if (ret == 0)
        {
            return SOCK_TIMEOUT;
        }
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                return SOCK_INTR;
            }
            return SOCK_ACCEPT_ERROR;
        }
    }

    s->type = TLS_SOCK_SERVER;
    s->u.server = ss->server;
    return tls_sock_open_(s, NULL, ss->timeout);
}
