/*
 * Copyright (c) 2017 Keith Cullen.
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

#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "reg_server.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"

#define REG_SERVER_URI_PATH_BUF_LEN  32
#define REG_SERVER_PAYLOAD_LEN       32
#define REG_SERVER_SMALL_BUF_NUM     128                                        /**< Number of buffers in the small memory allocator */
#define REG_SERVER_SMALL_BUF_LEN     256                                        /**< Length of each buffer in the small memory allocator */
#define REG_SERVER_MEDIUM_BUF_NUM    128                                        /**< Number of buffers in the medium memory allocator */
#define REG_SERVER_MEDIUM_BUF_LEN    1024                                       /**< Length of each buffer in the medium memory allocator */
#define REG_SERVER_LARGE_BUF_NUM     32                                         /**< Number of buffers in the large memory allocator */
#define REG_SERVER_LARGE_BUF_LEN     8192                                       /**< Length of each buffer in the large memory allocator */

static void reg_server_log_registrar(reg_server_t *server)
{
    registrar_entry_t *entry = NULL;
    int i = 0;

    entry = registrar_get_first(&server->registrar);
    while (entry != NULL)
    {
        coap_log_info("registrar[%d]: id='%s', addr='%s'",
                      i, registrar_entry_get_id(entry),
                      registrar_entry_get_addr(entry));
        i++;
        entry = registrar_entry_get_next(entry);
    }
}

static int reg_server_handle_client_id(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    reg_server_t *server = (reg_server_t *)trans->server;
    registrar_t *registrar = &server->registrar;
    const char *p = NULL;
    unsigned code_detail = 0;
    size_t n = 0;
    char payload[REG_SERVER_PAYLOAD_LEN] = {0};
    char addr[COAP_IPV_INET_ADDRSTRLEN] = {0};
    int created = 0;
    int ret = 0;

    code_detail = coap_msg_get_code_detail(req);
    if (code_detail == COAP_MSG_POST)
    {
        /* process request */
        coap_log_info("Received request method: POST");
        p = inet_ntop(COAP_IPV_AF_INET, &trans->client_sin.COAP_IPV_SIN_ADDR, addr, sizeof(addr));
        if (p == NULL)
        {
            coap_log_warn("Could not resolve client address: %s", strerror(errno));
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        addr[sizeof(addr) - 1] = '\0';
        coap_log_info("Received request from address: %s", addr);
        p = coap_msg_get_payload(req);
        n = coap_msg_get_payload_len(req);
        if ((p == NULL) || (n == 0))
        {
            coap_log_warn("Received request message without payload");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        if ((n + 1) > sizeof(payload))
        {
            coap_log_warn("Payload buffer too small by %zd bytes", (n + 1) - sizeof(payload));
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        memcpy(payload, p, n);
        memset(payload + n, 0, sizeof(payload) - n);
        coap_log_info("Received request payload: '%s'", payload);

        /* action */
        ret = registrar_add(registrar, payload, addr);
        if (ret < 0)
        {
            return ret;
        }
        if (ret == 0)
        {
            created = 1;
        }
        reg_server_log_registrar(server);

        /* generate response */
        if (created)
            coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CREATED);
        else
            coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CHANGED);
        ret = coap_msg_add_op(resp, COAP_MSG_URI_PATH, 6, "client");
        if (ret < 0)
        {
            coap_log_warn("Failed to set URI path in response message");
            return ret;
        }
        ret = coap_msg_add_op(resp, COAP_MSG_URI_PATH, 2, "id");
        if (ret < 0)
        {
            coap_log_warn("Failed to set URI path in response message");
            return ret;
        }
        memcpy(payload, "OK", 2);
        memset(payload + 2, 0, sizeof(payload) - 2);
        ret = coap_msg_set_payload(resp, payload, 2);
        if (ret < 0)
        {
            coap_log_warn("Failed to set payload in response message");
            return ret;
        }
        coap_log_info("Sent %s /client/id response with payload: '%s'",
                      created ? "CREATED" : "CHANGED", payload);
        return 0;
    }
    coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
    return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
}

static int reg_server_handle(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    size_t n = 0;
    char uri_path[REG_SERVER_URI_PATH_BUF_LEN] = {0};

    if (coap_msg_get_ver(req) != COAP_MSG_VER)
    {
        coap_log_warn("Received request message with invalid version: %d", coap_msg_get_ver(req));
        return -EBADMSG;
    }
    n = coap_msg_uri_path_to_str(req, uri_path, sizeof(uri_path));
    if ((n + 1) > sizeof(uri_path))
    {
        coap_log_warn("URI path buffer too small by %zd bytes", (n + 1) - sizeof(uri_path));
        return -ENOSPC;
    }
    coap_log_info("Received request URI path: '%s'", uri_path);
    if (strcmp(uri_path, "/client/id") != 0)
    {
        coap_log_warn("URI path not recognised");
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_NOT_FOUND);
    }
    return reg_server_handle_client_id(trans, req, resp);
}

/* one-time initialisation */
int reg_server_init(void)
{
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_INFO);
    ret = coap_mem_all_create(REG_SERVER_SMALL_BUF_NUM, REG_SERVER_SMALL_BUF_LEN,
                              REG_SERVER_MEDIUM_BUF_NUM, REG_SERVER_MEDIUM_BUF_LEN,
                              REG_SERVER_LARGE_BUF_NUM, REG_SERVER_LARGE_BUF_LEN);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return -1;
    }
#ifdef COAP_DTLS_EN
    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        coap_mem_all_destroy();
        return -1;
    }
    coap_log_info("GnuTLS version: %s", gnutls_ver);
#endif
    return 0;
}

void reg_server_deinit(void)
{
    coap_mem_all_destroy();
}

int reg_server_create(reg_server_t *server,
                      const char *host,
                      const char *port,
                      const char *key_file_name,
                      const char *cert_file_name,
                      const char *trust_file_name,
                      const char *crl_file_name)
{
    int ret = 0;

    memset(server, 0, sizeof(reg_server_t));
#ifdef COAP_DTLS_EN
    ret = coap_server_create(&server->coap_server,
                             reg_server_handle,
                             host,
                             port,
                             key_file_name,
                             cert_file_name,
                             trust_file_name,
                             crl_file_name);
#else
    ret = coap_server_create(&server->coap_server,
                             reg_server_handle,
                             host,
                             port);
#endif
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        memset(server, 0, sizeof(reg_server_t));
        return ret;
    }
    registrar_create(&server->registrar);
    return ret;
}

void reg_server_destroy(reg_server_t *server)
{
    registrar_destroy(&server->registrar);
    coap_server_destroy(&server->coap_server);
    memset(server, 0, sizeof(reg_server_t));
}

int reg_server_run(reg_server_t *server)
{
    int ret = 0;

    ret = coap_server_run(&server->coap_server);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
    }
    return ret;
}
