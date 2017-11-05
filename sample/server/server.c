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
#include <gnutls/gnutls.h>
#include <time.h>
#include "server.h"
#include "coap_msg.h"
#include "coap_log.h"
#include "raw_keys.h"

#define SERVER_URI_PATH_BUF_LEN  32
#define SERVER_PAYLOAD_BUF_LEN   32  /* ctime_r writes to a buffer which must be at least 26 bytes */

static int server_handle_time(coap_server_t *coap_server, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    time_t t = 0;
    char payload_buf[SERVER_PAYLOAD_BUF_LEN] = {0};
    char *p = NULL;
    int ret = 0;

    code_detail = coap_msg_get_code_detail(req);
    if (code_detail == COAP_MSG_GET)
    {
        /* process request */
        coap_log_info("Received request method: GET");
        if (coap_msg_get_payload_len(req) != 0)
        {
            coap_log_warn("Received request message with payload");
        }

        /* perform action */
        time(&t);
        ctime_r(&t, payload_buf);
        p = strchr(payload_buf, '\n');
        if (p != NULL)
            *p = '\0';

        /* generate response */
        coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
        ret = coap_msg_add_op(resp, COAP_MSG_URI_PATH, 4, "time");
        if (ret < 0)
        {
            coap_log_error("Failed to set URI path in response message");
            return ret;
        }
        ret = coap_msg_set_payload(resp, payload_buf, strlen(payload_buf));
        if (ret < 0)
        {
            coap_log_error("Failed to set payload in response message");
            return ret;
        }
        coap_log_info("Sent response with payload: '%s'", payload_buf);
        return 0;
    }
    coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
    return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
}

static int server_handle(coap_server_t *coap_server, coap_msg_t *req, coap_msg_t *resp)
{
    size_t n = 0;
    char uri_path_buf[SERVER_URI_PATH_BUF_LEN] = {0};

    if (coap_msg_get_ver(req) != COAP_MSG_VER)
    {
        coap_log_error("Received request message with invalid version: %d", coap_msg_get_ver(req));
        return -EBADMSG;
    }
    n = coap_msg_uri_path_to_str(req, uri_path_buf, sizeof(uri_path_buf));
    if ((n + 1) > sizeof(uri_path_buf))
    {
        coap_log_error("URI path buffer too small by %zd bytes", (n + 1) - sizeof(uri_path_buf));
        return -ENOSPC;
    }
    coap_log_info("Received request URI path: '%s'", uri_path_buf);
    if (strcmp(uri_path_buf, "/time") == 0)
    {
        return server_handle_time(coap_server, req, resp);
    }
    coap_log_warn("URI path not recognised");
    return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_NOT_FOUND);
}

/* one-time initialisation */
int server_init(const char *priv_key_file_name,
                const char *pub_key_file_name,
                const char *access_file_name)
{
    int ret = 0;

    coap_log_set_level(COAP_LOG_DEBUG);
    ret = raw_keys_load(priv_key_file_name,
                        pub_key_file_name,
                        access_file_name);
    if (ret < 0)
    {
        coap_log_error("Unable to load raw public keys");
        return ret;
    }
    return 0;
}

int server_create(server_t *server,
                  const char *host,
                  const char *port)
{
    int ret = 0;

    memset(server, 0, sizeof(server_t));
    ret = coap_server_create(&server->coap_server,
                             server_handle,
                             host,
                             port,
                             raw_keys_get_ecdsa_priv_key(),
                             raw_keys_get_ecdsa_pub_key_x(),
                             raw_keys_get_ecdsa_pub_key_y(),
                             raw_keys_get_ecdsa_access_x(),
                             raw_keys_get_ecdsa_access_y(),
                             raw_keys_get_ecdsa_access_num(),
                             RAW_KEYS_ECDSA_KEY_LEN);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        memset(server, 0, sizeof(server_t));
        return ret;
    }
    return ret;
}

void server_destroy(server_t *server)
{
    coap_server_destroy(&server->coap_server);
    memset(server, 0, sizeof(server_t));
}

int server_run(server_t *server)
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
