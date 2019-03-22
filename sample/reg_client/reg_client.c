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
#include "reg_client.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"
#ifdef COAP_DTLS_EN
#include "raw_keys.h"
#endif

#define REG_CLIENT_URI_PATH_BUF_LEN  32
#define REG_CLIENT_BIG_BUF_NUM       128
#define REG_CLIENT_BIG_BUF_LEN       1024
#define REG_CLIENT_SMALL_BUF_NUM     128
#define REG_CLIENT_SMALL_BUF_LEN     256

/* one-time initialisation */
int reg_client_init(const char *priv_key_file_name,
                    const char *pub_key_file_name,
                    const char *access_file_name)
{
#ifdef COAP_DTLS_EN
    int ret = 0;
#endif

    coap_log_set_level(COAP_LOG_DEBUG);
    ret = coap_mem_big_create(REG_CLIENT_BIG_BUF_NUM, REG_CLIENT_BIG_BUF_LEN);
    if (ret != 0)
    {
        coap_log_error("%s", strerror(-ret));
        return -1;
    }
    ret = coap_mem_small_create(REG_CLIENT_SMALL_BUF_NUM, REG_CLIENT_SMALL_BUF_LEN);
    if (ret != 0)
    {
        coap_log_error("%s", strerror(-ret));
        coap_mem_big_destroy();
        return -1;
    }
#ifdef COAP_DTLS_EN
    ret = raw_keys_load(priv_key_file_name,
                        pub_key_file_name,
                        access_file_name);
    if (ret < 0)
    {
        coap_log_error("Unable to load raw public keys");
        coap_mem_small_destroy();
        coap_mem_big_destroy();
        return ret;
    }
#endif
    return 0;
}

void reg_client_deinit(void)
{
    coap_mem_small_destroy();
    coap_mem_big_destroy();
}

int reg_client_create(reg_client_t *client,
                      const char *host,
                      const char *port)
{
    int ret = 0;

    memset(client, 0, sizeof(reg_client_t));
#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client->coap_client,
                             host,
                             port,
                             raw_keys_get_ecdsa_priv_key(),
                             raw_keys_get_ecdsa_pub_key_x(),
                             raw_keys_get_ecdsa_pub_key_y(),
                             raw_keys_get_ecdsa_access_x(),
                             raw_keys_get_ecdsa_access_y(),
                             raw_keys_get_ecdsa_access_num(),
                             RAW_KEYS_ECDSA_KEY_LEN);
#else
    ret = coap_client_create(&client->coap_client,
                             host,
                             port);
#endif
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        memset(client, 0, sizeof(reg_client_t));
        return ret;
    }
    return 0;
}

void reg_client_destroy(reg_client_t *client)
{
    coap_client_destroy(&client->coap_client);
    memset(client, 0, sizeof(reg_client_t));
}

int reg_client_register(reg_client_t *client, char *buf, size_t len)
{
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    size_t n = 0;
    char *p = NULL;
    char uri_path[REG_CLIENT_URI_PATH_BUF_LEN] = {0};
    int created = 0;
    int ret = 0;

    /* generate request */
    coap_msg_create(&req);
    coap_msg_set_type(&req, COAP_MSG_CON);
    coap_msg_set_code(&req, COAP_MSG_REQ, COAP_MSG_POST);
    coap_log_info("Sending POST /client/id request with payload: '%s'", buf);
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 6, "client");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
        coap_msg_destroy(&req);
        return ret;
    }
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 2, "id");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
        coap_msg_destroy(&req);
        return ret;
    }
    ret = coap_msg_set_payload(&req, buf, strlen(buf));
    if (ret < 0)
    {
        coap_log_error("Failed to set payload in request message");
        coap_msg_destroy(&req);
        return ret;
    }

    /* exchange */
    coap_msg_create(&resp);
    ret = coap_client_exchange(&client->coap_client, &req, &resp);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return ret;
    }

    /* process response */
    if (coap_msg_get_ver(&req) != coap_msg_get_ver(&resp))
    {
        coap_log_error("Received response message with invalid version: %d", coap_msg_get_ver(&resp));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    if ((coap_msg_get_code_class(&resp) != COAP_MSG_SUCCESS)
     || ((coap_msg_get_code_detail(&resp) != COAP_MSG_CREATED) && (coap_msg_get_code_detail(&resp) != COAP_MSG_CHANGED)))
    {
        coap_log_error("Received response message with invalid code class: %d, code detail: %d",
                       coap_msg_get_code_class(&resp), coap_msg_get_code_detail(&resp));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    created = coap_msg_get_code_detail(&resp) == COAP_MSG_CREATED;
    n = coap_msg_uri_path_to_str(&resp, uri_path, sizeof(uri_path));
    if ((n + 1) > sizeof(uri_path))
    {
        coap_log_error("URI path buffer too small by %zd bytes", (n + 1) - sizeof(uri_path));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -ENOSPC;
    }
    if (strcmp(uri_path, "/client/id") != 0)
    {
        coap_log_error("Received response message with invalid URI path: '%s'", uri_path);
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    p = coap_msg_get_payload(&resp);
    n = coap_msg_get_payload_len(&resp);
    if ((p == NULL) || (n == 0))
    {
        coap_log_error("Received response message with invalid payload");
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    if ((n + 1) > len)
    {
        coap_log_error("Payload buffer too small by %zd bytes", (n + 1) - len);
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -ENOSPC;
    }
    memcpy(buf, p, n);
    memset(buf + n, 0, len - n);
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    if (strcmp(buf, "OK") != 0)
    {
        coap_log_error("Received response message with unexpected payload: '%s'", buf);
        return -EBADMSG;
    }
    coap_log_info("Received %s %s response with payload: '%s'",
                  created ? "CREATED" : "CHANGED", uri_path, buf);
    return n;
}
