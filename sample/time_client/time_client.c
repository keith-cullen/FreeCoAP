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
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "time_client.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"

#define TIME_CLIENT_URI_PATH_BUF_LEN  32
#define TIME_CLIENT_SMALL_BUF_NUM     128                                       /**< Number of buffers in the small memory allocator */
#define TIME_CLIENT_SMALL_BUF_LEN     256                                       /**< Length of each buffer in the small memory allocator */
#define TIME_CLIENT_MEDIUM_BUF_NUM    128                                       /**< Number of buffers in the medium memory allocator */
#define TIME_CLIENT_MEDIUM_BUF_LEN    1024                                      /**< Length of each buffer in the medium memory allocator */
#define TIME_CLIENT_LARGE_BUF_NUM     32                                        /**< Number of buffers in the large memory allocator */
#define TIME_CLIENT_LARGE_BUF_LEN     8192                                      /**< Length of each buffer in the large memory allocator */

/* one-time initialisation */
int time_client_init(void)
{
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_INFO);
    ret = coap_mem_all_create(TIME_CLIENT_SMALL_BUF_NUM, TIME_CLIENT_SMALL_BUF_LEN,
                              TIME_CLIENT_MEDIUM_BUF_NUM, TIME_CLIENT_MEDIUM_BUF_LEN,
                              TIME_CLIENT_LARGE_BUF_NUM, TIME_CLIENT_LARGE_BUF_LEN);
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

void time_client_deinit(void)
{
    coap_mem_all_destroy();
}

int time_client_create(time_client_t *client,
                       const char *host,
                       const char *port,
                       const char *key_file_name,
                       const char *cert_file_name,
                       const char *trust_file_name,
                       const char *crl_file_name,
                       const char *common_name)
{
    int ret = 0;

    memset(client, 0, sizeof(time_client_t));
#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client->coap_client,
                             host,
                             port,
                             key_file_name,
                             cert_file_name,
                             trust_file_name,
                             crl_file_name,
                             common_name);
#else
    ret = coap_client_create(&client->coap_client,
                             host,
                             port);
#endif
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        memset(client, 0, sizeof(time_client_t));
        return ret;
    }
    return 0;
}

void time_client_destroy(time_client_t *client)
{
    coap_client_destroy(&client->coap_client);
    memset(client, 0, sizeof(time_client_t));
}

int time_client_get_time(time_client_t *client, char *buf, size_t len)
{
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    size_t n = 0;
    char *p = NULL;
    char uri_path_buf[TIME_CLIENT_URI_PATH_BUF_LEN] = {0};
    int ret = 0;

    /* generate request */
    coap_msg_create(&req);
    coap_msg_set_type(&req, COAP_MSG_CON);
    coap_msg_set_code(&req, COAP_MSG_REQ, COAP_MSG_GET);
    coap_log_info("Sending GET /time request");
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 4, "time");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
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
     || (coap_msg_get_code_detail(&resp) != COAP_MSG_CONTENT))
    {
        coap_log_error("Received response message with invalid code class: %d, code detail: %d",
                       coap_msg_get_code_class(&resp), coap_msg_get_code_detail(&resp));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    n = coap_msg_uri_path_to_str(&resp, uri_path_buf, sizeof(uri_path_buf));
    if ((n + 1) > sizeof(uri_path_buf))
    {
        coap_log_error("URI path buffer too small by %zd bytes", (n + 1) - sizeof(uri_path_buf));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -ENOSPC;
    }
    if (strcmp(uri_path_buf, "/time") != 0)
    {
        coap_log_error("Received response message with invalid URI path: '%s'", uri_path_buf);
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    p = coap_msg_get_payload(&resp);
    n = coap_msg_get_payload_len(&resp);
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
    coap_log_info("Received response with payload: '%s'", buf);
    return n;
}
