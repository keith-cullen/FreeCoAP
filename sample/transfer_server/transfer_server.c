/*
 * Copyright (c) 2019 Keith Cullen.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "transfer_server.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"

#define TRANSFER_SERVER_URI_PATH_BUF_LEN  32
#define TRANSFER_SERVER_SMALL_BUF_NUM     128                                   /**< Number of buffers in the small memory allocator */
#define TRANSFER_SERVER_SMALL_BUF_LEN     256                                   /**< Length of each buffer in the small memory allocator */
#define TRANSFER_SERVER_MEDIUM_BUF_NUM    128                                   /**< Number of buffers in the medium memory allocator */
#define TRANSFER_SERVER_MEDIUM_BUF_LEN    1024                                  /**< Length of each buffer in the medium memory allocator */
#define TRANSFER_SERVER_LARGE_BUF_NUM     32                                    /**< Number of buffers in the large memory allocator */
#define TRANSFER_SERVER_LARGE_BUF_LEN     8192                                  /**< Length of each buffer in the large memory allocator */
#define TRANSFER_SERVER_BLOCK1_SIZE       64                                    /**< Block size for data received from the client */
#define TRANSFER_SERVER_BLOCK2_SIZE       64                                    /**< Block size for data sent to the client */
#define TRANSFER_SERVER_FILENAME          "out"                                 /**< Filename to store received data */

static int transfer_server_handle_rx(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    ssize_t num = 0;
    FILE *file = NULL;

    file = fopen(TRANSFER_SERVER_FILENAME, "wb");
    if (file == NULL)
    {
        coap_log_warn("%s", strerror(-num));
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
    }
    num = fwrite(coap_server_trans_get_body(trans), 1, coap_server_trans_get_body_end(trans), file);
    if (num != coap_server_trans_get_body_end(trans))
    {
        fclose(file);
        num = -EIO;
        coap_log_warn("%s", strerror(-num));
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
    }
    fclose(file);
    coap_log_info("Saved %zu bytes to '%s'",
                  coap_server_trans_get_body_end(trans),
                  TRANSFER_SERVER_FILENAME);
    coap_server_trans_set_body_end(trans, 0);
    return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CHANGED);
}

static int transfer_server_handle(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;
    size_t n = 0;
    char uri_path[TRANSFER_SERVER_URI_PATH_BUF_LEN] = {0};

    if (coap_msg_get_ver(req) != COAP_MSG_VER)
    {
        coap_log_warn("Received request message with invalid version: %d", coap_msg_get_ver(req));
        return -EBADMSG;
    }
    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if ((code_class != COAP_MSG_REQ) || (code_detail != COAP_MSG_PUT))
    {
        coap_log_warn("Request method not implemented");
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
    }
    n = coap_msg_uri_path_to_str(req, uri_path, sizeof(uri_path));
    if ((n + 1) > sizeof(uri_path))
    {
        coap_log_warn("URI path buffer too small by %zd bytes", (n + 1) - sizeof(uri_path));
        return -ENOSPC;
    }
    coap_log_info("Received request URI path: '%s'", uri_path);
    if (strcmp(uri_path, "/client/transfer") != 0)
    {
        coap_log_warn("URI path not recognised");
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_NOT_FOUND);
    }
    return coap_server_trans_handle_blockwise(trans, req, resp,
                                              TRANSFER_SERVER_BLOCK1_SIZE,
                                              TRANSFER_SERVER_BLOCK2_SIZE,
                                              NULL, 0,
                                              transfer_server_handle_rx);
}

/* one-time initialisation */
int transfer_server_init(void)
{
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_INFO);
    ret = coap_mem_all_create(TRANSFER_SERVER_SMALL_BUF_NUM, TRANSFER_SERVER_SMALL_BUF_LEN,
                              TRANSFER_SERVER_MEDIUM_BUF_NUM, TRANSFER_SERVER_MEDIUM_BUF_LEN,
                              TRANSFER_SERVER_LARGE_BUF_NUM, TRANSFER_SERVER_LARGE_BUF_LEN);
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

void transfer_server_deinit(void)
{
    coap_mem_all_destroy();
}

int transfer_server_create(transfer_server_t *server,
                           const char *host,
                           const char *port,
                           const char *key_file_name,
                           const char *cert_file_name,
                           const char *trust_file_name,
                           const char *crl_file_name)
{
    int ret = 0;

    memset(server, 0, sizeof(transfer_server_t));
#ifdef COAP_DTLS_EN
    ret = coap_server_create(&server->coap_server,
                             transfer_server_handle,
                             host,
                             port,
                             key_file_name,
                             cert_file_name,
                             trust_file_name,
                             crl_file_name);
#else
    ret = coap_server_create(&server->coap_server,
                             transfer_server_handle,
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
        memset(server, 0, sizeof(transfer_server_t));
        return ret;
    }
    return ret;
}

void transfer_server_destroy(transfer_server_t *server)
{
    coap_server_destroy(&server->coap_server);
    memset(server, 0, sizeof(transfer_server_t));
}

int transfer_server_run(transfer_server_t *server)
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
