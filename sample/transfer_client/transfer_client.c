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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "transfer_client.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"

#define TRANSFER_CLIENT_URI_PATH_BUF_LEN  32
#define TRANSFER_CLIENT_SMALL_BUF_NUM     128                                   /**< Number of buffers in the small memory allocator */
#define TRANSFER_CLIENT_SMALL_BUF_LEN     256                                   /**< Length of each buffer in the small memory allocator */
#define TRANSFER_CLIENT_MEDIUM_BUF_NUM    128                                   /**< Number of buffers in the medium memory allocator */
#define TRANSFER_CLIENT_MEDIUM_BUF_LEN    1024                                  /**< Length of each buffer in the medium memory allocator */
#define TRANSFER_CLIENT_LARGE_BUF_NUM     32                                    /**< Number of buffers in the large memory allocator */
#define TRANSFER_CLIENT_LARGE_BUF_LEN     8192                                  /**< Length of each buffer in the large memory allocator */
#define TRANSFER_CLIENT_BLOCK1_SIZE       64                                    /**< Block size for data sent to the server */
#define TRANSFER_CLIENT_BLOCK2_SIZE       64                                    /**< Block size for data received from the server */

/* one-time initialisation */
int transfer_client_init(void)
{
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_INFO);
    ret = coap_mem_all_create(TRANSFER_CLIENT_SMALL_BUF_NUM, TRANSFER_CLIENT_SMALL_BUF_LEN,
                              TRANSFER_CLIENT_MEDIUM_BUF_NUM, TRANSFER_CLIENT_MEDIUM_BUF_LEN,
                              TRANSFER_CLIENT_LARGE_BUF_NUM, TRANSFER_CLIENT_LARGE_BUF_LEN);
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

void transfer_client_deinit(void)
{
    coap_mem_all_destroy();
}

int transfer_client_create(transfer_client_t *client,
                           const char *host,
                           const char *port,
                           const char *key_file_name,
                           const char *cert_file_name,
                           const char *trust_file_name,
                           const char *crl_file_name,
                           const char *common_name)
{
    int ret = 0;

    memset(client, 0, sizeof(transfer_client_t));
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
        memset(client, 0, sizeof(transfer_client_t));
        return ret;
    }
    return 0;
}

void transfer_client_destroy(transfer_client_t *client)
{
    coap_client_destroy(&client->coap_client);
    memset(client, 0, sizeof(transfer_client_t));
}

/*  returns: { >=0, number of bytes read
 *           { <0,  error
 */
static ssize_t load_file(const char *filename, char **buf)
{
    ssize_t num = 0;
    FILE *file = NULL;
    long file_len = 0;
    char *file_buf = NULL;
    int ret = 0;

    /* load file */
    file = fopen(filename, "rb");
    if (file == NULL)
    {
        return -errno;
    }
    ret = fseek(file, 0, SEEK_END);
    if (ret < 0)
    {
        fclose(file);
        return -errno;
    }
    file_len = ftell(file);
    if (file_len < 0)
    {
        fclose(file);
        return -errno;
    }
    ret = fseek(file, 0, SEEK_SET);
    if (ret < 0)
    {
        fclose(file);
        return -errno;
    }
    file_buf = (char *)malloc(file_len);
    if (file_buf == NULL)
    {
        fclose(file);
        return -errno;
    }
    num = fread(file_buf, 1, file_len, file);
    if (num != file_len)
    {
        free(file_buf);
        fclose(file);
        return -EIO;
    }
    fclose(file);
    *buf = file_buf;
    return file_len;
}

int transfer_client_execute(transfer_client_t *client, const char *filename)
{
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    ssize_t num = 0;
    size_t file_len = 0;
    char *file_buf = NULL;
    int ret = 0;

    num = load_file(filename, &file_buf);
    if (num < 0)
    {
        coap_log_error("%s", strerror(-num));
        return num;
    }
    file_len = num;

    /* generate request */
    coap_msg_create(&req);
    coap_msg_set_type(&req, COAP_MSG_CON);
    coap_msg_set_code(&req, COAP_MSG_REQ, COAP_MSG_PUT);
    coap_log_info("Sending PUT /client/transfer request");
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 6, "client");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
        coap_msg_destroy(&req);
        free(file_buf);
        return ret;
    }
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 8, "transfer");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
        coap_msg_destroy(&req);
        free(file_buf);
        return ret;
    }

    /* blockwise transfer exchange */
    coap_msg_create(&resp);
    num = coap_client_exchange_blockwise(&client->coap_client,
                                         &req, &resp,
                                         TRANSFER_CLIENT_BLOCK1_SIZE,
                                         TRANSFER_CLIENT_BLOCK2_SIZE,
                                         file_buf, file_len,
                                         /* have_resp */ 0);
    if (num < 0)
    {
        if (num != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        free(file_buf);
        return ret;
    }
    free(file_buf);
    coap_log_info("Transfer response: %u.%u",
                  coap_msg_get_code_class(&resp),
                  coap_msg_get_code_detail(&resp));
    return 0;
}
