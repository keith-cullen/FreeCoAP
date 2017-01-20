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
 *  @file test_server.c
 *
 *  @brief Source file for the FreeCoAP server test application
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "coap_server.h"
#include "coap_log.h"

#ifdef COAP_IP6
#define HOST                 "::"                                               /**< Host address to listen on */
#else
#define HOST                 "0.0.0.0"                                          /**< Host address to listen on */
#endif
#define PORT                 "12436"                                            /**< UDP port number to listen on */
#define KEY_FILE_NAME        "../../certs/server_privkey.pem"                   /**< DTLS key file name */
#define CERT_FILE_NAME       "../../certs/server_cert.pem"                      /**< DTLS certificate file name */
#define TRUST_FILE_NAME      "../../certs/root_client_cert.pem"                 /**< DTLS trust file name */
#define CRL_FILE_NAME        ""                                                 /**< DTLS certificate revocation list file name */
#define SEP_URI_PATH         "/separate"                                        /**< URI path that requires a separate response */
#define UNSAFE_URI_PATH      "unsafe"                                           /**< URI path that causes the server to include an unsafe option in the response */
#define UNSAFE_URI_PATH_LEN  6                                                  /**< Length of the URI path that causes the server to include an unsafe option in the response */

/**
 *  @brief Print a CoAP message
 *
 *  @param[in] str String to be printed before the message
 *  @param[in] msg Pointer to a message structure
 */
static void print_coap_msg(const char *str, coap_msg_t *msg)
{
    coap_log_level_t log_level = 0;
    coap_msg_op_t *op = NULL;
    unsigned num = 0;
    unsigned len = 0;
    unsigned i = 0;
    unsigned j = 0;
    char *payload = NULL;
    char *token = NULL;
    char *val = NULL;

    log_level = coap_log_get_level();
    if (log_level < COAP_LOG_INFO)
    {
        return;
    }
    printf("%s\n", str);
    printf("ver:         0x%02x\n", coap_msg_get_ver(msg));
    printf("type:        0x%02x\n", coap_msg_get_type(msg));
    printf("token_len:   %d\n", coap_msg_get_token_len(msg));
    printf("code_class:  %d\n", coap_msg_get_code_class(msg));
    printf("code_detail: %d\n", coap_msg_get_code_detail(msg));
    printf("msg_id:      0x%04x\n", coap_msg_get_msg_id(msg));
    printf("token:      ");
    token = coap_msg_get_token(msg);
    for (i = 0; i < coap_msg_get_token_len(msg); i++)
    {
        printf(" 0x%02x", (unsigned char)token[i]);
    }
    printf("\n");
    op = coap_msg_get_first_op(msg);
    while (op != NULL)
    {
        num = coap_msg_op_get_num(op);
        len = coap_msg_op_get_len(op);
        val = coap_msg_op_get_val(op);
        printf("op[%u].num:   %u\n", j, num);
        printf("op[%u].len:   %u\n", j, len);
        printf("op[%u].val:  ", j);
        for (i = 0; i < len; i++)
        {
            printf(" 0x%02x", (unsigned char)val[i]);
        }
        printf("\n");
        op = coap_msg_op_get_next(op);
        j++;
    }
    printf("payload:     ");
    payload = coap_msg_get_payload(msg);
    for (i = 0; i < coap_msg_get_payload_len(msg); i++)
    {
        printf("%c", payload[i]);
    }
    printf("\n");
    printf("payload_len: %zu\n", coap_msg_get_payload_len(msg));
    fflush(stdout);
}

/**
 *  @brief Check for the unsafe indication in the request
 *
 *  Check the URI path option in the request message for
 *  the value that instructs the server to include an unsafe
 *  option in the response. This feature is used to test
 *  the HTTP/CoAP proxy application.
 *
 *  @param[in] req Pointer to the request message
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int server_handle_unsafe(coap_msg_t *req, coap_msg_t *resp)
{
    coap_msg_op_t *op = NULL;
    unsigned num = 0;
    char *val = NULL;

    op = coap_msg_get_first_op(req);
    while (op != NULL)
    {
        num = coap_msg_op_get_num(op);
        if (num == COAP_MSG_URI_PATH)
        {
            val = coap_msg_op_get_val(op);
            if (strncmp(val, UNSAFE_URI_PATH, UNSAFE_URI_PATH_LEN) == 0)
            {
                coap_log_info("Including unsafe option in the response");
                return coap_msg_add_op(resp, 0x62, 5, "dummy");
            }
        }
        op = coap_msg_op_get_next(op);
    }
    return 0;
}

/**
 *  @brief Callback function to handle requests and generate responses
 *
 *  The handler function is called to service a request
 *  and produce a response. This function should only set
 *  the code and payload fields in the response message.
 *  The other fields are set by the server library when
 *  this function returns.
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int server_handle(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    char *payload = "Hello Client!";
    int ret = 0;

    ret = coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    ret = server_handle_unsafe(req, resp);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    ret = coap_msg_set_payload(resp, payload, strlen(payload));
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    print_coap_msg("Received:", req);
    print_coap_msg("Sent: (Note: the type, message ID and token fields have not been set by the server library yet)", resp);
    return 0;
}

/**
 *  @brief Main function for the CoAP server test application
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main()
{
    coap_server_t server = {0};
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_DEBUG);

#ifdef COAP_DTLS_EN
    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        return EXIT_FAILURE;
    }
    coap_log_info("GnuTLS version: %s", gnutls_ver);

    ret = coap_server_create(&server, server_handle, HOST, PORT, KEY_FILE_NAME, CERT_FILE_NAME, TRUST_FILE_NAME, CRL_FILE_NAME);
#else
    ret = coap_server_create(&server, server_handle, HOST, PORT);
#endif
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return EXIT_FAILURE;
    }
    ret = coap_server_add_sep_resp_uri_path(&server, SEP_URI_PATH);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        coap_server_destroy(&server);
        return EXIT_FAILURE;
    }
    ret = coap_server_run(&server);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        coap_server_destroy(&server);
        return EXIT_FAILURE;
    }
    coap_server_destroy(&server);
    return EXIT_SUCCESS;
}
