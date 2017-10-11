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
#include "coap_server.h"
#include "coap_log.h"
#ifdef COAP_DTLS_EN
#include "raw_keys.h"
#endif

#ifdef COAP_IP6
#define HOST                 "::1"                                              /**< Host address to listen on */
#else
#define HOST                 "127.0.0.1"                                        /**< Host address to listen on */
#endif
#define PORT                 "12436"                                            /**< UDP port number to listen on */
#define PUB_KEY_FILE_NAME    "../../raw_keys/server_pub_key.txt"                /**< ECDSA public key file name */
#define PRIV_KEY_FILE_NAME   "../../raw_keys/server_priv_key.txt"               /**< ECDSA private key file name */
#define ACCESS_FILE_NAME     "../../raw_keys/server_access.txt"                 /**< ECDSA public key access control list file name */
#define KEY_LEN              32                                                 /**< Length in bytes of the ECDSA keys*/
#define SEP_URI_PATH         "/sep/uri/path"                                    /**< URI path that requires a separate response */
#define UNSAFE_URI_PATH      "unsafe"                                           /**< URI path that causes the server to include an unsafe option in the response */
#define BLOCKWISE_URI_PATH   "block"                                            /**< URI path that causes the server to use blockwise transfers */
#define BLOCKWISE_BUF_LEN    40                                                 /**< Total length (in bytes) of the buffer used for blockwise transfers */
#define BLOCK_SIZE           16                                                 /**< Size of an individual block in a blockwise transfer */

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
 *  @brief Match the URI path in a CoAP message
 *
 *  Check the URI path option in a CoAP message
 *  against a specific value.
 *
 *  @param[in] msg Pointer to a CoAP message
 *  @param[in] str String containing the URI path
 *
 *  @returns Operation status
 *  @retval 1 match
 *  @retval 0 no match
 */
static int server_match_uri_path(coap_msg_t *msg, const char *str)
{
    coap_msg_op_t *op = NULL;
    unsigned num = 0;
    unsigned len = 0;
    char *val = NULL;

    op = coap_msg_get_first_op(msg);
    while (op != NULL)
    {
        num = coap_msg_op_get_num(op);
        if (num == COAP_MSG_URI_PATH)
        {
            len = coap_msg_op_get_len(op);
            val = coap_msg_op_get_val(op);
            if ((len == strlen(str)) && (strncmp(val, str, len) == 0))
            {
                return 1;  /* match */
            }
        }
        op = coap_msg_op_get_next(op);
    }
    return 0;  /* no match */
}

/**
 *  @brief Find and parse a Block1 or Block2 option
 *
 *  @param[out] num Pointer to Block number
 *  @param[out] more Pointer to More value
 *  @param[out] size Pointre to Block size (in bytes)
 *  @param[in] msg Pointer to a CoAP message
 *  @param[in] type Block option type: COAP_MSG_BLOCK1 or COAP_MSG_BLOCK2
 *
 *  @returns Operation status
 *  @retval 1 Block option not found
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_parse_block_op(unsigned *num, unsigned *more, unsigned *size, coap_msg_t *msg, int type)
{
    coap_msg_op_t *op = NULL;
    unsigned op_num = 0;
    unsigned op_len = 0;
    char *op_val = NULL;

    op = coap_msg_get_first_op(msg);
    while (op != NULL)
    {
        op_num = coap_msg_op_get_num(op);
        op_len = coap_msg_op_get_len(op);
        op_val = coap_msg_op_get_val(op);
        if (((op_num == COAP_MSG_BLOCK1) && (type == COAP_MSG_BLOCK1))
         || ((op_num == COAP_MSG_BLOCK2) && (type == COAP_MSG_BLOCK2)))
        {
            return coap_msg_op_parse_block_val(num, more, size, op_val, op_len);
        }
        op = coap_msg_op_get_next(op);
    }
    return 1;  /* not found */
}

/**
 *  @brief Handle unsafe transfers
 *
 *  This function generates a response that contains an unsafe
 *  option. This is used to test the HTTP/CoAP proxy.
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_unsafe(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;
    char *payload = "Hello Client!";
    int ret = 0;

    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if (code_class != COAP_MSG_REQ)
    {
        coap_log_warn("Received request message with invalid code class: %d", code_class);
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
    }
    if (code_detail != COAP_MSG_GET)
    {
        coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
    }
    coap_log_info("Including unsafe option in the response");
    ret = coap_msg_add_op(resp, 0x62, 5, "dummy");
    if (ret < 0)
    {
        coap_log_error("Failed to add CoAP option to response message");
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
    }
    ret = coap_msg_set_payload(resp, payload, strlen(payload));
    if (ret < 0)
    {
        coap_log_error("Failed to add payload to response message");
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
    }
    return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
}

static char blockwise_buf[BLOCKWISE_BUF_LEN] = {0};                             /**< Buffer used for blockwise transfers */

/**
 *  @brief Handle blockwise transfers
 *
 *  This function handles requests and responses that
 *  involve blockwise transfers.
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_blockwise(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    const char *payload = NULL;
    unsigned code_detail = 0;
    unsigned code_class = 0;
    unsigned block_size = 0;
    unsigned block_more = 0;
    unsigned block_num = 0;
    unsigned start = 0;
    unsigned len = 0;
    char block_val[3] = {0};
    int ret = 0;

    /* determine method */
    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if (code_class != COAP_MSG_REQ)
    {
        coap_log_warn("Received request message with invalid code class: %d", code_class);
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
    }
    if (code_detail == COAP_MSG_PUT)
    {
        /* request */
        ret = server_parse_block_op(&block_num, &block_more, &block_size, req, COAP_MSG_BLOCK1);
        if (ret < 0)
        {
            coap_log_warn("Unable to parse Block1 option value in request message");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
        }
        if (ret == 1)
        {
            /* no Block1 option in the request */
            coap_log_warn("Received request message without Block1 option");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        start = block_num * block_size;
        if (start >= sizeof(blockwise_buf))
        {
            coap_log_warn("Received request message with invalid Block1 option value");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        len = coap_msg_get_payload_len(req);
        if (start + len > sizeof(blockwise_buf))
        {
            len = sizeof(blockwise_buf) - start;
        }
        payload = coap_msg_get_payload(req);
        if (payload == NULL)
        {
            coap_log_warn("Received request message without payload");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        memcpy(blockwise_buf + start, payload, len);

        /* response */
        ret = coap_msg_op_format_block_val(block_val, 1, block_num, 0, block_size);
        if (ret < 0)
        {
            coap_log_error("Failed to format Block1 option value, num:%d, size:%d", block_num, block_size);
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        ret = coap_msg_add_op(resp, COAP_MSG_BLOCK1, ret, block_val);
        if (ret < 0)
        {
            coap_log_error("Failed to add Block1 option to response message");
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CHANGED);
    }
    else if (code_detail == COAP_MSG_GET)
    {
        /* request */
        ret = server_parse_block_op(&block_num, &block_more, &block_size, req, COAP_MSG_BLOCK2);
        if (ret < 0)
        {
            coap_log_warn("Unable to parse Block2 option value in request message");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
        }
        if (ret == 1)
        {
            /* no Block2 option in the request */
            block_size = BLOCK_SIZE;
        }
        start = block_num * block_size;
        if (start >= sizeof(blockwise_buf))
        {
            coap_log_warn("Received request message with invalid Block2 option value");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        len = block_size;
        block_more = 1;
        if (start + len >= sizeof(blockwise_buf))
        {
            block_more = 0;
            len = sizeof(blockwise_buf) - start;
        }

        /* response */
        ret = coap_msg_op_format_block_val(block_val, 1, block_num, block_more, block_size);
        if (ret < 0)
        {
            coap_log_error("Failed to format Block2 option value");
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        ret = coap_msg_add_op(resp, COAP_MSG_BLOCK2, ret, block_val);
        if (ret < 0)
        {
            coap_log_error("Failed to add Block2 option to response message");
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        ret = coap_msg_set_payload(resp, blockwise_buf + start, len);
        if (ret < 0)
        {
            coap_log_error("Failed to add payload to response message");
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
    }
    coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
    return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
}

/**
 *  @brief Handle non-blockwise transfers
 *
 *  This function handles requests and responses that
 *  do not involve blockwise transfers.
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_non_blockwise(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;
    char *payload = "Hello Client!";
    int ret = 0;

    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if (code_class != COAP_MSG_REQ)
    {
        coap_log_warn("Received request message with invalid code class: %d", code_class);
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
    }
    if ((code_detail != COAP_MSG_GET) && (code_detail != COAP_MSG_POST))
    {
        coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
    }
    ret = coap_msg_set_payload(resp, payload, strlen(payload));
    if (ret < 0)
    {
        coap_log_error("Failed to add payload to response message");
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
    }
    return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
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
static int server_handle(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    int ret = 0;

    if (server_match_uri_path(req, UNSAFE_URI_PATH))
    {
        ret = server_handle_unsafe(server, req, resp);
    }
    if (server_match_uri_path(req, BLOCKWISE_URI_PATH))
    {
        ret = server_handle_blockwise(server, req, resp);
    }
    else
    {
        ret = server_handle_non_blockwise(server, req, resp);
    }
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
    int ret = 0;

    coap_log_set_level(COAP_LOG_DEBUG);

#ifdef COAP_DTLS_EN
    ret = raw_keys_load(PRIV_KEY_FILE_NAME, PUB_KEY_FILE_NAME, ACCESS_FILE_NAME);
    if (ret < 0)
    {
        return EXIT_FAILURE;
    }
    ret = coap_server_create(&server, server_handle, HOST, PORT,
                             raw_keys_get_ecdsa_priv_key(),
                             raw_keys_get_ecdsa_pub_key_x(),
                             raw_keys_get_ecdsa_pub_key_y(),
                             raw_keys_get_ecdsa_access_x(),
                             raw_keys_get_ecdsa_access_y(),
                             raw_keys_get_ecdsa_access_num(),
                             RAW_KEYS_ECDSA_KEY_LEN);

#else
    ret = coap_server_create(&server, server_handle, HOST, PORT);
#endif
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
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
        coap_log_error("%s", strerror(-ret));
        coap_server_destroy(&server);
        return EXIT_FAILURE;
    }
    coap_server_destroy(&server);
    return EXIT_SUCCESS;
}
