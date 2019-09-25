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
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"

#ifdef COAP_IP6
#define HOST                                "::"                                /**< Host address to listen on */
#else
#define HOST                                "0.0.0.0"                           /**< Host address to listen on */
#endif
#define PORT                                "12436"                             /**< UDP port number to listen on */
#define KEY_FILE_NAME                       "../../certs/server_privkey.pem"    /**< DTLS key file name */
#define CERT_FILE_NAME                      "../../certs/server_cert.pem"       /**< DTLS certificate file name */
#define TRUST_FILE_NAME                     "../../certs/root_client_cert.pem"  /**< DTLS trust file name */
#define CRL_FILE_NAME                       ""                                  /**< DTLS certificate revocation list file name */
#define RESET_URI_PATH                      "reset"                             /**< URI path that causes the server to reset to a known state */
#define RESET_URI_PATH_LEN                  5                                   /**< Length of the URI path that causes the server to reset to a known state */
#define UNSAFE_URI_PATH                     "unsafe"                            /**< URI path that causes the server to include an unsafe option in the response */
#define UNSAFE_URI_PATH_LEN                 6                                   /**< Length of the URI path that causes the server to include an unsafe option in the response */
#define SEP_URI_PATH                        "/sep/uri/path"                     /**< URI path that requires a separate response */
#define SEP_URI_PATH_LEN                    13                                  /**< Length of the URI path that requires a separate response */
#define REGULAR_URI_PATH                    "regular"                           /**< URI path that causes the server to use regular (i.e. non-blockwise) transfers */
#define REGULAR_URI_PATH_LEN                7                                   /**< Length of the URI path that causes the server to use regular (i.e. non-blockwise) transfers */
#define APP_LEVEL_BLOCKWISE_URI_PATH        "app-level-blockwise"               /**< URI path that causes the server to use application-level blockwise transfers */
#define APP_LEVEL_BLOCKWISE_URI_PATH_LEN    19                                  /**< Length of the URI path that causes the server to use application-level blockwise transfers */
#define LIB_LEVEL_BLOCKWISE_URI_PATH        "lib-level-blockwise"               /**< URI path that causes the server to use library-level blockwise transfers */
#define LIB_LEVEL_BLOCKWISE_URI_PATH_LEN    19                                  /**< Length of the URI path that causes the server to use library-level blockwise transfers */
#define REGULAR_BUF_LEN                     16                                  /**< Length of the buffer used in regular transfers */
#define APP_LEVEL_BLOCKWISE_BUF_LEN         40                                  /**< Length of the buffer used in application-level blockwise transfers */
#define LIB_LEVEL_BLOCKWISE_BUF_LEN         72                                  /**< Length of the buffers used in library-level blockwise transfers */
#define BLOCK_SIZE                          16                                  /**< Size of an individual block in a blockwise transfer */
#define SMALL_BUF_NUM                       128                                 /**< Number of buffers in the small memory allocator */
#define SMALL_BUF_LEN                       256                                 /**< Length of each buffer in the small memory allocator */
#define MEDIUM_BUF_NUM                      128                                 /**< Number of buffers in the medium memory allocator */
#define MEDIUM_BUF_LEN                      1024                                /**< Length of each buffer in the medium memory allocator */
#define LARGE_BUF_NUM                       32                                  /**< Number of buffers in the large memory allocator */
#define LARGE_BUF_LEN                       8192                                /**< Length of each buffer in the large memory allocator */
#define BLOCK1_SIZE                         32                                  /**< Preferred block1 size for blockwise transfers */
#define BLOCK2_SIZE                         32                                  /**< Preferred block2 size for blockwise transfers */

/**
 *  @brief Buffer used for regular transfers
 */
static char *regular_def_val = "qwertyuiopasdfgh";
static char regular_buf[REGULAR_BUF_LEN] = {0};

/**
 *  @brief Buffer used for application-level blockwise transfers
 */
static char *app_level_blockwise_def_val = "";
static char app_level_blockwise_buf[APP_LEVEL_BLOCKWISE_BUF_LEN] = {0};

/**
 *  @brief Buffer used for library-level blockwise transfers
 */
static char *lib_level_blockwise_def_val = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq";
static char lib_level_blockwise_buf[LIB_LEVEL_BLOCKWISE_BUF_LEN] = {0};

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
 *  @brief Handle reset
 *
 *  This function resets the server to a known state.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_reset(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    coap_log_notice("Resetting to a known state");

    memset(regular_buf, 0, sizeof(regular_buf));
    memcpy(regular_buf, regular_def_val, sizeof(regular_buf));

    memset(app_level_blockwise_buf, 0, sizeof(app_level_blockwise_buf));
    memcpy(app_level_blockwise_buf, app_level_blockwise_def_val, sizeof(app_level_blockwise_buf));

    memset(lib_level_blockwise_buf, 0, sizeof(lib_level_blockwise_buf));
    memcpy(lib_level_blockwise_buf, lib_level_blockwise_def_val, sizeof(lib_level_blockwise_buf));

    return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
}

/**
 *  @brief Handle unsafe transfers
 *
 *  This function generates a response that contains an unsafe
 *  option. This is used to test the HTTP/CoAP proxy.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_unsafe(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;
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
    ret = coap_msg_set_payload(resp, regular_buf, sizeof(regular_buf));
    if (ret < 0)
    {
        coap_log_error("Failed to add payload to response message");
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
    }
    return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
}

/**
 *  @brief Handle regular (i.e. non-blockwise) transfers
 *
 *  This function handles regular (i.e. non-blockwise)
 *  requests and responses. The same payload
 *  is returned to the client every time.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_regular(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;
    int ret = 0;

    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if (code_class != COAP_MSG_REQ)
    {
        coap_log_warn("Received request message with invalid code class: %d", code_class);
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
    }
    if (code_detail == COAP_MSG_GET)
    {
        ret = coap_msg_set_payload(resp, regular_buf, sizeof(regular_buf));
        if (ret < 0)
        {
            coap_log_error("Failed to add payload to response message");
            return ret;
        }
        return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
    }
    else if ((code_detail == COAP_MSG_PUT) || (code_detail == COAP_MSG_POST))
    {
        if (coap_msg_get_payload_len(req) > sizeof(regular_buf))
        {
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_REQ_ENT_TOO_LARGE);
        }
        memset(regular_buf, 0, sizeof(regular_buf));
        memcpy(regular_buf, coap_msg_get_payload(req), coap_msg_get_payload_len(req));
        return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CHANGED);
    }
    coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
    return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
}

/**
 *  @brief Handle application-level blockwise transfers
 *
 *  This function handles requests and responses
 *  that involve blockwise transfers that are
 *  implemented at the application level as opposed
 *  to the library level.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_app_level_blockwise(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    const char *payload = NULL;
    unsigned code_detail = 0;
    unsigned code_class = 0;
    unsigned block_size = 0;
    unsigned block_more = 0;
    unsigned block_num = 0;
    unsigned len = 0;
    size_t start = 0;
    char block_val[COAP_MSG_OP_MAX_BLOCK_VAL_LEN] = {0};
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
            coap_log_warn("Unable to parse Block1 option in request message");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
        }
        if (ret == 1)
        {
            /* no Block1 option in the request */
            coap_log_warn("Received request message without Block1 option");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        start = block_num * block_size;
        if (start >= sizeof(app_level_blockwise_buf))
        {
            coap_log_warn("Received request message with invalid Block1 option value");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        len = coap_msg_get_payload_len(req);
        if (start + len > sizeof(app_level_blockwise_buf))
        {
            len = sizeof(app_level_blockwise_buf) - start;
        }
        payload = coap_msg_get_payload(req);
        if (payload == NULL)
        {
            coap_log_warn("Received request message without payload");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        memcpy(app_level_blockwise_buf + start, payload, len);

        /* response */
        ret = coap_msg_op_format_block_val(block_val, sizeof(block_val), block_num, 0, block_size);
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
            coap_log_warn("Unable to parse Block2 option in request message");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
        }
        if (ret == 1)
        {
            /* no Block2 option in the request */
            block_size = BLOCK_SIZE;
        }
        start = block_num * block_size;
        if (start >= sizeof(app_level_blockwise_buf))
        {
            coap_log_warn("Received request message with invalid Block2 option value");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        len = block_size;
        block_more = 1;
        if (start + len >= sizeof(app_level_blockwise_buf))
        {
            block_more = 0;
            len = sizeof(app_level_blockwise_buf) - start;
        }

        /* response */
        ret = coap_msg_op_format_block_val(block_val, sizeof(block_val), block_num, block_more, block_size);
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
        ret = coap_msg_set_payload(resp, app_level_blockwise_buf + start, len);
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
 *  @brief Handle received blockwise body
 */
static int server_handle_lib_level_blockwise_rx(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    if (coap_server_trans_get_body_end(trans) > sizeof(lib_level_blockwise_buf))
    {
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_REQ_ENT_TOO_LARGE);
    }
    memset(lib_level_blockwise_buf, 0, sizeof(lib_level_blockwise_buf));
    memcpy(lib_level_blockwise_buf, coap_server_trans_get_body(trans), coap_server_trans_get_body_end(trans));
    /* for POST requests, return the recveived payload in the response body */
    if (coap_msg_get_code_detail(req) != COAP_MSG_POST)
    {
        coap_server_trans_set_body_end(trans, 0);
    }
    return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CHANGED);
}

/**
 *  @brief Handle library-level blockwise transfers
 *
 *  This function handles requests and responses
 *  that involve blockwise transfers that are
 *  implemented at the library level as opposed
 *  to the application level.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_lib_level_blockwise(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    unsigned code_detail = 0;
    unsigned code_class = 0;

    /* determine method */
    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if (code_class != COAP_MSG_REQ)
    {
        coap_log_warn("Received request message with invalid code class: %d", code_class);
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
    }
    if ((code_detail != COAP_MSG_GET)
     && (code_detail != COAP_MSG_PUT)
     && (code_detail != COAP_MSG_POST))
    {
        coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
        return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
    }
    /* do not allow regular transfers to succeed */
    if (coap_msg_get_payload_len(req) > sizeof(lib_level_blockwise_buf) - 1)
    {
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_REQ_ENT_TOO_LARGE);
    }
    /* request */
    return coap_server_trans_handle_blockwise(trans, req, resp,
                                              BLOCK1_SIZE, BLOCK2_SIZE,
                                              lib_level_blockwise_buf,
                                              sizeof(lib_level_blockwise_buf),
                                              server_handle_lib_level_blockwise_rx);
}

/**
 *  @brief Callback function to handle requests and generate responses
 *
 *  The handler function is called to service a request
 *  and produce a response.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle(coap_server_trans_t *trans, coap_msg_t *req, coap_msg_t *resp)
{
    int ret = 0;

    if (server_match_uri_path(req, RESET_URI_PATH))
    {
        coap_log_notice("handle reset");
        return server_handle_reset(trans, req, resp);
    }
    else if (server_match_uri_path(req, UNSAFE_URI_PATH))
    {
        coap_log_notice("handle unsafe");
        ret = server_handle_unsafe(trans, req, resp);
    }
    else if (server_match_uri_path(req, APP_LEVEL_BLOCKWISE_URI_PATH))
    {
        coap_log_notice("handle application-level blockwise");
        ret = server_handle_app_level_blockwise(trans, req, resp);
    }
    else if (server_match_uri_path(req, LIB_LEVEL_BLOCKWISE_URI_PATH))
    {
        coap_log_notice("handle library-level blockwise");
        ret = server_handle_lib_level_blockwise(trans, req, resp);
    }
    else
    {
        coap_log_notice("handle regular");
        ret = server_handle_regular(trans, req, resp);
    }
    print_coap_msg("Received:", req);
    print_coap_msg("Sent: ", resp);
    return ret;
}

/**
 *  @brief Main function for the CoAP server test application
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(void)
{
    coap_server_t server = {0};
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_INFO);
    ret = coap_mem_all_create(SMALL_BUF_NUM, SMALL_BUF_LEN,
                              MEDIUM_BUF_NUM, MEDIUM_BUF_LEN,
                              LARGE_BUF_NUM, LARGE_BUF_LEN);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return EXIT_FAILURE;
    }

#ifdef COAP_DTLS_EN
    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        coap_mem_all_destroy();
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
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }
    ret = coap_server_add_sep_resp_uri_path(&server, SEP_URI_PATH);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        coap_server_destroy(&server);
        coap_mem_all_destroy();
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
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }
    coap_server_destroy(&server);
    coap_mem_all_destroy();
    return EXIT_SUCCESS;
}
