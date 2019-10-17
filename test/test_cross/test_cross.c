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
 *  @file test_cross.c
 *
 *  @brief Source file for the FreeCoAP HTTP/COAP message/URI cross library unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "cross.h"
#include "coap_mem.h"
#include "coap_log.h"
#include "test.h"

#undef DEBUG
#define DIM(x) (sizeof(x) / sizeof(x[0]))                                       /**< Calculate the size of an array */

#define SMALL_BUF_NUM   128                                                     /**< Number of buffers in the small memory allocator */
#define SMALL_BUF_LEN   256                                                     /**< Length of each buffer in the small memory allocator */
#define MEDIUM_BUF_NUM  128                                                     /**< Number of buffers in the medium memory allocator */
#define MEDIUM_BUF_LEN  1024                                                    /**< Length of each buffer in the medium memory allocator */
#define LARGE_BUF_NUM   32                                                      /**< Number of buffers in the large memory allocator */
#define LARGE_BUF_LEN   8192                                                    /**< Length of each buffer in the large memory allocator */

/**
 *  @brief CoAP message option test data structure
 */
typedef struct
{
    unsigned num;                                                               /**< Option number */
    unsigned len;                                                               /**< Option length */
    char *val;                                                                  /**< Pointer to a buffer containing the option value */
}
test_coap_msg_op_t;

/**
 *  @brief HTTP/CoAP message/URI cross test data structure
 */
typedef struct
{
    const char *http_to_coap_desc;                                              /**< Test description for the HTTP to CoAP conversion test */
    const char *coap_to_http_desc;                                              /**< Test description for the CoAP to HTTP conversion test */
    const char *str;                                                            /**< String containing a HTTP message or HTTP URI */
    int cross_ret;                                                              /**< Return value for the conversion */
    unsigned cross_code;                                                        /**< Result code for the conversion */
    unsigned coap_ver;                                                          /**< CoAP version */
    coap_msg_type_t coap_type;                                                  /**< CoAP message type */
    unsigned coap_code_class;                                                   /**< CoAP message code class */
    unsigned coap_code_detail;                                                  /**< CoAP message code detail */
    test_coap_msg_op_t *coap_ops;                                               /**< Array of CoAP message option test data structures */
    unsigned num_coap_ops;                                                      /**< Size of the array of CoAP message option test data structures */
    char *coap_payload;                                                         /**< Buffer containing a CoAP payload */
    size_t coap_payload_len;                                                    /**< Length of the buffer containing a CoAP payload */
    char *coap_body;                                                            /**< Buffer containing a CoAP body */
    size_t coap_body_len;                                                       /**< Length of the buffer containing a CoAP body */
    size_t coap_body_end;                                                       /**< End of the buffer containing a CoAP body */
}
test_cross_data_t;

/*    1           host,    port,    path,    query        coaps://host:1234/path?query
 *    2           host,    port,    path,    query        coaps://host:1234/root/path?query&extra
 *    3        no host, no port, no path, no query        coaps:/
 *    4           host, no port, no path, no query        coaps://host/
 *    5        no host,    port, no path, no query        coaps://:1234/
 *    6        no host, no port,    path, no query        coaps:/path
 *    7        no host, no port, no path,    query        coaps:/?query
 */

test_coap_msg_op_t test1_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_URI_HOST,
        .len = 4,
        .val = "host"
    },
    [1] =
    {
        .num = COAP_MSG_URI_PORT,
        .len = 4,
        .val = "1234"
    },
    [2] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = 4,
        .val = "path"
    },
    [3] =
    {
        .num = COAP_MSG_URI_QUERY,
        .len = 5,
        .val = "query"
    }
};

test_cross_data_t test1_data =
{
    .http_to_coap_desc = "Test  1: Convert a HTTP URI to a CoAP URI",
    .coap_to_http_desc = "Test  8: Convert a CoAP URI to a HTTP URI",
    .str = "coaps://host:1234/path?query",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = test1_coap_ops,
    .num_coap_ops = DIM(test1_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test2_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_URI_HOST,
        .len = 4,
        .val = "host"
    },
    [1] =
    {
        .num = COAP_MSG_URI_PORT,
        .len = 4,
        .val = "1234"
    },
    [2] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = 4,
        .val = "root"
    },
    [3] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = 4,
        .val = "path"
    },
    [4] =
    {
        .num = COAP_MSG_URI_QUERY,
        .len = 5,
        .val = "query"
    },
    [5] =
    {
        .num = COAP_MSG_URI_QUERY,
        .len = 5,
        .val = "extra"
    }
};

test_cross_data_t test2_data =
{
    .http_to_coap_desc = "Test  2: Convert a HTTP URI to a CoAP URI with two path options and two query options",
    .coap_to_http_desc = "Test  9: Convert a CoAP URI to a HTTP URI with two path options and two query options",
    .str = "coaps://host:1234/root/path?query&extra",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = test2_coap_ops,
    .num_coap_ops = DIM(test2_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_cross_data_t test3_data =
{
    .http_to_coap_desc = "Test  3: Convert a HTTP URI to a CoAP URI with no host, no port, no path, no query",
    .coap_to_http_desc = "Test 10: Convert a HTTP URI to a CoAP URI with no host, no port, no path, no query",
    .str = "coaps:/",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = NULL,
    .num_coap_ops = 0,
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test4_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_URI_HOST,
        .len = 4,
        .val = "host"
    }
};

test_cross_data_t test4_data =
{
    .http_to_coap_desc = "Test  4: Convert a HTTP URI to a CoAP URI with only a host",
    .coap_to_http_desc = "Test 11: Convert a CoAP URI to a HTTP URI with only a host",
    .str = "coaps://host/",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = test4_coap_ops,
    .num_coap_ops = DIM(test4_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test5_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_URI_PORT,
        .len = 4,
        .val = "1234"
    }
};

test_cross_data_t test5_data =
{
    .http_to_coap_desc = "Test  5: Convert a HTTP URI to a CoAP URI with only a port",
    .coap_to_http_desc = "Test 12: Convert a CoAP URI to a HTTP URI with only a port",
    .str = "coaps://:1234/",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = test5_coap_ops,
    .num_coap_ops = DIM(test5_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test6_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = 4,
        .val = "path"
    },

};

test_cross_data_t test6_data =
{
    .http_to_coap_desc = "Test  6: Convert a HTTP URI to a CoAP URI with only a path",
    .coap_to_http_desc = "Test 13: Convert a CoAP URI to a HTTP URI with only a path",
    .str = "coaps:/path",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = test6_coap_ops,
    .num_coap_ops = DIM(test6_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test7_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_URI_QUERY,
        .len = 5,
        .val = "query"
    }
};

test_cross_data_t test7_data =
{
    .http_to_coap_desc = "Test  7: Convert a HTTP URI to a CoAP URI with only a query option",
    .coap_to_http_desc = "Test 14: Convert a CoAP URI to a HTTP URI with only a query option",
    .str = "coaps:/?query",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = test7_coap_ops,
    .num_coap_ops = DIM(test7_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test8_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,
        .len = 6,
        .val = "abc123"
    },
    [1] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = 8,
        .val = "resource"
    },
    [2] =
    {
        .num = COAP_MSG_MAX_AGE,
        .len = 2,
        .val = "60"
    },
    [3] =
    {
        .num = COAP_MSG_ACCEPT,
        .len = 1,
        .val = "0"
    }
};

char test8_coap_payload[] = "body";

test_cross_data_t test8_data =
{
    .http_to_coap_desc = "Test 15: Convert a HTTP request message to a CoAP request message",
    .str = "GET coap:///resource HTTP/1.1\r\nContent-Length: 4\r\nEtag: abc123\r\nCache-Control: max-age=60\r\nAccept: text/plain\r\n\r\nbody",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = COAP_MSG_VER,
    .coap_type = CROSS_COAP_REQ_TYPE,
    .coap_code_class = COAP_MSG_REQ,
    .coap_code_detail = COAP_MSG_GET,
    .coap_ops = test8_coap_ops,
    .num_coap_ops = DIM(test8_coap_ops),
    .coap_payload = test8_coap_payload,
    .coap_payload_len = sizeof(test8_coap_payload) - 1,  /* -1 for the terminating '\0' */
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_cross_data_t test9_data =
{
    .http_to_coap_desc = "Test 16: Convert a HTTP request message with an unsupported method to a CoAP request message",
    .str = "CONNECT coap:///resource HTTP/1.1\r\n\r\n",
    .cross_ret = -EBADMSG,
    .cross_code = 501,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = NULL,
    .num_coap_ops = 0,
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_cross_data_t test10_data =
{
    .http_to_coap_desc = "Test 17: Convert a HTTP request message with an invalid URI to a CoAP request message",
    .str = "GET coap:///resource#fragment HTTP/1.1\r\n\r\n",
    .cross_ret = -EBADMSG,
    .cross_code = 400,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = NULL,
    .num_coap_ops = 0,
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_cross_data_t test11_data =
{
    .http_to_coap_desc = "Test 18: Convert a HTTP request message with an unacceptable content format to a CoAP request message",
    .str = "GET coap:///resource HTTP/1.1\r\nAccept: unsupported\r\n\r\n",
    .cross_ret = -EBADMSG,
    .cross_code = 406,
    .coap_ver = 0,
    .coap_type = 0,
    .coap_code_class = 0,
    .coap_code_detail = 0,
    .coap_ops = NULL,
    .num_coap_ops = 0,
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test12_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,
        .len = 6,
        .val = "abc123"
    },
    [1] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = 8,
        .val = "resource"
    },
    [2] =
    {
        .num = COAP_MSG_MAX_AGE,
        .len = 2,
        .val = "60"
    },
    [3] =
    {
        .num = COAP_MSG_ACCEPT,
        .len = 1,
        .val = "0"
    }
};

char test12_coap_body[] =
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
"1";

test_cross_data_t test12_data =
{
    .http_to_coap_desc = "Test 19: Convert a HTTP request message to a CoAP request message with a body",
    .str = "GET coap:///resource HTTP/1.1\r\nContent-Length: 1025\r\nEtag: abc123\r\nCache-Control: max-age=60\r\nAccept: text/plain\r\n\r\n" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" \
           "1",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = COAP_MSG_VER,
    .coap_type = CROSS_COAP_REQ_TYPE,
    .coap_code_class = COAP_MSG_REQ,
    .coap_code_detail = COAP_MSG_GET,
    .coap_ops = test12_coap_ops,
    .num_coap_ops = DIM(test12_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = test12_coap_body,
    .coap_body_len = sizeof(test12_coap_body) - 1,  /* -1 for the terminating '\0' */
    .coap_body_end = sizeof(test12_coap_body) - 1   /* -1 for the terminating '\0' */
};

test_coap_msg_op_t test13_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,
        .len = 6,
        .val = "abc123"
    },
    [1] =
    {
        .num = COAP_MSG_MAX_AGE,
        .len = 2,
        .val = "60"
    },
    [2] =
    {
        .num = COAP_MSG_ACCEPT,
        .len = 1,
        .val = "0"
    }
};

char test13_coap_payload[] = "body";

test_cross_data_t test13_data =
{
    .http_to_coap_desc = "Test 20: Convert a CoAP response message to a HTTP response message",
    .str = "HTTP/1.1 200 OK\r\nEtag: abc123\r\nCache-Control: max-age=60\r\nAccept: text/plain\r\nContent-Length: 4\r\n\r\nbody",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = COAP_MSG_VER,
    .coap_type = CROSS_COAP_REQ_TYPE,
    .coap_code_class = COAP_MSG_SUCCESS,
    .coap_code_detail = COAP_MSG_CONTENT,
    .coap_ops = test13_coap_ops,
    .num_coap_ops = DIM(test13_coap_ops),
    .coap_payload = test13_coap_payload,
    .coap_payload_len = sizeof(test13_coap_payload) - 1,  /* -1 for the terminating '\0' */
    .coap_body = NULL,
    .coap_body_len = 0,
    .coap_body_end = 0
};

test_coap_msg_op_t test14_coap_ops[] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,
        .len = 6,
        .val = "abc123"
    },
    [1] =
    {
        .num = COAP_MSG_MAX_AGE,
        .len = 2,
        .val = "60"
    },
    [2] =
    {
        .num = COAP_MSG_ACCEPT,
        .len = 1,
        .val = "0"
    }
};

char test14_coap_body[] = "body";

test_cross_data_t test14_data =
{
    .http_to_coap_desc = "Test 21: Convert a CoAP response message with a body to a HTTP response message",
    .str = "HTTP/1.1 200 OK\r\nEtag: abc123\r\nCache-Control: max-age=60\r\nAccept: text/plain\r\nContent-Length: 4\r\n\r\nbody",
    .cross_ret = 0,
    .cross_code = 0,
    .coap_ver = COAP_MSG_VER,
    .coap_type = CROSS_COAP_REQ_TYPE,
    .coap_code_class = COAP_MSG_SUCCESS,
    .coap_code_detail = COAP_MSG_CONTENT,
    .coap_ops = test14_coap_ops,
    .num_coap_ops = DIM(test14_coap_ops),
    .coap_payload = NULL,
    .coap_payload_len = 0,
    .coap_body = test14_coap_body,
    .coap_body_len = sizeof(test14_coap_body) - 1,  /* -1 for the terminating '\0' */
    .coap_body_end = sizeof(test14_coap_body) - 1   /* -1 for the terminating '\0' */
};

/**
 *  @brief Test the conversion from a HTTP URI to a CoAP URI
 *
 *  @param[in] data Pointer to a HTTP to CoAP test structure
 *
 *  @returns Test result
 */
test_result_t test_uri_http_to_coap_func(test_data_t data)
{
    test_cross_data_t *test_data = (test_cross_data_t *)data;
    test_result_t result = PASS;
    coap_msg_op_t *coap_op = NULL;
    coap_msg_t coap_msg = {0};
    unsigned i = 0;
    int ret = 0;

    printf("%s\n", test_data->http_to_coap_desc);

    coap_msg_create(&coap_msg);

    /* convert the HTTP URI to a CoAP URI */
    ret = cross_uri_http_to_coap(&coap_msg, test_data->str);
    if (ret != test_data->cross_ret)
    {
        result = FAIL;
    }
    if (test_data->cross_ret != 0)
    {
        coap_msg_destroy(&coap_msg);
        return result;
    }

    /* check the CoAP URI */
    coap_op = coap_msg_get_first_op(&coap_msg);
    for (i = 0; i < test_data->num_coap_ops; i++)
    {
        if (coap_op == NULL)
        {
            result = FAIL;
            break;
        }
        if (coap_msg_op_get_num(coap_op) != test_data->coap_ops[i].num)
        {
            result = FAIL;
        }
        if (coap_msg_op_get_len(coap_op) != test_data->coap_ops[i].len)
        {
            result = FAIL;
        }
        if (memcmp(coap_msg_op_get_val(coap_op), test_data->coap_ops[i].val, test_data->coap_ops[i].len) != 0)
        {
            result = FAIL;
        }
        coap_op = coap_msg_op_get_next(coap_op);
    }
    if (coap_op != NULL)
    {
        result = FAIL;
    }

    coap_msg_destroy(&coap_msg);
    return result;
}

/**
 *  @brief Test the conversion from a CoAP URI to a HTTP URI
 *
 *  @param[in] data Pointer to a HTTP to CoAP test structure
 *
 *  @returns Test result
 */
test_result_t test_uri_coap_to_http_func(test_data_t data)
{
    test_cross_data_t *test_data = (test_cross_data_t *)data;
    test_result_t result = PASS;
    coap_msg_t coap_msg = {0};
    unsigned i = 0;
    char buf[256] = {0};
    int ret = 0;

    printf("%s\n", test_data->coap_to_http_desc);

    coap_msg_create(&coap_msg);

    /* add the options to the CoAP message */
    for (i = 0; i < test_data->num_coap_ops; i++)
    {
        ret = coap_msg_add_op(&coap_msg,
                              test_data->coap_ops[i].num,
                              test_data->coap_ops[i].len,
                              test_data->coap_ops[i].val);
        if (ret != 0)
        {
            coap_msg_destroy(&coap_msg);
            return FAIL;
        }
    }

    /* convert the COAP URI to a HTTP URI */
    ret = cross_uri_coap_to_http(buf, sizeof(buf), &coap_msg);
    if (ret != test_data->cross_ret)
    {
        result = FAIL;
    }
    if (test_data->cross_ret != 0)
    {
        coap_msg_destroy(&coap_msg);
        return result;
    }

    /* check the HTTP URI */
    if (strcmp(buf, test_data->str) != 0)
    {
        result = FAIL;
    }

    coap_msg_destroy(&coap_msg);
    return result;
}

/**
 *  @brief Test the conversion from a HTTP message to a CoAP message
 *
 *  @param[in] data Pointer to a HTTP to CoAP test structure
 *
 *  @returns Test result
 */
test_result_t test_msg_http_to_coap_func(test_data_t data)
{
    test_cross_data_t *test_data = (test_cross_data_t *)data;
    test_result_t result = PASS;
    coap_msg_op_t *coap_op = NULL;
    http_msg_t http_msg = {{0}};
    coap_msg_t coap_msg = {0};
    unsigned code = 0;
    unsigned i = 0;
    ssize_t num = 0;
    size_t coap_body_end = 0;
    char coap_body[test_data->coap_body_len];
    int ret = 0;

    printf("%s\n", test_data->http_to_coap_desc);

    http_msg_create(&http_msg);

    /* parse the HTTP message */
    num = http_msg_parse(&http_msg, test_data->str, strlen(test_data->str));
    if (num != strlen(test_data->str))
    {
        http_msg_destroy(&http_msg);
        return FAIL;
    }

    coap_msg_create(&coap_msg);

    /* convert the HTTP message to a CoAP message */
    ret = cross_req_http_to_coap(&coap_msg, coap_body, sizeof(coap_body), &coap_body_end, &http_msg, &code);
    if (ret != test_data->cross_ret)
    {
        result = FAIL;
    }
    if (code != test_data->cross_code)
    {
        result = FAIL;
    }
    if (test_data->cross_ret != 0)
    {
        coap_msg_destroy(&coap_msg);
        http_msg_destroy(&http_msg);
        return result;
    }

    /* check the CoAP message */
    if (coap_msg.ver != test_data->coap_ver)
    {
        result = FAIL;
    }
    if (coap_msg.type != test_data->coap_type)
    {
        result = FAIL;
    }
    if (coap_msg.code_class != test_data->coap_code_class)
    {
        result = FAIL;
    }
    if (coap_msg.code_detail != test_data->coap_code_detail)
    {
        result = FAIL;
    }
    coap_op = coap_msg_get_first_op(&coap_msg);
    for (i = 0; i < test_data->num_coap_ops; i++)
    {
        if (coap_op == NULL)
        {
            result = FAIL;
            break;
        }
        if (coap_msg_op_get_num(coap_op) != test_data->coap_ops[i].num)
        {
            result = FAIL;
        }
        if (coap_msg_op_get_len(coap_op) != test_data->coap_ops[i].len)
        {
            result = FAIL;
        }
        if (memcmp(coap_msg_op_get_val(coap_op), test_data->coap_ops[i].val, test_data->coap_ops[i].len) != 0)
        {
            result = FAIL;
        }
        coap_op = coap_msg_op_get_next(coap_op);
    }
    if (coap_op != NULL)
    {
        result = FAIL;
    }
    if (test_data->coap_payload != NULL)
    {
        if ((coap_msg.payload == NULL)
         || (memcmp(coap_msg.payload, test_data->coap_payload, test_data->coap_payload_len) != 0))
        {
            result = FAIL;
        }
    }
    else
    {
        if (coap_msg.payload != NULL)
        {
            result = FAIL;
        }
    }
    if (coap_msg.payload_len != test_data->coap_payload_len)
    {
        result = FAIL;
    }
    if (test_data->coap_body != NULL)
    {
        if (memcmp(coap_body, test_data->coap_body, test_data->coap_body_end) != 0)
        {
            result = FAIL;
        }
    }
    if (coap_body_end != test_data->coap_body_end)
    {
        result = FAIL;
    }
    coap_msg_destroy(&coap_msg);
    http_msg_destroy(&http_msg);
    return result;
}

/**
 *  @brief Test the conversion from a CoAP message to a HTTP message
 *
 *  @param[in] data Pointer to a CoAP to HTTP test structure
 *
 *  @returns Test result
 */
test_result_t test_msg_coap_to_http_func(test_data_t data)
{
    test_cross_data_t *test_data = (test_cross_data_t *)data;
    test_result_t result = PASS;
    http_msg_t http_msg = {{0}};
    coap_msg_t coap_msg = {0};
    unsigned code = 0;
    unsigned i = 0;
    char buf[256] = {0};
    int ret = 0;

    printf("%s\n", test_data->http_to_coap_desc);

    coap_msg_create(&coap_msg);
    ret = coap_msg_set_type(&coap_msg, test_data->coap_type);
    if (ret < 0)
    {
        coap_msg_destroy(&coap_msg);
        return FAIL;
    }
    ret = coap_msg_set_code(&coap_msg, test_data->coap_code_class, test_data->coap_code_detail);
    if (ret < 0)
    {
        coap_msg_destroy(&coap_msg);
        return FAIL;
    }
    for (i = 0; i < test_data->num_coap_ops; i++)
    {
        ret = coap_msg_add_op(&coap_msg, test_data->coap_ops[i].num, test_data->coap_ops[i].len, test_data->coap_ops[i].val);
        if (ret < 0)
        {
            coap_msg_destroy(&coap_msg);
            return FAIL;
        }
    }
    if (test_data->coap_payload != NULL)
    {
        ret = coap_msg_set_payload(&coap_msg, test_data->coap_payload, test_data->coap_payload_len);
        if (ret < 0)
        {
            coap_msg_destroy(&coap_msg);
            return FAIL;
        }
    }

    http_msg_create(&http_msg);

    ret = cross_resp_coap_to_http(&http_msg, &coap_msg, test_data->coap_body, test_data->coap_body_end, &code);
    if (ret != test_data->cross_ret)
    {
        result = FAIL;
    }
    if (test_data->cross_code != code)
    {
        result = FAIL;
    }
    if (test_data->cross_ret != 0)
    {
        result = FAIL;
    }
    http_msg_generate(&http_msg, buf, sizeof(buf));
    if (strcmp(buf, test_data->str) != 0)
    {
        result = FAIL;
    }

    http_msg_destroy(&http_msg);
    coap_msg_destroy(&coap_msg);
    return result;
}

/**
 *  @brief Main function for the FreeCoAP HTTP/COAP message/URI cross library unit tests
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(void)
{
    test_t tests[] = {{test_uri_http_to_coap_func, &test1_data},
                      {test_uri_http_to_coap_func, &test2_data},
                      {test_uri_http_to_coap_func, &test3_data},
                      {test_uri_http_to_coap_func, &test4_data},
                      {test_uri_http_to_coap_func, &test5_data},
                      {test_uri_http_to_coap_func, &test6_data},
                      {test_uri_http_to_coap_func, &test7_data},
                      {test_uri_coap_to_http_func, &test1_data},
                      {test_uri_coap_to_http_func, &test2_data},
                      {test_uri_coap_to_http_func, &test3_data},
                      {test_uri_coap_to_http_func, &test4_data},
                      {test_uri_coap_to_http_func, &test5_data},
                      {test_uri_coap_to_http_func, &test6_data},
                      {test_uri_coap_to_http_func, &test7_data},
                      {test_msg_http_to_coap_func, &test8_data},
                      {test_msg_http_to_coap_func, &test9_data},
                      {test_msg_http_to_coap_func, &test10_data},
                      {test_msg_http_to_coap_func, &test11_data},
                      {test_msg_http_to_coap_func, &test12_data},
                      {test_msg_coap_to_http_func, &test13_data},
                      {test_msg_coap_to_http_func, &test14_data}};

    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;
    int ret = 0;

    coap_log_set_level(COAP_LOG_ERROR);
    ret = coap_mem_all_create(SMALL_BUF_NUM, SMALL_BUF_LEN,
                              MEDIUM_BUF_NUM, MEDIUM_BUF_LEN,
                              LARGE_BUF_NUM, LARGE_BUF_LEN);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return EXIT_FAILURE;
    }
    num_pass = test_run(tests, num_tests);
    coap_mem_all_destroy();
    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
