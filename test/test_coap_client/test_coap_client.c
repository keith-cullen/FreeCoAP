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
 *  @file test_coap_client.c
 *
 *  @brief Source file for the FreeCoAP client test application
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "coap_client.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"
#include "test.h"

#ifdef COAP_IP6
#define HOST                                "::1"                               /**< Host address of the server */
#else
#define HOST                                "127.0.0.1"                         /**< Host address of the server */
#endif
#define PORT                                "12436"                             /**< UDP port number of the server */
#define TRUST_FILE_NAME                     "../../certs/root_server_cert.pem"  /**< DTLS trust file name */
#define CERT_FILE_NAME                      "../../certs/client_cert.pem"       /**< DTLS certificate file name */
#define KEY_FILE_NAME                       "../../certs/client_privkey.pem"    /**< DTLS key file name */
#define CRL_FILE_NAME                       ""                                  /**< DTLS certificate revocation list file name */
#define COMMON_NAME                         "dummy/server"                      /**< Common name of the server */
#define RESET_URI_PATH                      "reset"                             /**< URI path that causes the server to reset buffers */
#define RESET_URI_PATH_LEN                  5                                   /**< Length of the URI path that causes the server to reset buffers */
#define SEP_URI_PATH1                       "sep"                               /**< First URI path option value required to trigger a separate response from the server */
#define SEP_URI_PATH1_LEN                   3                                   /**< Length of the first URI path option value required to trigger a separate response from the server */
#define SEP_URI_PATH2                       "uri"                               /**< Second URI path option value required to trigger a separate response from the server */
#define SEP_URI_PATH2_LEN                   3                                   /**< Length of the second URI path option value required to trigger a separate response from the server */
#define SEP_URI_PATH3                       "path"                              /**< Third URI path option value required to trigger a separate response from the server */
#define SEP_URI_PATH3_LEN                   4                                   /**< Length of the third URI path option value required to trigger a separate response from the server */
#define REGULAR_URI_PATH                    "regular"                           /**< URI path that causes the server to use regular (i.e. non-blockwise) transfers */
#define REGULAR_URI_PATH_LEN                7                                   /**< Length of the URI path that causes the server to use regular (i.e. non-blockwise) transfers */
#define APP_LEVEL_BLOCKWISE_URI_PATH        "app-level-blockwise"               /**< URI path that causes the server to use application-level blockwise transfers */
#define APP_LEVEL_BLOCKWISE_URI_PATH_LEN    19                                  /**< Length of the URI path that causes the server to use application-level blockwise transfers */
#define LIB_LEVEL_BLOCKWISE_URI_PATH        "lib-level-blockwise"               /**< URI path that causes the server to use library-level blockwise transfers */
#define LIB_LEVEL_BLOCKWISE_URI_PATH_LEN    19                                  /**< Length of the URI path that causes the server to use library-level blockwise transfers */
#define BLOCK_SIZE                          16                                  /**< Size of an individual block in a blockwise transfer */
#define SMALL_BUF_NUM                       128                                 /**< Number of buffers in the small memory allocator */
#define SMALL_BUF_LEN                       256                                 /**< Length of each buffer in the small memory allocator */
#define MEDIUM_BUF_NUM                      128                                 /**< Number of buffers in the medium memory allocator */
#define MEDIUM_BUF_LEN                      1024                                /**< Length of each buffer in the medium memory allocator */
#define LARGE_BUF_NUM                       32                                  /**< Number of buffers in the large memory allocator */
#define LARGE_BUF_LEN                       8192                                /**< Length of each buffer in the large memory allocator */

/**
 *  @brief Message option test data structure
 */
typedef struct
{
    unsigned num;                                                               /**< Option number */
    unsigned len;                                                               /**< Option length */
    char *val;                                                                  /**< Pointer to a buffer containing the option value */
}
test_coap_client_msg_op_t;

/**
 *  @brief Client test message data structure
 */
typedef struct
{
    coap_msg_type_t type;                                                       /**< Message type */
    unsigned code_class;                                                        /**< Message code class */
    unsigned code_detail;                                                       /**< Message code detail */
    test_coap_client_msg_op_t *ops;                                             /**< Array of message option test data structures */
    unsigned num_ops;                                                           /**< Size of the array of message option test data structures */
    char *payload;                                                              /**< Buffer containing the payload */
    size_t payload_len;                                                         /**< Length of the buffer containing the payload */
    unsigned block1_size;                                                       /**< Size value for the block1 option */
    unsigned block2_size;                                                       /**< Size value for the block2 option */
    size_t body_end;                                                            /**< Amount of relevant data in the buffer to store the body */
}
test_coap_client_msg_t;

/**
 *  @brief Client test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    const char *host;                                                           /**< Server host address */
    const char *port;                                                           /**< Server UDP port */
    const char *key_file_name;                                                  /**< DTLS key file name */
    const char *cert_file_name;                                                 /**< DTLS certificate file name */
    const char *trust_file_name;                                                /**< DTLS trust file name */
    const char *crl_file_name;                                                  /**< DTLS certificate revocation list file name */
    const char *common_name;                                                    /**< Common name of the server */
    test_coap_client_msg_t *test_req;                                           /**< Array of test request message structures */
    test_coap_client_msg_t *test_resp;                                          /**< Array of test response message structures */
    size_t num_msg;                                                             /**< Length of the arrays of test message structures */
    const char *body;                                                           /**< Buffers to store the body */
    size_t body_len;                                                            /**< Length of the buffer to store the body */
}
test_coap_client_data_t;

#define TEST1_NUM_MSG      1
#define TEST1_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST1_NUM_OPS      1

char test1_req_op1_val[TEST1_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;

test_coap_client_msg_op_t test1_req_ops[TEST1_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST1_REQ_OP1_LEN,
        .val = test1_req_op1_val
    }
};

test_coap_client_msg_t test1_req[TEST1_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test1_req_ops,
        .num_ops = TEST1_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test1_resp[TEST1_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test1_data =
{
    .desc = "test 1: send a confirmable GET request and expect a piggy-backed response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test1_req,
    .test_resp = test1_resp,
    .num_msg = TEST1_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST2_NUM_MSG      1
#define TEST2_REQ_OP1_LEN  SEP_URI_PATH1_LEN
#define TEST2_REQ_OP2_LEN  SEP_URI_PATH2_LEN
#define TEST2_REQ_OP3_LEN  SEP_URI_PATH3_LEN
#define TEST2_NUM_OPS      3

char test2_req_op1_val[TEST2_REQ_OP1_LEN + 1] = SEP_URI_PATH1;
char test2_req_op2_val[TEST2_REQ_OP2_LEN + 1] = SEP_URI_PATH2;
char test2_req_op3_val[TEST2_REQ_OP3_LEN + 1] = SEP_URI_PATH3;

test_coap_client_msg_op_t test2_req_ops[TEST2_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST2_REQ_OP1_LEN,
        .val = test2_req_op1_val
    },
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST2_REQ_OP2_LEN,
        .val = test2_req_op2_val
    },
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST2_REQ_OP3_LEN,
        .val = test2_req_op3_val
    }
};

test_coap_client_msg_t test2_req[TEST2_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test2_req_ops,
        .num_ops = TEST2_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test2_resp[TEST2_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test2_data =
{
    .desc = "test 2: send a confirmable GET request and expect a separate response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test2_req,
    .test_resp = test2_resp,
    .num_msg = TEST2_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST3_NUM_MSG      1
#define TEST3_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST3_NUM_OPS      1

char test3_req_op1_val[TEST3_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;

test_coap_client_msg_op_t test3_req_ops[TEST3_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST3_REQ_OP1_LEN,
        .val = test3_req_op1_val
    }
};

test_coap_client_msg_t test3_req[TEST3_NUM_MSG] =
{
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test3_req_ops,
        .num_ops = TEST3_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test3_resp[TEST3_NUM_MSG] =
{
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test3_data =
{
    .desc = "test 3: send a non-confirmable GET request",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test3_req,
    .test_resp = test3_resp,
    .num_msg = TEST3_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST4_NUM_MSG      2
#define TEST4_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST4_NUM_OPS      1

char test4_req_op1_val[TEST4_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;

test_coap_client_msg_op_t test4_req_ops[TEST4_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST4_REQ_OP1_LEN,
        .val = test4_req_op1_val
    }
};

test_coap_client_msg_t test4_req[TEST4_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test4_req_ops,
        .num_ops = TEST4_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test4_req_ops,
        .num_ops = TEST4_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test4_resp[TEST4_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test4_data =
{
    .desc = "test 4: send two confirmable GET requests and expect piggy-backed responses",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test4_req,
    .test_resp = test4_resp,
    .num_msg = TEST4_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST5_NUM_MSG      2
#define TEST5_REQ_OP1_LEN  SEP_URI_PATH1_LEN
#define TEST5_REQ_OP2_LEN  SEP_URI_PATH2_LEN
#define TEST5_REQ_OP3_LEN  SEP_URI_PATH3_LEN
#define TEST5_NUM_OPS      3

char test5_req_op1_val[TEST5_REQ_OP1_LEN + 1] = SEP_URI_PATH1;
char test5_req_op2_val[TEST5_REQ_OP2_LEN + 1] = SEP_URI_PATH2;
char test5_req_op3_val[TEST5_REQ_OP3_LEN + 1] = SEP_URI_PATH3;

test_coap_client_msg_op_t test5_req_ops[TEST5_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST5_REQ_OP1_LEN,
        .val = test5_req_op1_val
    },
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST5_REQ_OP2_LEN,
        .val = test5_req_op2_val
    },
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST5_REQ_OP3_LEN,
        .val = test5_req_op3_val
    }
};

test_coap_client_msg_t test5_req[TEST5_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test5_req_ops,
        .num_ops = TEST5_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test5_req_ops,
        .num_ops = TEST5_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test5_resp[TEST5_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test5_data =
{
    .desc = "test 5: send two confirmable GET requests and expect separate responses",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test5_req,
    .test_resp = test5_resp,
    .num_msg = TEST5_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST6_NUM_MSG      2
#define TEST6_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST6_NUM_OPS      1

char test6_req_op1_val[TEST6_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;

test_coap_client_msg_op_t test6_req_ops[TEST6_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST6_REQ_OP1_LEN,
        .val = test6_req_op1_val
    }
};

test_coap_client_msg_t test6_req[TEST6_NUM_MSG] =
{
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test6_req_ops,
        .num_ops = TEST6_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test6_req_ops,
        .num_ops = TEST6_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test6_resp[TEST6_NUM_MSG] =
{
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "qwertyuiopasdfgh",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test6_data =
{
    .desc = "test 6: send two non-confirmable GET requests",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test6_req,
    .test_resp = test6_resp,
    .num_msg = TEST6_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST7_NUM_MSG      1
#define TEST7_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST7_REQ_OP2_LEN  1
#define TEST7_NUM_OPS      2

char test7_req_op1_val[TEST7_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;
char test7_req_op2_val[TEST7_REQ_OP2_LEN + 1] = "x";

test_coap_client_msg_op_t test7_req_ops[TEST7_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST7_REQ_OP1_LEN,
        .val = test7_req_op1_val
    },
    {
        .num = 0x61,  /* unrecognised critical option */
        .len = TEST7_REQ_OP1_LEN,
        .val = test7_req_op1_val
    }
};

test_coap_client_msg_t test7_req[TEST7_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test7_req_ops,
        .num_ops = TEST7_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test7_resp[TEST7_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_CLIENT_ERR,
        .code_detail = COAP_MSG_BAD_OPTION,
        .ops = NULL,
        .num_ops = 0,
        .payload = "Bad option number: 97",
        .payload_len = 21,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test7_data =
{
    .desc = "test 7: send a confirmable GET request and expect a bad option response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test7_req,
    .test_resp = test7_resp,
    .num_msg = TEST7_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST8_NUM_MSG      2
#define TEST8_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST8_NUM_OPS      1

char test8_req_op1_val[TEST8_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;

test_coap_client_msg_op_t test8_req_ops[TEST8_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST8_REQ_OP1_LEN,
        .val = test8_req_op1_val
    }
};

test_coap_client_msg_t test8_req[TEST8_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test8_req_ops,
        .num_ops = TEST8_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test8_req_ops,
        .num_ops = TEST8_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test8_resp[TEST8_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = NULL,
        .num_ops = 0,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test8_data =
{
    .desc = "test 8: send a confirmable PUT request followed by a confirmable GET request and expect piggy-backed responses",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test8_req,
    .test_resp = test8_resp,
    .num_msg = TEST8_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST9_NUM_MSG      2
#define TEST9_REQ_OP1_LEN  REGULAR_URI_PATH_LEN
#define TEST9_NUM_OPS      1

char test9_req_op1_val[TEST9_REQ_OP1_LEN + 1] = REGULAR_URI_PATH;

test_coap_client_msg_op_t test9_req_ops[TEST9_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST9_REQ_OP1_LEN,
        .val = test9_req_op1_val
    }
};

test_coap_client_msg_t test9_req[TEST9_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_POST,
        .ops = test9_req_ops,
        .num_ops = TEST9_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test9_req_ops,
        .num_ops = TEST9_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test9_resp[TEST9_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = NULL,
        .num_ops = 0,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test9_data =
{
    .desc = "test 9: send a confirmable POST request followed by a confirmable GET request and expect piggy-backed responses",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test9_req,
    .test_resp = test9_resp,
    .num_msg = TEST9_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST10_NUM_MSG       6
#define TEST10_REQ_OP1_LEN   APP_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST10_REQ_OP2_LEN   3
#define TEST10_REQ_OP3_LEN   3
#define TEST10_REQ_OP4_LEN   3
#define TEST10_REQ_OP5_LEN   3
#define TEST10_REQ_OP6_LEN   3
#define TEST10_REQ_NUM_OPS1  2
#define TEST10_REQ_NUM_OPS2  2
#define TEST10_REQ_NUM_OPS3  2
#define TEST10_REQ_NUM_OPS4  1
#define TEST10_REQ_NUM_OPS5  2
#define TEST10_REQ_NUM_OPS6  2
#define TEST10_RESP_OP_LEN   3
#define TEST10_RESP_NUM_OPS  1

char test10_req_op1_val[TEST10_REQ_OP1_LEN + 1] = APP_LEVEL_BLOCKWISE_URI_PATH;
char test10_req_op2_val[TEST10_REQ_OP2_LEN] =  {0x00, 0x00, 0x08};  /* PUT num: 0, more: 1, size: 16 */
char test10_req_op3_val[TEST10_REQ_OP3_LEN] =  {0x00, 0x00, 0x18};  /* PUT num: 1, more: 1, size: 16 */
char test10_req_op4_val[TEST10_REQ_OP4_LEN] =  {0x00, 0x00, 0x20};  /* PUT num: 2, more: 0, size: 16 */
char test10_req_op5_val[TEST10_REQ_OP5_LEN] =  {0x00, 0x00, 0x10};  /* GET num: 1, more: 0, size: 16 */
char test10_req_op6_val[TEST10_REQ_OP6_LEN] =  {0x00, 0x00, 0x20};  /* GET num: 2, more: 0, size: 16 */

char test10_resp_op1_val[TEST10_RESP_OP_LEN] =  {0x00, 0x00, 0x00};  /* PUT num: 0, more: 0, size: 16 */
char test10_resp_op2_val[TEST10_RESP_OP_LEN] =  {0x00, 0x00, 0x10};  /* PUT num: 1, more: 0, size: 16 */
char test10_resp_op3_val[TEST10_RESP_OP_LEN] =  {0x00, 0x00, 0x20};  /* PUT num: 2, more: 0, size: 16 */
char test10_resp_op4_val[TEST10_RESP_OP_LEN] =  {0x00, 0x00, 0x08};  /* GET num: 0, more: 1, size: 16 */
char test10_resp_op5_val[TEST10_RESP_OP_LEN] =  {0x00, 0x00, 0x18};  /* GET num: 1, more: 1, size: 16 */
char test10_resp_op6_val[TEST10_RESP_OP_LEN] =  {0x00, 0x00, 0x20};  /* GET num: 2, more: 0, size: 16 */

test_coap_client_msg_op_t test10_req_ops1[TEST10_REQ_NUM_OPS1] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST10_REQ_OP1_LEN,
        .val = test10_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST10_REQ_OP2_LEN,
        .val = test10_req_op2_val
    }
};

test_coap_client_msg_op_t test10_req_ops2[TEST10_REQ_NUM_OPS2] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST10_REQ_OP1_LEN,
        .val = test10_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST10_REQ_OP3_LEN,
        .val = test10_req_op3_val
    }
};

test_coap_client_msg_op_t test10_req_ops3[TEST10_REQ_NUM_OPS3] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST10_REQ_OP1_LEN,
        .val = test10_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST10_REQ_OP4_LEN,
        .val = test10_req_op4_val
    }
};

test_coap_client_msg_op_t test10_req_ops4[TEST10_REQ_NUM_OPS4] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST10_REQ_OP1_LEN,
        .val = test10_req_op1_val
    }
};

test_coap_client_msg_op_t test10_req_ops5[TEST10_REQ_NUM_OPS5] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST10_REQ_OP1_LEN,
        .val = test10_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST10_REQ_OP5_LEN,
        .val = test10_req_op5_val
    }
};

test_coap_client_msg_op_t test10_req_ops6[TEST10_REQ_NUM_OPS6] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST10_REQ_OP1_LEN,
        .val = test10_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST10_REQ_OP6_LEN,
        .val = test10_req_op6_val
    }
};

test_coap_client_msg_op_t test10_resp_ops1[TEST10_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST10_RESP_OP_LEN,
        .val = test10_resp_op1_val
    }
};

test_coap_client_msg_op_t test10_resp_ops2[TEST10_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST10_RESP_OP_LEN,
        .val = test10_resp_op2_val
    }
};

test_coap_client_msg_op_t test10_resp_ops3[TEST10_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST10_RESP_OP_LEN,
        .val = test10_resp_op3_val
    }
};

test_coap_client_msg_op_t test10_resp_ops4[TEST10_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST10_RESP_OP_LEN,
        .val = test10_resp_op4_val
    }
};

test_coap_client_msg_op_t test10_resp_ops5[TEST10_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST10_RESP_OP_LEN,
        .val = test10_resp_op5_val
    }
};

test_coap_client_msg_op_t test10_resp_ops6[TEST10_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST10_RESP_OP_LEN,
        .val = test10_resp_op6_val
    }
};

test_coap_client_msg_t test10_req[TEST10_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test10_req_ops1,
        .num_ops = TEST10_REQ_NUM_OPS1,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test10_req_ops2,
        .num_ops = TEST10_REQ_NUM_OPS2,
        .payload = "ghijklmnopqrstuv",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test10_req_ops3,
        .num_ops = TEST10_REQ_NUM_OPS3,
        .payload = "wzyx.!?#",
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test10_req_ops4,
        .num_ops = TEST10_REQ_NUM_OPS4,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test10_req_ops5,
        .num_ops = TEST10_REQ_NUM_OPS5,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test10_req_ops6,
        .num_ops = TEST10_REQ_NUM_OPS6,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test10_resp[TEST10_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = test10_resp_ops1,
        .num_ops = TEST10_RESP_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = test10_resp_ops2,
        .num_ops = TEST10_RESP_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = test10_resp_ops3,
        .num_ops = TEST10_RESP_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test10_resp_ops4,
        .num_ops = TEST10_RESP_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test10_resp_ops5,
        .num_ops = TEST10_RESP_NUM_OPS,
        .payload = "ghijklmnopqrstuv",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test10_resp_ops6,
        .num_ops = TEST10_RESP_NUM_OPS,
        .payload = "wzyx.!?#",
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test10_data =
{
    .desc = "test 10: send three application-level blockwise PUT requests and three application-level blockwise GET requests",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test10_req,
    .test_resp = test10_resp,
    .num_msg = TEST10_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

#define TEST11_NUM_MSG       1
#define TEST11_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST11_NUM_REQ_OPS   1
#define TEST11_RESP_OP1_LEN  3
#define TEST11_NUM_RESP_OPS  1
#define TEST11_BODY_LEN      72

char test11_req_op1_val[TEST11_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test11_resp_op1_val[TEST11_RESP_OP1_LEN] =  {0x00, 0x00, 0x40};  /* num: 4, more: 0, size: 16 */

test_coap_client_msg_op_t test11_req_ops[TEST11_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST11_REQ_OP1_LEN,
        .val = test11_req_op1_val
    }
};

test_coap_client_msg_op_t test11_resp_ops[TEST11_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST11_RESP_OP1_LEN,
        .val = test11_resp_op1_val
    }
};

test_coap_client_msg_t test11_req[TEST11_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test11_req_ops,
        .num_ops = TEST11_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 16,
        .block2_size = 16,
        .body_end = 0
    }
};

test_coap_client_msg_t test11_resp[TEST11_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test11_resp_ops,
        .num_ops = TEST11_NUM_RESP_OPS,
        .payload = "vntfbghq",  /* partial last block */
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = TEST11_BODY_LEN
    }
};

test_coap_client_data_t test11_data =
{
    .desc = "test 11: perform a GET library-level blockwise transfer in which the client has the smaller block2 size-exponent value",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test11_req,
    .test_resp = test11_resp,
    .num_msg = TEST11_NUM_MSG,
    .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq",
    .body_len = TEST11_BODY_LEN
};

#define TEST12_NUM_MSG       1
#define TEST12_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST12_NUM_REQ_OPS   1
#define TEST12_RESP_OP1_LEN  3
#define TEST12_NUM_RESP_OPS  1
#define TEST12_BODY_LEN      72

char test12_req_op1_val[TEST12_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test12_resp_op1_val[TEST12_RESP_OP1_LEN] =  {0x00, 0x00, 0x21};  /* num: 2, more: 0, size: 32 */

test_coap_client_msg_op_t test12_req_ops[TEST12_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST12_REQ_OP1_LEN,
        .val = test12_req_op1_val
    }
};

test_coap_client_msg_op_t test12_resp_ops[TEST12_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST12_RESP_OP1_LEN,
        .val = test12_resp_op1_val
    }
};

test_coap_client_msg_t test12_req[TEST12_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test12_req_ops,
        .num_ops = TEST12_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 64,
        .block2_size = 64,
        .body_end = 0
    }
};

test_coap_client_msg_t test12_resp[TEST12_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test12_resp_ops,
        .num_ops = TEST12_NUM_RESP_OPS,
        .payload = "vntfbghq",  /* partial last block */
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = TEST12_BODY_LEN
    }
};

test_coap_client_data_t test12_data =
{
    .desc = "test 12: perform a GET library-level blockwise transfer in which the server has the smaller block2 size-exponent value",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test12_req,
    .test_resp = test12_resp,
    .num_msg = TEST12_NUM_MSG,
    .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq",
    .body_len = TEST12_BODY_LEN
};

#define TEST13_NUM_MSG       1
#define TEST13_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST13_NUM_REQ_OPS   1
#define TEST13_RESP_OP1_LEN  3
#define TEST13_NUM_RESP_OPS  1
#define TEST13_BODY_LEN      72

char test13_req_op1_val[TEST13_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test13_resp_op1_val[TEST13_RESP_OP1_LEN] =  {0x00, 0x00, 0x21};  /* num: 2, more: 0, size: 32 */

test_coap_client_msg_op_t test13_req_ops[TEST13_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST13_REQ_OP1_LEN,
        .val = test13_req_op1_val
    }
};

test_coap_client_msg_op_t test13_resp_ops[TEST13_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST13_RESP_OP1_LEN,
        .val = test13_resp_op1_val
    }
};

test_coap_client_msg_t test13_req[TEST13_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test13_req_ops,
        .num_ops = TEST13_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 32,
        .block2_size = 32,
        .body_end = 0
    }
};

test_coap_client_msg_t test13_resp[TEST13_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test13_resp_ops,
        .num_ops = TEST13_NUM_RESP_OPS,
        .payload = "vntfbghq",  /* partial last block */
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = TEST13_BODY_LEN
    }
};

test_coap_client_data_t test13_data =
{
    .desc = "test 13: perform a GET library-level blockwise transfer initiated by the server",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test13_req,
    .test_resp = test13_resp,
    .num_msg = TEST13_NUM_MSG,
    .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq",
    .body_len = TEST13_BODY_LEN
};

#define TEST14_NUM_MSG       2
#define TEST14_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST14_NUM_REQ_OPS   1
#define TEST14_RESP_OP1_LEN  3
#define TEST14_NUM_RESP_OPS  1
#define TEST14_BODY_LEN      72

char test14_req_op1_val[TEST14_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test14_resp_op1_val[TEST14_RESP_OP1_LEN] =  {0x00, 0x00, 0x40};  /* num: 2, more: 0, size: 16 */

test_coap_client_msg_op_t test14_req_ops[TEST14_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST14_REQ_OP1_LEN,
        .val = test14_req_op1_val
    }
};

test_coap_client_msg_op_t test14_resp_ops1[TEST14_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST14_RESP_OP1_LEN,
        .val = test14_resp_op1_val
    }
};

test_coap_client_msg_op_t test14_resp_ops2[TEST14_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST14_RESP_OP1_LEN,
        .val = test14_resp_op1_val
    }
};

test_coap_client_msg_t test14_req[TEST14_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test14_req_ops,
        .num_ops = TEST14_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 16,
        .block2_size = 16,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test14_req_ops,
        .num_ops = TEST14_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 16,
        .block2_size = 16,
        .body_end = 0
    }
};

test_coap_client_msg_t test14_resp[TEST14_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = test14_resp_ops1,
        .num_ops = TEST14_NUM_RESP_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test14_resp_ops2,
        .num_ops = TEST14_NUM_RESP_OPS,
        .payload = "vntfbghq",  /* partial last block */
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = TEST14_BODY_LEN
    }
};

test_coap_client_data_t test14_data =
{
    .desc = "test 14: perform PUT and GET library-level blockwise transfers in which the client has the smaller block1 and block2 size-exponent values",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test14_req,
    .test_resp = test14_resp,
    .num_msg = TEST14_NUM_MSG,
    .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq",
    .body_len = TEST14_BODY_LEN
};

#define TEST15_NUM_MSG       2
#define TEST15_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST15_NUM_REQ_OPS   1
#define TEST15_RESP_OP1_LEN  3
#define TEST15_NUM_RESP_OPS  1
#define TEST15_BODY_LEN      72

char test15_req_op1_val[TEST15_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test15_resp_op1_val[TEST15_RESP_OP1_LEN] =  {0x00, 0x00, 0x21};  /* num: 2, more: 0, size: 32 */

test_coap_client_msg_op_t test15_req_ops[TEST15_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST15_REQ_OP1_LEN,
        .val = test15_req_op1_val
    }
};

test_coap_client_msg_op_t test15_resp_ops1[TEST15_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST15_RESP_OP1_LEN,
        .val = test15_resp_op1_val
    }
};

test_coap_client_msg_op_t test15_resp_ops2[TEST15_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST15_RESP_OP1_LEN,
        .val = test15_resp_op1_val
    }
};

test_coap_client_msg_t test15_req[TEST15_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test15_req_ops,
        .num_ops = TEST15_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 64,
        .block2_size = 64,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test15_req_ops,
        .num_ops = TEST15_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 64,
        .block2_size = 64,
        .body_end = 0
    }
};

test_coap_client_msg_t test15_resp[TEST15_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = test15_resp_ops1,
        .num_ops = TEST15_NUM_RESP_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = test15_resp_ops2,
        .num_ops = TEST15_NUM_RESP_OPS,
        .payload = "dkfsgj12",  /* partial last block */
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = TEST15_BODY_LEN
    }
};

test_coap_client_data_t test15_data =
{
    .desc = "test 15: perform PUT and GET library-level blockwise transfers in which the server has the smaller block1 and block2 size-exponent values",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test15_req,
    .test_resp = test15_resp,
    .num_msg = TEST15_NUM_MSG,
    .body = "jgortinoinsfwvdeuwneriuu86ldkfjglkdjg954pdfgjoeisrjgoisrjglkdjgldkfsgj12",
    .body_len = TEST15_BODY_LEN
};

#define TEST16_NUM_MSG       1
#define TEST16_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST16_NUM_REQ_OPS   1
#define TEST16_RESP_OP1_LEN  3
#define TEST16_NUM_RESP_OPS  1
#define TEST16_BODY_LEN      72

char test16_req_op1_val[TEST16_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test16_resp_op1_val[TEST16_RESP_OP1_LEN] =  {0x00, 0x00, 0x21};  /* num: 2, more: 0, size: 32 */

test_coap_client_msg_op_t test16_req_ops[TEST16_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST16_REQ_OP1_LEN,
        .val = test16_req_op1_val
    }
};

test_coap_client_msg_op_t test16_resp_ops[TEST16_NUM_RESP_OPS] =
{
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST16_RESP_OP1_LEN,
        .val = test16_resp_op1_val
    }
};

test_coap_client_msg_t test16_req[TEST16_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_POST,
        .ops = test16_req_ops,
        .num_ops = TEST16_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 32,
        .block2_size = 32,
        .body_end = 0
    }
};

test_coap_client_msg_t test16_resp[TEST16_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CHANGED,
        .ops = test16_resp_ops,
        .num_ops = TEST16_NUM_RESP_OPS,
        .payload = "padgjlzc",
        .payload_len = 8,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = TEST16_BODY_LEN
    }
};

test_coap_client_data_t test16_data =
{
    .desc = "test 16: perform a POST library-level blockwise transfer in which the request and response both carry a body",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test16_req,
    .test_resp = test16_resp,
    .num_msg = TEST16_NUM_MSG,
    .body = "1234567890abcdefghijzxcvbnmasd2468135790qwertyuiopplmkoijnbhwryipadgjlzc",
    .body_len = TEST16_BODY_LEN
};

#define TEST17_NUM_MSG      1
#define TEST17_REQ_OP1_LEN  LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST17_NUM_REQ_OPS  1
#define TEST17_BODY_LEN     80

char test17_req_op1_val[TEST17_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;

test_coap_client_msg_op_t test17_req_ops[TEST17_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST17_REQ_OP1_LEN,
        .val = test17_req_op1_val
    }
};

test_coap_client_msg_t test17_req[TEST17_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_POST,
        .ops = test17_req_ops,
        .num_ops = TEST17_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 16,
        .block2_size = 16,
        .body_end = 0
    }
};

test_coap_client_msg_t test17_resp[TEST17_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_CLIENT_ERR,
        .code_detail = COAP_MSG_REQ_ENT_TOO_LARGE,
        .ops = NULL,
        .num_ops = 0,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test17_data =
{
    .desc = "test 17: attempt a PUT library-level blockwise transfer with a body that is too large",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test17_req,
    .test_resp = test17_resp,
    .num_msg = TEST17_NUM_MSG,
    .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq24680135",
    .body_len = TEST17_BODY_LEN
};

#define TEST18_NUM_MSG      1
#define TEST18_REQ_OP1_LEN  LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST18_NUM_REQ_OPS  1
#define TEST18_BODY_LEN     80

char test18_req_op1_val[TEST18_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;

test_coap_client_msg_op_t test18_req_ops[TEST18_NUM_REQ_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST18_REQ_OP1_LEN,
        .val = test18_req_op1_val
    }
};

test_coap_client_msg_t test18_req[TEST18_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test18_req_ops,
        .num_ops = TEST18_NUM_REQ_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 16,
        .block2_size = 16,
        .body_end = 0
    }
};

test_coap_client_msg_t test18_resp[TEST18_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_CLIENT_ERR,
        .code_detail = COAP_MSG_REQ_ENT_TOO_LARGE,
        .ops = NULL,
        .num_ops = 0,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test18_data =
{
    .desc = "test 18: attempt a POST library-level blockwise transfer with a body that is too large",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test18_req,
    .test_resp = test18_resp,
    .num_msg = TEST18_NUM_MSG,
    .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq24680135",
    .body_len = TEST18_BODY_LEN
};

/* the client uses application-level blockwise transfers
 * the server uses library-level blockwise transfers
 */
#define TEST19_NUM_MSG       2
#define TEST19_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST19_REQ_OP2_LEN   3
#define TEST19_REQ_OP3_LEN   3
#define TEST19_REQ_NUM_OPS   2
#define TEST19_RESP_OP1_LEN  3
#define TEST19_RESP_NUM_OPS  1

char test19_req_op1_val[TEST19_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test19_req_op2_val[TEST19_REQ_OP2_LEN] =  {0x00, 0x00, 0x08};  /* PUT num: 0, more: 1, size: 16 */
char test19_req_op3_val[TEST19_REQ_OP3_LEN] =  {0x00, 0x00, 0x20};  /* PUT num: 2, more: 0, size: 16 */

char test19_resp_op1_val[TEST19_RESP_OP1_LEN] =  {0x00, 0x00, 0x08};  /* PUT num: 0, more: 1, size: 16 */

test_coap_client_msg_op_t test19_req_ops1[TEST19_REQ_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST19_REQ_OP1_LEN,
        .val = test19_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST19_REQ_OP2_LEN,
        .val = test19_req_op2_val
    }
};

test_coap_client_msg_op_t test19_req_ops2[TEST19_REQ_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST19_REQ_OP1_LEN,
        .val = test19_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST19_REQ_OP3_LEN,
        .val = test19_req_op3_val
    }
};

test_coap_client_msg_op_t test19_resp_ops1[TEST19_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST19_RESP_OP1_LEN,
        .val = test19_resp_op1_val
    }
};

test_coap_client_msg_t test19_req[TEST19_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test19_req_ops1,
        .num_ops = TEST19_REQ_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_PUT,
        .ops = test19_req_ops2,
        .num_ops = TEST19_REQ_NUM_OPS,
        .payload = "ghijklmnopqrstuv",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test19_resp[TEST19_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTINUE,
        .ops = test19_resp_ops1,
        .num_ops = TEST19_RESP_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_CLIENT_ERR,
        .code_detail = COAP_MSG_INCOMPLETE,
        .ops = NULL,
        .num_ops = 0,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test19_data =
{
    .desc = "test 19: send two out-of-sequence blockwise PUT requests",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test19_req,
    .test_resp = test19_resp,
    .num_msg = TEST19_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

/* the client uses application-level blockwise transfers
 * the server uses library-level blockwise transfers
 */
#define TEST20_NUM_MSG       2
#define TEST20_REQ_OP1_LEN   LIB_LEVEL_BLOCKWISE_URI_PATH_LEN
#define TEST20_REQ_OP2_LEN   3
#define TEST20_REQ_OP3_LEN   3
#define TEST20_REQ_NUM_OPS   2
#define TEST20_RESP_OP1_LEN  3
#define TEST20_RESP_NUM_OPS  1

char test20_req_op1_val[TEST20_REQ_OP1_LEN + 1] = LIB_LEVEL_BLOCKWISE_URI_PATH;
char test20_req_op2_val[TEST20_REQ_OP2_LEN] =  {0x00, 0x00, 0x08};  /* POST num: 0, more: 1, size: 16 */
char test20_req_op3_val[TEST20_REQ_OP3_LEN] =  {0x00, 0x00, 0x20};  /* POST num: 2, more: 0, size: 16 */

char test20_resp_op1_val[TEST20_RESP_OP1_LEN] =  {0x00, 0x00, 0x08};  /* POST num: 0, more: 1, size: 16 */

test_coap_client_msg_op_t test20_req_ops1[TEST20_REQ_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST20_REQ_OP1_LEN,
        .val = test20_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST20_REQ_OP2_LEN,
        .val = test20_req_op2_val
    }
};

test_coap_client_msg_op_t test20_req_ops2[TEST20_REQ_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST20_REQ_OP1_LEN,
        .val = test20_req_op1_val
    },
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST20_REQ_OP3_LEN,
        .val = test20_req_op3_val
    }
};

test_coap_client_msg_op_t test20_resp_ops1[TEST20_RESP_NUM_OPS] =
{
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST20_RESP_OP1_LEN,
        .val = test20_resp_op1_val
    }
};

test_coap_client_msg_t test20_req[TEST20_NUM_MSG] =
{
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_POST,
        .ops = test20_req_ops1,
        .num_ops = TEST20_REQ_NUM_OPS,
        .payload = "0123456789abcdef",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_POST,
        .ops = test20_req_ops2,
        .num_ops = TEST20_REQ_NUM_OPS,
        .payload = "ghijklmnopqrstuv",
        .payload_len = 16,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_msg_t test20_resp[TEST20_NUM_MSG] =
{
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTINUE,
        .ops = test20_resp_ops1,
        .num_ops = TEST20_RESP_NUM_OPS,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_CLIENT_ERR,
        .code_detail = COAP_MSG_INCOMPLETE,
        .ops = NULL,
        .num_ops = 0,
        .payload = NULL,
        .payload_len = 0,
        .block1_size = 0,
        .block2_size = 0,
        .body_end = 0
    }
};

test_coap_client_data_t test20_data =
{
    .desc = "test 20: send two out-of-sequence blockwise POST requests",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test20_req,
    .test_resp = test20_resp,
    .num_msg = TEST20_NUM_MSG,
    .body = NULL,
    .body_len = 0
};

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
}

/**
 *  @brief Populate a request message with details from a test request message structure
 *
 *  @param[in] test_req Pointer to a test request message structure
 *  @param[out] req Pointer to a request message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int populate_req(test_coap_client_msg_t *test_req, coap_msg_t *req)
{
    unsigned i = 0;
    int ret = 0;

    ret = coap_msg_set_type(req, test_req->type);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    ret = coap_msg_set_code(req, test_req->code_class, test_req->code_detail);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    for (i = 0; i < test_req->num_ops; i++)
    {
        ret = coap_msg_add_op(req, test_req->ops[i].num, test_req->ops[i].len, test_req->ops[i].val);
        if (ret < 0)
        {
            coap_log_error("%s", strerror(-ret));
            return ret;
        }
    }
    if (test_req->payload)
    {
        ret = coap_msg_set_payload(req, test_req->payload, test_req->payload_len);
        if (ret < 0)
        {
            coap_log_error("%s", strerror(-ret));
            return ret;
        }
    }
    return 0;
}

/**
 *  @brief Send a request to the server to reset it to a known state
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[out] req Pointer to a request message structure
 *  @param[out] resp Pointer to a response message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int exchange_reset(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    int ret = 0;

    ret = coap_msg_set_type(req, COAP_MSG_CON);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    ret = coap_msg_set_code(req, COAP_MSG_REQ, COAP_MSG_GET);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    ret = coap_msg_add_op(req, COAP_MSG_URI_PATH, RESET_URI_PATH_LEN, RESET_URI_PATH);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    ret = coap_client_exchange(client, req, resp);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return ret;
    }
    return 0;
}

/**
 *  @brief Send a request to the server and receive the response
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] test_req Pointer to a test request message structure
 *  @param[out] req Pointer to a request message structure
 *  @param[out] resp Pointer to a response message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int exchange(coap_client_t *client, test_coap_client_msg_t *test_req, coap_msg_t *req, coap_msg_t *resp)
{
    int ret = 0;

    ret = coap_client_exchange(client, req, resp);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return ret;
    }
    print_coap_msg("Sent:", req);
    print_coap_msg("Received:", resp);
    return 0;
}

/**
 *  @brief Send a blockwise request to the server and receive the response
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] test_req Pointer to a test request message structure
 *  @param[out] req Pointer to a request message structure
 *  @param[out] resp Pointer to a response message structure
 *  @param[out] body Buffer to hold the body
 *  @param[in] body_len Length of the buffer to hold the body
 *
 *  @returns Operation status
 *  @retval >0 Length of the data sent/received
 *  @retval <0 Error
 */
static ssize_t exchange_blockwise(coap_client_t *client,
                                 test_coap_client_msg_t *test_req,
                                 coap_msg_t *req, coap_msg_t *resp,
                                 char *body, size_t body_len, int have_resp)
{
    ssize_t num = 0;

    num = coap_client_exchange_blockwise(client,
                                         req, resp,
                                         test_req->block1_size,
                                         test_req->block2_size,
                                         body, body_len, have_resp);
    if (num < 0)
    {
        if (num != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-num));
        }
        return num;
    }
    print_coap_msg("Sent:", req);
    print_coap_msg("Received:", resp);
    return num;
}

/**
 *  @brief Compare the version and token fields in a request message and a response message
 *
 *  @param[out] req Pointer to a request message structure
 *  @param[out] resp Pointer to a response message structure
 *
 *  @returns Test result
 */
static test_result_t compare_ver_token(coap_msg_t *req, coap_msg_t *resp)
{
    if (coap_msg_get_ver(req) != coap_msg_get_ver(resp))
    {
        coap_log_warn("Version in request and response messages do not match");
        return FAIL;
    }
    if (coap_msg_get_token_len(req) != coap_msg_get_token_len(resp))
    {
        coap_log_warn("Token length in request and response messages do not match");
        return FAIL;
    }
    else if (memcmp(coap_msg_get_token(req), coap_msg_get_token(resp), coap_msg_get_token_len(req)) != 0)
    {
        coap_log_warn("Token in request and response messages do not match");
        return FAIL;
    }
    return PASS;
}

/**
 *  @brief Check the fields in a response message against the expected values
 *
 *  @param[out] test_resp Pointer to a test response message structure
 *  @param[out] resp Pointer to a response message structure
 *
 *  @returns Test result
 */
static test_result_t check_resp(test_coap_client_msg_t *test_resp, coap_msg_t *resp)
{
    test_coap_client_msg_op_t *exp_op = NULL;
    coap_msg_op_t *resp_op = NULL;
    unsigned match = 0;
    unsigned i = 0;

    if (test_resp->type != coap_msg_get_type(resp))
    {
        coap_log_warn("Unexpected type in response message");
        coap_log_debug("Received: %d", coap_msg_get_type(resp));
        coap_log_debug("Expected: %d", test_resp->type);
        return FAIL;
    }
    if (test_resp->code_class != coap_msg_get_code_class(resp))
    {
        coap_log_warn("Unexpected code class in response message");
        coap_log_debug("Received: %d", coap_msg_get_code_class(resp));
        coap_log_debug("Expected: %d", test_resp->code_class);
        return FAIL;
    }
    if (test_resp->code_detail != coap_msg_get_code_detail(resp))
    {
        coap_log_warn("Unexpected code detail in response message");
        coap_log_debug("Received: %d", coap_msg_get_code_detail(resp));
        coap_log_debug("Expected: %d", test_resp->code_detail);
        return FAIL;
    }
    for (i = 0; i < test_resp->num_ops; i++)
    {
        match = 0;
        exp_op = &test_resp->ops[i];
        resp_op = coap_msg_get_first_op(resp);
        while (resp_op != NULL)
        {
            if ((coap_msg_op_get_num(resp_op) == exp_op->num)
             && (coap_msg_op_get_len(resp_op) == exp_op->len)
             && (memcmp(coap_msg_op_get_val(resp_op), exp_op->val, exp_op->len) == 0))
            {
                match = 1;
                break;
            }
            resp_op = coap_msg_op_get_next(resp_op);
        }
        if (!match)
        {
            coap_log_warn("Expected option: %d not found in response message", exp_op->num);
            return FAIL;
        }
    }
    if (test_resp->payload_len != coap_msg_get_payload_len(resp))
    {
        coap_log_warn("Unexpected payload length in response message");
        coap_log_debug("Received: %d", coap_msg_get_payload_len(resp));
        coap_log_debug("Expected: %d", test_resp->payload_len);
        return FAIL;
    }
    if ((test_resp->payload_len > 0)
     && (memcmp(test_resp->payload, coap_msg_get_payload(resp), test_resp->payload_len)))
    {
        coap_log_warn("Unexpected payload in response message");
        coap_log_debug("Received: %s", coap_msg_get_payload(resp));
        coap_log_debug("Expected: %s", test_resp->payload);
        return FAIL;
    }
    return PASS;
}

/**
 *  @brief Check the body in the response messages against the expected values
 *
 *  @param[in] test_data Pointer to a client test data structure
 *  @param[in] test_resp Pointer to a test response message structure
 *  @param[in] body Buffer to contain the expected body content
 *  @param[in] body_end Amount of relevant data in the buffer to contain the expected body content
 *
 *  @returns Test result
 */
static test_result_t check_resp_body(test_coap_client_data_t *test_data,
                                     test_coap_client_msg_t *test_resp,
                                     const char *body, size_t body_end)
{
    if (body_end != test_resp->body_end)
    {
        coap_log_warn("Unexpected body length in response messages");
        coap_log_debug("Received: %s", body_end);
        coap_log_debug("Expected: %s", test_resp->body_end);
        return FAIL;
    }
    if (memcmp(body, test_data->body, test_resp->body_end) != 0)
    {
        coap_log_warn("Unexpected body in response messages");
        coap_log_debug("Received: %s", body);
        coap_log_debug("Expected: %s", test_data->body);
        return FAIL;
    }
    return PASS;
}

/**
 *  @brief Test an exchange with the server
 *
 *  @param[in] data Pointer to a client test data structure
 *
 *  @returns Test result
 */
static test_result_t test_exchange_func(test_data_t data)
{
    test_coap_client_data_t *test_data = (test_coap_client_data_t *)data;
    test_result_t result = PASS;
    coap_client_t client = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    unsigned i = 0;
    int ret = 0;

    printf("%s\n", test_data->desc);

#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port,
                             test_data->key_file_name,
                             test_data->cert_file_name,
                             test_data->trust_file_name,
                             test_data->crl_file_name,
                             test_data->common_name);
#else
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port);
#endif
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return FAIL;
    }
    coap_msg_create(&req);
    coap_msg_create(&resp);
    exchange_reset(&client, &req, &resp);
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    for (i = 0; i < test_data->num_msg; i++)
    {
        coap_msg_create(&req);
        coap_msg_create(&resp);
        ret = populate_req(&test_data->test_req[i], &req);
        if (ret < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        ret = exchange(&client, &test_data->test_req[i], &req, &resp);
        if (ret < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        ret = compare_ver_token(&req, &resp);
        if (ret != PASS)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return ret;
        }
        ret = check_resp(&test_data->test_resp[i], &resp);
        if (ret != PASS)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return ret;
        }
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
    }
    coap_client_destroy(&client);
    return result;
}

/**
 *  @brief Test an exchange with the server using library-level blockwise transfers
 *
 *  @param[in] data Pointer to a client test data structure
 *  @param[in] index Message index
 *
 *  @returns Test result
 */
static test_result_t test_exchange_blockwise_func(test_data_t data)
{
    test_coap_client_data_t *test_data = (test_coap_client_data_t *)data;
    test_result_t result = PASS;
    coap_client_t client = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    unsigned i = 0;
    ssize_t num = 0;
    size_t body_len = 0;
    char body[test_data->body_len];
    int ret = 0;

    printf("%s\n", test_data->desc);

#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port,
                             test_data->key_file_name,
                             test_data->cert_file_name,
                             test_data->trust_file_name,
                             test_data->crl_file_name,
                             test_data->common_name);
#else
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port);
#endif
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return FAIL;
    }
    coap_msg_create(&req);
    coap_msg_create(&resp);
    exchange_reset(&client, &req, &resp);
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    for (i = 0; i < test_data->num_msg; i++)
    {
        coap_msg_create(&req);
        coap_msg_create(&resp);
        memset(body, 0, sizeof(body));
        ret = populate_req(&test_data->test_req[i], &req);
        if (ret < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        if (test_data->test_req[i].code_detail == COAP_MSG_GET)
        {
            memset(body, 0, sizeof(body));
            body_len = sizeof(body);
        }
        else if ((test_data->test_req[i].code_detail == COAP_MSG_PUT)
              || (test_data->test_req[i].code_detail == COAP_MSG_POST))
        {
            memcpy(body, test_data->body, test_data->body_len);
            body_len = test_data->body_len;
        }
        num = exchange_blockwise(&client,
                                 &test_data->test_req[i],
                                 &req, &resp,
                                 body, body_len, 0);
        if (num < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        ret = check_resp(&test_data->test_resp[i], &resp);
        if (ret != PASS)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return ret;
        }
        ret = check_resp_body(test_data, &test_data->test_resp[i], body, num);
        if (ret != PASS)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return ret;
        }
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
    }
    coap_client_destroy(&client);
    return result;
}

/**
 *  @brief Test an exchange with the server using different transfer types
 *
 *  @param[in] data Pointer to a client test data structure
 *
 *  @returns Test result
 */
static test_result_t test_exchange_different_func(test_data_t data)
{
    test_coap_client_data_t *test_data = (test_coap_client_data_t *)data;
    test_result_t result = PASS;
    coap_client_t client = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    unsigned block2_size = 0;
    unsigned block2_more = 0;
    unsigned block2_num = 0;
    unsigned i = 0;
    ssize_t num = 0;
    char body[test_data->body_len];
    int ret = 0;

    printf("%s\n", test_data->desc);

#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port,
                             test_data->key_file_name,
                             test_data->cert_file_name,
                             test_data->trust_file_name,
                             test_data->crl_file_name,
                             test_data->common_name);
#else
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port);
#endif
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return FAIL;
    }
    coap_msg_create(&req);
    coap_msg_create(&resp);
    exchange_reset(&client, &req, &resp);
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    for (i = 0; i < test_data->num_msg; i++)
    {
        coap_msg_create(&req);
        coap_msg_create(&resp);
        ret = populate_req(&test_data->test_req[i], &req);
        if (ret < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        /* try using a regular transfer */
        ret = exchange(&client, &test_data->test_req[i], &req, &resp);
        if (ret < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        /* inspect the block2 option in the response */
        ret = coap_msg_parse_block_op(&block2_num, &block2_more, &block2_size, &resp, COAP_MSG_BLOCK2);
        if (ret != 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        /* continue using a blockwise transfer */
        num = exchange_blockwise(&client,
                                 &test_data->test_req[i],
                                 &req, &resp,
                                 body, sizeof(body), 1);
        if (num < 0)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return FAIL;
        }
        ret = check_resp(&test_data->test_resp[i], &resp);
        if (ret != PASS)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return ret;
        }
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
    }
    coap_client_destroy(&client);
    return result;
}

/**
 *  @brief Helper function to list command line options
 */
static void usage(void)
{
    coap_log_error("Usage: test_coap_client <options> test-num");
    coap_log_error("Options:");
    coap_log_error("    -l log-level - set the log level (0 to 4)");
}

/**
 *  @brief Main function for the FreeCoAP client test application
 *
 *  @param[in] argc Number of command line arguments
 *  @param[in] argv Array of pointers to command line arguments
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(int argc, char **argv)
{
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    const char *opts = ":hl:";
    unsigned num_tests = 0;
    unsigned num_pass = 0;
    int log_level = COAP_LOG_INFO;
    int test_num = 0;
    int ret = 0;
    int c = 0;
    test_t tests[] = {{test_exchange_func,           &test1_data},
                      {test_exchange_func,           &test2_data},
                      {test_exchange_func,           &test3_data},
                      {test_exchange_func,           &test4_data},
                      {test_exchange_func,           &test5_data},
                      {test_exchange_func,           &test6_data},
                      {test_exchange_func,           &test7_data},
                      {test_exchange_func,           &test8_data},
                      {test_exchange_func,           &test9_data},
                      {test_exchange_func,           &test10_data},
                      {test_exchange_blockwise_func, &test11_data},
                      {test_exchange_blockwise_func, &test12_data},
                      {test_exchange_different_func, &test13_data},
                      {test_exchange_blockwise_func, &test14_data},
                      {test_exchange_blockwise_func, &test15_data},
                      {test_exchange_blockwise_func, &test16_data},
                      {test_exchange_blockwise_func, &test17_data},
                      {test_exchange_blockwise_func, &test18_data},
                      {test_exchange_func,           &test19_data},
                      {test_exchange_func,           &test20_data}};

    opterr = 0;
    while ((c = getopt(argc, argv, opts)) != -1)
    {
        switch (c)
        {
        case 'h':
            usage();
            return EXIT_SUCCESS;
        case 'l':
            log_level = atoi(optarg);
            break;
        case ':':
            coap_log_error("Option '%c' requires an argument", optopt);
            return EXIT_FAILURE;
        case '?':
            coap_log_error("Unknown option '%c'", optopt);
            return EXIT_FAILURE;
        default:
            usage();
        }
    }
    /* if there is an argument after the options then interpret it as a test number */
    if (optind < argc)
    {
        test_num = atoi(argv[optind]);
    }

    coap_log_set_level(log_level);
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
#endif

    switch (test_num)
    {
    case 1:
        num_tests = 1;
        num_pass = test_run(&tests[0], num_tests);
        break;
    case 2:
        num_tests = 1;
        num_pass = test_run(&tests[1], num_tests);
        break;
    case 3:
        num_tests = 1;
        num_pass = test_run(&tests[2], num_tests);
        break;
    case 4:
        num_tests = 1;
        num_pass = test_run(&tests[3], num_tests);
        break;
    case 5:
        num_tests = 1;
        num_pass = test_run(&tests[4], num_tests);
        break;
    case 6:
        num_tests = 1;
        num_pass = test_run(&tests[5], num_tests);
        break;
    case 7:
        num_tests = 1;
        num_pass = test_run(&tests[6], num_tests);
        break;
    case 8:
        num_tests = 1;
        num_pass = test_run(&tests[7], num_tests);
        break;
    case 9:
        num_tests = 1;
        num_pass = test_run(&tests[8], num_tests);
        break;
    case 10:
        num_tests = 1;
        num_pass = test_run(&tests[9], num_tests);
        break;
    case 11:
        num_tests = 1;
        num_pass = test_run(&tests[10], num_tests);
        break;
    case 12:
        num_tests = 1;
        num_pass = test_run(&tests[11], num_tests);
        break;
    case 13:
        num_tests = 1;
        num_pass = test_run(&tests[12], num_tests);
        break;
    case 14:
        num_tests = 1;
        num_pass = test_run(&tests[13], num_tests);
        break;
    case 15:
        num_tests = 1;
        num_pass = test_run(&tests[14], num_tests);
        break;
    case 16:
        num_tests = 1;
        num_pass = test_run(&tests[15], num_tests);
        break;
    case 17:
        num_tests = 1;
        num_pass = test_run(&tests[16], num_tests);
        break;
    case 18:
        num_tests = 1;
        num_pass = test_run(&tests[17], num_tests);
        break;
    case 19:
        num_tests = 1;
        num_pass = test_run(&tests[18], num_tests);
        break;
    case 20:
        num_tests = 1;
        num_pass = test_run(&tests[19], num_tests);
        break;
    default:
        num_tests = 20;
        num_pass = test_run(tests, num_tests);
    }
    coap_mem_all_destroy();
    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
