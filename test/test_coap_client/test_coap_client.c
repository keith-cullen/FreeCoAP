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
#include "coap_log.h"
#include "test.h"

#ifdef COAP_IP6
#define HOST             "::1"                                                  /**< Host address of the server */
#else
#define HOST             "127.0.0.1"                                            /**< Host address of the server */
#endif
#define PORT             "12436"                                                /**< UDP port number of the server */
#define TRUST_FILE_NAME  "../../certs/root_server_cert.pem"                     /**< DTLS trust file name */
#define CERT_FILE_NAME   "../../certs/client_cert.pem"                          /**< DTLS certificate file name */
#define KEY_FILE_NAME    "../../certs/client_privkey.pem"                       /**< DTLS key file name */
#define CRL_FILE_NAME    ""                                                     /**< DTLS certificate revocation list file name */
#define COMMON_NAME      "dummy/server"                                         /**< Common name of the server */
#define SEP_URI_PATH     "separate"                                             /**< URI path option value to trigger a separate response from the server */

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
}
test_coap_client_data_t;

#define TEST1_NUM_MSG      1
#define TEST1_REQ_OP1_LEN  8
#define TEST1_NUM_OPS      1

char test1_req_op1_val[TEST1_REQ_OP1_LEN + 1] = "resource";

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
        .payload = "Hello Server!",
        .payload_len = 13
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
        .payload = "Hello Client!",
        .payload_len = 13
    }
};

test_coap_client_data_t test1_data =
{
    .desc = "test 1: send a confirmable request and expect a piggy-backed response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test1_req,
    .test_resp = test1_resp,
    .num_msg = TEST1_NUM_MSG
};

#define TEST2_NUM_MSG      1
#define TEST2_REQ_OP1_LEN  8
#define TEST2_NUM_OPS      1

char test2_req_op1_val[TEST2_REQ_OP1_LEN + 1] = SEP_URI_PATH;

test_coap_client_msg_op_t test2_req_ops[TEST2_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST2_REQ_OP1_LEN,
        .val = test2_req_op1_val
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
        .payload = "Hello Server!",
        .payload_len = 13
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
        .payload = "Hello Client!",
        .payload_len = 13
    }
};

test_coap_client_data_t test2_data =
{
    .desc = "test 2: send a confirmable request and expect a separate response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test2_req,
    .test_resp = test2_resp,
    .num_msg = TEST2_NUM_MSG
};

#define TEST3_NUM_MSG      1
#define TEST3_REQ_OP1_LEN  8
#define TEST3_NUM_OPS      1

char test3_req_op1_val[TEST3_REQ_OP1_LEN + 1] = "resource";

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
        .payload = "Hello Server!",
        .payload_len = 13
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
        .payload = "Hello Client!",
        .payload_len = 13
    }
};

test_coap_client_data_t test3_data =
{
    .desc = "test 3: send a non-confirmable request",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test3_req,
    .test_resp = test3_resp,
    .num_msg = TEST3_NUM_MSG
};

#define TEST4_NUM_MSG      2
#define TEST4_REQ_OP1_LEN  8
#define TEST4_NUM_OPS      1

char test4_req_op1_val[TEST4_REQ_OP1_LEN + 1] = "resource";

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
        .payload = "Hello Server!",
        .payload_len = 13
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test4_req_ops,
        .num_ops = TEST4_NUM_OPS,
        .payload = "Hello again server!",
        .payload_len = 19
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
        .payload = "Hello Client!",
        .payload_len = 13
    },
    {
        .type = COAP_MSG_ACK,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "Hello Client!",
        .payload_len = 13
    }
};

test_coap_client_data_t test4_data =
{
    .desc = "test 4: send two confirmable requests and expect piggy-backed responses",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test4_req,
    .test_resp = test4_resp,
    .num_msg = TEST4_NUM_MSG
};

#define TEST5_NUM_MSG      2
#define TEST5_REQ_OP1_LEN  8
#define TEST5_NUM_OPS      1

char test5_req_op1_val[TEST5_REQ_OP1_LEN + 1] = SEP_URI_PATH;

test_coap_client_msg_op_t test5_req_ops[TEST5_NUM_OPS] =
{
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST5_REQ_OP1_LEN,
        .val = test5_req_op1_val
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
        .payload = "Hello Server!",
        .payload_len = 13
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test5_req_ops,
        .num_ops = TEST5_NUM_OPS,
        .payload = "Hello again server!",
        .payload_len = 19
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
        .payload = "Hello Client!",
        .payload_len = 13
    },
    {
        .type = COAP_MSG_CON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "Hello Client!",
        .payload_len = 13
    }
};

test_coap_client_data_t test5_data =
{
    .desc = "test 5: send two confirmable requests and expect separate responses",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test5_req,
    .test_resp = test5_resp,
    .num_msg = TEST5_NUM_MSG
};

#define TEST6_NUM_MSG      2
#define TEST6_REQ_OP1_LEN  8
#define TEST6_NUM_OPS      1

char test6_req_op1_val[TEST6_REQ_OP1_LEN + 1] = "resource";

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
        .payload = "Hello Server!",
        .payload_len = 13
    },
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_REQ,
        .code_detail = COAP_MSG_GET,
        .ops = test6_req_ops,
        .num_ops = TEST6_NUM_OPS,
        .payload = "Hello again server!",
        .payload_len = 19
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
        .payload = "Hello Client!",
        .payload_len = 13
    },
    {
        .type = COAP_MSG_NON,
        .code_class = COAP_MSG_SUCCESS,
        .code_detail = COAP_MSG_CONTENT,
        .ops = NULL,
        .num_ops = 0,
        .payload = "Hello Client!",
        .payload_len = 13
    }
};

test_coap_client_data_t test6_data =
{
    .desc = "test 6: send two non-confirmable requests",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test6_req,
    .test_resp = test6_resp,
    .num_msg = TEST6_NUM_MSG
};

#define TEST7_NUM_MSG      1
#define TEST7_REQ_OP1_LEN  8
#define TEST7_REQ_OP2_LEN  1
#define TEST7_NUM_OPS      2

char test7_req_op1_val[TEST7_REQ_OP1_LEN + 1] = "resource";
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
        .payload = "Hello Server!",
        .payload_len = 13
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
        .payload_len = 21
    }
};

test_coap_client_data_t test7_data =
{
    .desc = "test 7: send a confirmable request and expect a bad option response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .common_name = COMMON_NAME,
    .test_req = test7_req,
    .test_resp = test7_resp,
    .num_msg = TEST7_NUM_MSG
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
 *  @returns Test result
 */
static test_result_t populate_req(test_coap_client_msg_t *test_req, coap_msg_t *req)
{
    unsigned i = 0;
    int ret = 0;

    ret = coap_msg_set_type(req, test_req->type);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return FAIL;
    }
    ret = coap_msg_set_code(req, test_req->code_class, test_req->code_detail);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return FAIL;
    }
    for (i = 0; i < test_req->num_ops; i++)
    {
        ret = coap_msg_add_op(req, test_req->ops[i].num, test_req->ops[i].len, test_req->ops[i].val);
        if (ret < 0)
        {
            coap_log_error("%s", strerror(-ret));
            return FAIL;
        }
    }
    if (test_req->payload)
    {
        ret = coap_msg_set_payload(req, test_req->payload, test_req->payload_len);
        if (ret < 0)
        {
            coap_log_error("%s", strerror(-ret));
            return FAIL;
        }
    }
    return PASS;
}

/**
 *  @brief Send a request to the server and receive the response
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] test_req Pointer to a test request message structure
 *  @param[out] req Pointer to a request message structure
 *  @param[out] resp Pointer to a response message structure
 *
 *  @returns Test result
 */
static test_result_t exchange(coap_client_t *client, test_coap_client_msg_t *test_req, coap_msg_t *req, coap_msg_t *resp)
{
    test_result_t result = PASS;
    int ret = 0;

    result = populate_req(test_req, req);
    if (result != PASS)
    {
        return result;
    }
    ret = coap_client_exchange(client, req, resp);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return FAIL;
    }

    print_coap_msg("Sent:", req);
    print_coap_msg("Received:", resp);

    return PASS;
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
        return FAIL;
    }
    if (coap_msg_get_token_len(req) != coap_msg_get_token_len(resp))
    {
        return FAIL;
    }
    else if (memcmp(coap_msg_get_token(req), coap_msg_get_token(resp), coap_msg_get_token_len(req)) != 0)
    {
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
    if (test_resp->type != coap_msg_get_type(resp))
    {
        return FAIL;
    }
    if (test_resp->code_class != coap_msg_get_code_class(resp))
    {
        return FAIL;
    }
    if (test_resp->code_detail != coap_msg_get_code_detail(resp))
    {
        return FAIL;
    }
    if (test_resp->payload_len != coap_msg_get_payload_len(resp))
    {
        return FAIL;
    }
    else if (memcmp(test_resp->payload, coap_msg_get_payload(resp), test_resp->payload_len))
    {
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
        coap_log_error("%s", strerror(-ret));
        return FAIL;
    }

    for (i = 0; i < test_data->num_msg; i++)
    {
        coap_msg_create(&req);
        coap_msg_create(&resp);

        ret = exchange(&client, &test_data->test_req[i], &req, &resp);
        if (ret != PASS)
        {
            coap_msg_destroy(&resp);
            coap_msg_destroy(&req);
            coap_client_destroy(&client);
            return ret;
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
    int log_level = COAP_LOG_DEBUG;
    int test_num = 0;
    int c = 0;
    test_t tests[] = {{test_exchange_func, &test1_data},
                      {test_exchange_func, &test2_data},
                      {test_exchange_func, &test3_data},
                      {test_exchange_func, &test4_data},
                      {test_exchange_func, &test5_data},
                      {test_exchange_func, &test6_data},
                      {test_exchange_func, &test7_data}};

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

#ifdef COAP_DTLS_EN
    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
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
    default:
        num_tests = 7;
        num_pass = test_run(tests, num_tests);
    }

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
