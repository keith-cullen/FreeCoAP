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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "coap_client.h"
#include "coap_log.h"
#include "test.h"

#define HOST             "::1"                                                  /**< Host address of the server */
#define PORT             12436                                                  /**< UDP port number of the server */
#define KEY_FILE_NAME    "client_privkey.pem"                                   /**< DTLS key file name */
#define CERT_FILE_NAME   "client_cert.pem"                                      /**< DTLS certificate file name */
#define TRUST_FILE_NAME  "root_server_cert.pem"                                 /**< DTLS trust file name */
#define CRL_FILE_NAME    ""                                                     /**< DTLS certificate revocation list file name */
#define SEP_URI_PATH     "separate"                                             /**< URI path option value to trigger a separate response from the server */

/**
 *  @brief Client test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    const char *host;                                                           /**< Server host address */
    unsigned port;                                                              /**< Server UDP port */
    const char *key_file_name;                                                  /**< DTLS key file name */
    const char *cert_file_name;                                                 /**< DTLS certificate file name */
    const char *trust_file_name;                                                /**< DTLS trust file name */
    const char *crl_file_name;                                                  /**< DTLS certificate revocation list file name */
    const char *uri_path_opt;                                                   /**< URI path option value */
    coap_msg_type_t type;                                                       /**< Message type */
    unsigned code_class;                                                        /**< Message code class */
    unsigned code_detail;                                                       /**< Message code detail */
    char *payload;                                                              /**< Buffer containing the payload */
    size_t payload_len;                                                         /**< Length of the buffer containing the payload */
}
test_client_data_t;

test_client_data_t test1_data =
{
    .desc = "test 1: send a confirmable request and expect a piggy-backed response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .uri_path_opt = NULL,
    .type = COAP_MSG_CON,
    .code_class = 0x0,
    .code_detail = 0x1,
    .payload = "Hello server!",
    .payload_len = 13
};

test_client_data_t test2_data =
{
    .desc = "test 2: send a confirmable request and expect a separate response",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .uri_path_opt = SEP_URI_PATH,
    .type = COAP_MSG_CON,
    .code_class = 0x0,
    .code_detail = 0x1,
    .payload = "Hello server!",
    .payload_len = 13
};

test_client_data_t test3_data =
{
    .desc = "test 3: send a non-confirmable request",
    .host = HOST,
    .port = PORT,
    .key_file_name = KEY_FILE_NAME,
    .cert_file_name = CERT_FILE_NAME,
    .trust_file_name = TRUST_FILE_NAME,
    .crl_file_name = CRL_FILE_NAME,
    .uri_path_opt = NULL,
    .type = COAP_MSG_NON,
    .code_class = 0x0,
    .code_detail = 0x1,
    .payload = "Hello server!",
    .payload_len = 13
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
 *  @brief Send a request to the server and receive the response
 *
 *  @param[in] test_data Pointer to a client test data structure
 *  @param[out] client Pointer to a client structure
 *  @param[out] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Test result
 */
static test_result_t exchange(test_client_data_t *test_data, coap_client_t *client, coap_msg_t *req, coap_msg_t *resp)
{
    int ret = 0;

    coap_msg_create(req);
    ret = coap_msg_set_type(req, test_data->type);
    if (ret != 0)
    {
        coap_log_error("Error: %s\n", strerror(-ret));
        coap_msg_destroy(req);
        coap_client_destroy(client);
        return FAIL;
    }
    ret = coap_msg_set_code(req, COAP_MSG_REQ, COAP_MSG_GET);
    if (ret != 0)
    {
        coap_log_error("Error: %s\n", strerror(-ret));
        coap_msg_destroy(req);
        coap_client_destroy(client);
        return FAIL;
    }
    if (test_data->uri_path_opt)
    {
        ret = coap_msg_add_op(req, COAP_MSG_OP_URI_PATH_NUM, strlen(test_data->uri_path_opt), test_data->uri_path_opt);
        if (ret != 0)
        {
            coap_log_error("Error: %s\n", strerror(-ret));
            coap_msg_destroy(req);
            coap_client_destroy(client);
            return FAIL;
        }
    }
    if (test_data->payload)
    {
        ret = coap_msg_set_payload(req, test_data->payload, test_data->payload_len);
        if (ret != 0)
        {
            coap_log_error("Error: %s\n", strerror(-ret));
            coap_msg_destroy(req);
            coap_client_destroy(client);
            return FAIL;
        }
    }
    coap_msg_create(resp);
    ret = coap_client_exchange(client, req, resp);
    if (ret != 0)
    {
        coap_log_error("Error: %s\n", strerror(-ret));
        coap_msg_destroy(resp);
        coap_msg_destroy(req);
        coap_client_destroy(client);
        return FAIL;
    }

    print_coap_msg("Sent:", req);
    print_coap_msg("Received:", resp);

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
    test_client_data_t *test_data = (test_client_data_t *)data;
    test_result_t result = PASS;
    coap_client_t client = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port,
                             test_data->key_file_name,
                             test_data->cert_file_name,
                             test_data->trust_file_name,
                             test_data->crl_file_name);
#else
    ret = coap_client_create(&client,
                             test_data->host,
                             test_data->port);
#endif
    if (ret != 0)
    {
        coap_log_error("Error: %s\n", strerror(-ret));
        return FAIL;
    }

    ret = exchange(test_data, &client, &req, &resp);
    if (ret != PASS)
    {
        return ret;
    }

    if (coap_msg_get_ver(&req) != coap_msg_get_ver(&resp))
    {
        result = FAIL;
    }
    if (coap_msg_get_token_len(&req) != coap_msg_get_token_len(&resp))
    {
        result = FAIL;
    }
    else
    {
        if (memcmp(coap_msg_get_token(&req), coap_msg_get_token(&resp), coap_msg_get_token_len(&req)) != 0)
        {
            result = FAIL;
        }
    }

    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    coap_client_destroy(&client);

    return result;
}


/**
 *  @brief Show usage
 */
static void usage(void)
{
    coap_log_error("Usage: client <options> test-num\n");
    coap_log_error("Options:");
    coap_log_error("    -l log-level - set the log level (0 to 4)\n");
}

int main(int argc, char **argv)
{
    const char *opts = ":hl:";
    int log_level = COAP_LOG_ERROR;
    int test_num = 0;
    int c = 0;
    test_t tests[] = {{test_exchange_func, &test1_data},
                      {test_exchange_func, &test2_data},
                      {test_exchange_func, &test3_data}};

    opterr = 0;
    while ((c = getopt(argc, argv, opts)) != -1)
    {
        switch (c)
        {
        case 'h':
            usage();
            return 0;
        case 'l':
            log_level = atoi(optarg);
            break;
        case ':':
            coap_log_error("Option '%c' requires an argument\n", optopt);
            return -1;
        case '?':
            coap_log_error("Unknown option '%c'\n", optopt);
            return -1;
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

    switch (test_num)
    {
    case 1:
        test_run(&tests[0], 1);
        break;
    case 2:
        test_run(&tests[1], 1);
        break;
    case 3:
        test_run(&tests[2], 1);
        break;
    default:
        test_run(tests, 3);
    }

    return 0;
}
