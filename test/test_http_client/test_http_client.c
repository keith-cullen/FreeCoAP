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
 *  @file test_http_client.c
 *
 *  @brief Source file for the FreeCoAP HTTP client test application
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>
#include "http_msg.h"
#include "tls_sock.h"
#include "tls.h"
#include "sock.h"
#include "coap_log.h"
#include "test.h"

#define SERVER_COMMON_NAME  "dummy/server"                                      /**< Expected common name in the proxy's certificate */
#ifdef SOCK_IP6
#define PROXY_HOST          "::1"                                               /**< Host address of the proxy */
#else
#define PROXY_HOST          "127.0.0.1"                                         /**< Host address of the proxy */
#endif
#ifdef COAP_IP6
#define SERVER_HOST         "[::1]"                                             /**< Host address of the server */
#else
#define SERVER_HOST         "127.0.0.1"                                         /**< Host address of the server */
#endif
#define PROXY_PORT          "12437"                                             /**< TCP port number of the proxy */
#define TRUST_FILE_NAME     "../../certs/root_server_cert.pem"                  /**< TLS trust file name */
#define CERT_FILE_NAME      "../../certs/client_cert.pem"                       /**< TLS certificate file name */
#define KEY_FILE_NAME       "../../certs/client_privkey.pem"                    /**< TLS key file name */
#define CRL_FILE_NAME       ""                                                  /**< TLS certificate revocation list file name */
#define SOCKET_TIMEOUT      120                                                 /**< Timeout for TLS/IPv6 socket operations */
#define RESP_BUF_LEN        1024                                                /**< Size of the buffer used to store responses */

/**
 *  @brief HTTP client test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    char *req_str;                                                              /**< String containing the HTTP request to transmit */
    const char **start;                                                         /**< Array of start line values expected in the HTTP response */
    size_t num_headers;                                                         /**< Number of headers to look for in the HTTP response */
    const char **name;                                                          /**< Array of header names expected in the HTTP response */
    const char **value;                                                         /**< Array of header values expected in the HTTP response */
    const char *body;                                                           /**< String containing the expected body in the HTTP response */
}
test_http_client_data_t;

#define TEST1_NUM_HEADERS  1

const char *test1_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test1_name[TEST1_NUM_HEADERS] = {"Content-Length"};
const char *test1_value[TEST1_NUM_HEADERS] = {"13"};
const char test1_body[] = "Hello Client!";

test_http_client_data_t test1_data =
{
    .desc = "test 1: Send GET request",
    .req_str = "GET coaps://"SERVER_HOST":12436/resource HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello Server!",
    .start = test1_start,
    .num_headers = TEST1_NUM_HEADERS,
    .name = test1_name,
    .value = test1_value,
    .body = test1_body
};

#define TEST2_NUM_HEADERS  1

const char *test2_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test2_name[TEST2_NUM_HEADERS] = {"Content-Length"};
const char *test2_value[TEST2_NUM_HEADERS] = {"13"};
const char test2_body[] = "Hello Client!";

test_http_client_data_t test2_data =
{
    .desc = "test 2: Send double POST request",
    .req_str = "POST coaps://"SERVER_HOST":12436/resource HTTP/1.1\r\nContent-Length: 13\r\n\r\nRequest=Hello",
    .start = test2_start,
    .num_headers = TEST2_NUM_HEADERS,
    .name = test2_name,
    .value = test2_value,
    .body = test2_body
};

const char *test3_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "501", "Not Implemented"};

test_http_client_data_t test3_data =
{
    .desc = "test 3: Send a request with an unsupported method",
    .req_str = "CONNECT coaps://"SERVER_HOST":12436/resource HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello Server!",
    .start = test3_start,
    .num_headers = 0,
    .name = NULL,
    .value = NULL,
    .body = NULL
};

const char *test4_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "400", "Bad Request"};

test_http_client_data_t test4_data =
{
    .desc = "test 4: Send a request with an unsupported scheme in the request-URI",
    .req_str = "GET dummy://"SERVER_HOST":12436/resource HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello Server!",
    .start = test4_start,
    .num_headers = 0,
    .name = NULL,
    .value = NULL,
    .body = NULL
};

const char *test5_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "406", "Not Acceptable"};

test_http_client_data_t test5_data =
{
    .desc = "test 5: Send a request with an unsupported Accept header value",
    .req_str = "GET coaps://"SERVER_HOST":12436/resource HTTP/1.1\r\nAccept: unsupported/format\r\nContent-Length: 13\r\n\r\nHello Server!",
    .start = test5_start,
    .num_headers = 0,
    .name = NULL,
    .value = NULL,
    .body = NULL
};

const char *test6_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "502", "Bad Gateway"};

test_http_client_data_t test6_data =
{
    .desc = "test 6: Send a request that will invoke a response from the CoAP server with an unsafe option",
    .req_str = "GET coaps://"SERVER_HOST":12436/unsafe HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello Server!",
    .start = test6_start,
    .num_headers = 0,
    .name = NULL,
    .value = NULL,
    .body = NULL
};

/**
 *  @brief TLS client context used by all tests
 */
tls_client_t client = {0};

/**
 *  @brief Compare the start line in a HTTP message with expected values
 *
 *  @param[in] test_data Pointer to a HTTP client test data structure
 *  @param[in] msg Pointer to a HTTP message structure
 *
 *  @returns Test result
 */
static test_result_t check_start(test_http_client_data_t *test_data, http_msg_t *msg)
{
    unsigned i = 0;

    for (i = 0; i < HTTP_MSG_NUM_START; i++)
    {
        if (strcmp(http_msg_get_start(msg, i), test_data->start[i]) != 0)
        {
            return FAIL;
        }
    }
    return PASS;
}

/**
 *  @brief Check that a HTTP message contains an expected header
 *
 *  @param[in] msg Pointer to a HTTP message structure
 *  @param[in] name Header name
 *  @param[in] value Header value
 *
 *  @returns Test result
 */
static test_result_t check_header(http_msg_t *msg, const char *name, const char *value)
{
    http_msg_header_t *header = NULL;

    header = http_msg_get_first_header(msg);
    while (header != NULL)
    {
        if ((strcmp(http_msg_header_get_name(header), name) == 0)
         && (strcmp(http_msg_header_get_value(header), value) == 0))
        {
            return PASS;
        }
        header = http_msg_header_get_next(header);
    }
    return FAIL;
}

/**
 *  @brief Check that a HTTP message contains expected headers
 *
 *  @param[in] test_data Pointer to a HTTP client test data structure
 *  @param[in] msg Pointer to a HTTP message structure
 *
 *  @returns Test result
 */
static test_result_t check_headers(test_http_client_data_t *test_data, http_msg_t *msg)
{
    unsigned i = 0;

    for (i = 0; i < test_data->num_headers; i++)
    {
        if (check_header(msg, test_data->name[i], test_data->value[i]) != PASS)
        {
            return FAIL;
        }
    }
    return PASS;
}

/**
 *  @brief Check that a HTTP message contains the expected body
 *
 *  @param[in] test_data Pointer to a HTTP client test data structure
 *  @param[in] msg Pointer to a HTTP message structure
 *
 *  @returns Test result
 */
static test_result_t check_body(test_http_client_data_t *test_data, http_msg_t *msg)
{
    size_t len = 0;

    if (test_data->body == NULL)
    {
        if (http_msg_get_body(msg) != NULL)
        {
            return FAIL;
        }
    }
    else
    {
        len = strlen(test_data->body);
        if (http_msg_get_body(msg) == NULL)
        {
            return FAIL;
        }
        if (http_msg_get_body_len(msg) != len)
        {
            return FAIL;
        }
        if (memcmp(http_msg_get_body(msg), test_data->body, len) != 0)
        {
            return FAIL;
        }
    }
    return PASS;
}

/**
 *  @brief Test an exchange with the proxy
 *
 *  @param[in] data Pointer to a HTTP client test data structure
 *
 *  @returns Test result
 */
static test_result_t test_exchange_func(test_data_t data)
{
    test_http_client_data_t *test_data = (test_http_client_data_t *)data;
    test_result_t result = PASS;
    http_msg_t resp_msg = {{0}};
    tls_sock_t s = {0};
    char resp_buf[RESP_BUF_LEN] = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = tls_sock_open(&s, &client, PROXY_HOST, PROXY_PORT, SERVER_COMMON_NAME, SOCKET_TIMEOUT);
    if (ret != SOCK_OK)
    {
        return FAIL;
    }
    ret = tls_sock_write_full(&s, test_data->req_str, strlen(test_data->req_str));
    if (ret <= 0)
    {
        tls_sock_close(&s);
        return FAIL;
    }
    coap_log_info("Sent: %s", test_data->req_str);
    ret = tls_sock_read(&s, resp_buf, sizeof(resp_buf));
    if (ret <= 0)
    {
        tls_sock_close(&s);
        return FAIL;
    }
    coap_log_info("Received: %s", resp_buf);
    http_msg_create(&resp_msg);
    ret = http_msg_parse(&resp_msg, resp_buf, strlen(resp_buf));
    if (ret <= 0)
    {
        http_msg_destroy(&resp_msg);
        tls_sock_close(&s);
        return FAIL;
    }
    if (check_start(test_data, &resp_msg) != PASS)
    {
        result = FAIL;
    }
    if (check_headers(test_data, &resp_msg) != PASS)
    {
        result = FAIL;
    }
    if (check_body(test_data, &resp_msg) != PASS)
    {
        result = FAIL;
    }
    http_msg_destroy(&resp_msg);
    tls_sock_close(&s);
    return result;
}

/**
 *  @brief Test a double exchange with the proxy
 *
 *  @param[in] data Pointer to a HTTP client test data structure
 *
 *  @returns Test result
 */
static test_result_t test_double_exchange_func(test_data_t data)
{
    test_http_client_data_t *test_data = (test_http_client_data_t *)data;
    test_result_t result = PASS;
    http_msg_t resp_msg = {{0}};
    tls_sock_t s = {0};
    unsigned i = 0;
    char resp_buf[RESP_BUF_LEN] = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = tls_sock_open(&s, &client, PROXY_HOST, PROXY_PORT, SERVER_COMMON_NAME, SOCKET_TIMEOUT);
    if (ret != SOCK_OK)
    {
        return FAIL;
    }
    for (i = 0; i < 2; i++)
    {
        ret = tls_sock_write_full(&s, test_data->req_str, strlen(test_data->req_str));
        if (ret <= 0)
        {
            tls_sock_close(&s);
            return FAIL;
        }
        coap_log_info("Sent: %s", test_data->req_str);
        memset(resp_buf, 0, sizeof(resp_buf));
        ret = tls_sock_read(&s, resp_buf, sizeof(resp_buf));
        if (ret <= 0)
        {
            tls_sock_close(&s);
            return FAIL;
        }
        coap_log_info("Received: %s", resp_buf);
        http_msg_create(&resp_msg);
        ret = http_msg_parse(&resp_msg, resp_buf, strlen(resp_buf));
        if (ret <= 0)
        {
            http_msg_destroy(&resp_msg);
            tls_sock_close(&s);
            return FAIL;
        }
        if (check_start(test_data, &resp_msg) != PASS)
        {
            result = FAIL;
        }
        if (check_headers(test_data, &resp_msg) != PASS)
        {
            result = FAIL;
        }
        if (check_body(test_data, &resp_msg) != PASS)
        {
            result = FAIL;
        }
        http_msg_destroy(&resp_msg);
    }
    tls_sock_close(&s);
    return result;
}

/**
 *  @brief Helper function to list command line options
 */
static void usage(void)
{
    coap_log_error("Usage: test_http_client <options> test-num");
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
    const char *gnutls_ver = NULL;
    const char *opts = ":hl:";
    unsigned num_tests = 0;
    unsigned num_pass = 0;
    int log_level = COAP_LOG_DEBUG;
    int test_num = 0;
    int ret = 0;
    int c = 0;
    test_t tests[] = {{test_exchange_func,        &test1_data},
                      {test_double_exchange_func, &test2_data},
                      {test_exchange_func,        &test3_data},
                      {test_exchange_func,        &test4_data},
                      {test_exchange_func,        &test5_data},
                      {test_exchange_func,        &test6_data}};

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

    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        return EXIT_FAILURE;
    }
    coap_log_info("GnuTLS version: %s", gnutls_ver);

    ret = tls_init();
    if (ret != SOCK_OK)
    {
        coap_log_error("%s", sock_strerror(ret));
        return EXIT_FAILURE;
    }
    ret = tls_client_create(&client, TRUST_FILE_NAME, CERT_FILE_NAME, KEY_FILE_NAME);
    if (ret != SOCK_OK)
    {
        coap_log_error("%s", sock_strerror(ret));
        tls_deinit();
        return EXIT_FAILURE;
    }

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
    default:
        num_tests = 6;
        num_pass = test_run(tests, num_tests);
    }

    tls_client_destroy(&client);
    tls_deinit();

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
