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

#define SERVER_COMMON_NAME                  "dummy/server"                      /**< Expected common name in the proxy's certificate */
#ifdef SOCK_IP6
#define PROXY_HOST                          "::1"                               /**< Host address of the proxy */
#else
#define PROXY_HOST                          "127.0.0.1"                         /**< Host address of the proxy */
#endif
#ifdef COAP_IP6
#define SERVER_HOST                         "[::1]"                             /**< Host address of the server */
#else
#define SERVER_HOST                         "127.0.0.1"                         /**< Host address of the server */
#endif
#define PROXY_PORT                          "12437"                             /**< TCP port number of the proxy */
#define TRUST_FILE_NAME                     "../../certs/root_server_cert.pem"  /**< TLS trust file name */
#define CERT_FILE_NAME                      "../../certs/client_cert.pem"       /**< TLS certificate file name */
#define KEY_FILE_NAME                       "../../certs/client_privkey.pem"    /**< TLS key file name */
#define CRL_FILE_NAME                       ""                                  /**< TLS certificate revocation list file name */
#define RESET_URI_PATH                      "reset"                             /**< URI path that causes the server to reset to a known state */
#define RESET_URI_PATH_LEN                  5                                   /**< Length of the URI path that causes the server to reset to a known state */
#define UNSAFE_URI_PATH                     "unsafe"                            /**< URI path that causes the server to include an unsafe option in the response */
#define UNSAFE_URI_PATH_LEN                 6                                   /**< Length of the URI path that causes the server to include an unsafe option in the response */
#define REGULAR_URI_PATH                    "regular"                           /**< URI path that causes the server to use regular (i.e. non-blockwise) transfers */
#define REGULAR_URI_PATH_LEN                7                                   /**< Length of the URI path that causes the server to use regular (i.e. non-blockwise) transfers */
#define LIB_LEVEL_BLOCKWISE_URI_PATH        "lib-level-blockwise"               /**< URI path that causes the server to use library-level blockwise transfers */
#define LIB_LEVEL_BLOCKWISE_URI_PATH_LEN    19                                  /**< Length of the URI path that causes the server to use library-level blockwise transfers */
#define SOCKET_TIMEOUT                      120                                 /**< Timeout for TLS/IPv6 socket operations */
#define RESP_BUF_LEN                        1024                                /**< Size of the buffer used to store responses */

/**
 *  @brief HTTP client test message data structure
 */
typedef struct
{
    char *req_str;                                                              /**< String containing the HTTP request to transmit */
    const char **start;                                                         /**< Array of start line values expected in the HTTP response */
    size_t num_headers;                                                         /**< Number of headers to look for in the HTTP response */
    const char **name;                                                          /**< Array of header names expected in the HTTP response */
    const char **value;                                                         /**< Array of header values expected in the HTTP response */
    const char *body;                                                           /**< String containing the expected body in the HTTP response */
}
test_http_client_msg_t;

/**
 *  @brief HTTP client test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    test_http_client_msg_t *msg;                                                /**< Array of test message structures */
    size_t num_msg;                                                             /**< Length of the array of test message structures */
}
test_http_client_data_t;

#define TEST1_NUM_MSGS     1
#define TEST1_NUM_HEADERS  1

const char *test1_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test1_name[TEST1_NUM_HEADERS] = {"Content-Length"};
const char *test1_value[TEST1_NUM_HEADERS] = {"16"};

test_http_client_msg_t test1_msg[TEST1_NUM_MSGS] =
{
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        .start = test1_start,
        .num_headers = TEST1_NUM_HEADERS,
        .name = test1_name,
        .value = test1_value,
        .body = "qwertyuiopasdfgh"
    }
};

test_http_client_data_t test1_data =
{
    .desc = "test 1: Send a GET request",
    .msg = test1_msg,
    .num_msg = TEST1_NUM_MSGS
};

#define TEST2_NUM_MSGS     2
#define TEST2_NUM_HEADERS  1

const char *test2_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test2_name[TEST2_NUM_HEADERS] = {"Content-Length"};
const char *test2_value[TEST2_NUM_HEADERS] = {"16"};

test_http_client_msg_t test2_msg[TEST2_NUM_MSGS] =
{
    {
        .req_str = "PUT coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\nContent-Length: 16\r\n\r\n0123456789abcdef",
        .start = test2_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    },
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\n\r\n",
        .start = test2_start,
        .num_headers = TEST2_NUM_HEADERS,
        .name = test2_name,
        .value = test2_value,
        .body = "0123456789abcdef"
    }
};

test_http_client_data_t test2_data =
{
    .desc = "test 2: Send a PUT request followed by a GET request",
    .msg = test2_msg,
    .num_msg = TEST2_NUM_MSGS
};

#define TEST3_NUM_MSGS     2
#define TEST3_NUM_HEADERS  1

const char *test3_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test3_name[TEST3_NUM_HEADERS] = {"Content-Length"};
const char *test3_value[TEST3_NUM_HEADERS] = {"16"};

test_http_client_msg_t test3_msg[TEST3_NUM_MSGS] =
{
    {
        .req_str = "POST coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\nContent-Length: 16\r\n\r\nzxcvbnmasdfghjkl",
        .start = test3_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    },
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\n\r\n",
        .start = test3_start,
        .num_headers = TEST3_NUM_HEADERS,
        .name = test3_name,
        .value = test3_value,
        .body = "zxcvbnmasdfghjkl"
    }
};

test_http_client_data_t test3_data =
{
    .desc = "test 3: Send a POST request followed by a GET request",
    .msg = test3_msg,
    .num_msg = TEST3_NUM_MSGS
};

#define TEST4_NUM_MSGS  1

const char *test4_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "501", "Not Implemented"};

test_http_client_msg_t test4_msg[TEST4_NUM_MSGS] =
{
    {
        .req_str = "CONNECT coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\nContent-Length: 12\r\n\r\nUnsupported!",
        .start = test4_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    }
};

test_http_client_data_t test4_data =
{
    .desc = "test 4: Send a request with an unsupported method",
    .msg = test4_msg,
    .num_msg = TEST4_NUM_MSGS
};

#define TEST5_NUM_MSGS  1

const char *test5_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "400", "Bad Request"};

test_http_client_msg_t test5_msg[TEST5_NUM_MSGS] =
{
    {
        .req_str = "GET dummy://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\nContent-Length: 12\r\n\r\nUnsupported!",
        .start = test5_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    }
};

test_http_client_data_t test5_data =
{
    .desc = "test 5: Send a request with an unsupported method",
    .msg = test5_msg,
    .num_msg = TEST5_NUM_MSGS
};

#define TEST6_NUM_MSGS  1

const char *test6_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "406", "Not Acceptable"};

test_http_client_msg_t test6_msg[TEST6_NUM_MSGS] =
{
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"REGULAR_URI_PATH" HTTP/1.1\r\nAccept: unsupported/format\r\nContent-Length: 12\r\n\r\nUnsupported!",
        .start = test6_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    }
};

test_http_client_data_t test6_data =
{
    .desc = "test 6: Send a request with an unsupported Accept header value",
    .msg = test6_msg,
    .num_msg = TEST6_NUM_MSGS
};

#define TEST7_NUM_MSGS  1

const char *test7_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "502", "Bad Gateway"};

test_http_client_msg_t test7_msg[TEST7_NUM_MSGS] =
{
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"UNSAFE_URI_PATH" HTTP/1.1\r\nContent-Length: 7\r\n\r\nUnsafe!",
        .start = test7_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    }
};

test_http_client_data_t test7_data =
{
    .desc = "test 7: Send a request that will invoke a response from the CoAP server with an unsafe option",
    .msg = test7_msg,
    .num_msg = TEST7_NUM_MSGS
};

#define TEST8_NUM_MSGS     1
#define TEST8_NUM_HEADERS  1

const char *test8_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test8_name[TEST8_NUM_HEADERS] = {"Content-Length"};
const char *test8_value[TEST8_NUM_HEADERS] = {"72"};

test_http_client_msg_t test8_msg[TEST8_NUM_MSGS] =
{
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"LIB_LEVEL_BLOCKWISE_URI_PATH" HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        .start = test8_start,
        .num_headers = TEST8_NUM_HEADERS,
        .name = test8_name,
        .value = test8_value,
        .body = "0123456789abcdefghijABCDEFGHIJasdfghjklpqlfktnghrexi49s1zlkdfiecvntfbghq"
    }
};

test_http_client_data_t test8_data =
{
    .desc = "test 8: perform a GET request that invokes a blockwise transfer from the server",
    .msg = test8_msg,
    .num_msg = TEST8_NUM_MSGS
};

#define TEST9_NUM_MSGS     2
#define TEST9_NUM_HEADERS  1

const char *test9_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test9_name[TEST9_NUM_HEADERS] = {"Content-Length"};
const char *test9_value[TEST9_NUM_HEADERS] = {"72"};

test_http_client_msg_t test9_msg[TEST9_NUM_MSGS] =
{
    {
        .req_str = "PUT coaps://"SERVER_HOST":12436/"LIB_LEVEL_BLOCKWISE_URI_PATH" HTTP/1.1\r\nContent-Length: 72\r\n\r\n" \
                   "cnierugpuedg[sdklgw9045ut6sw]gmk045gtj0gbmw09igh[iwrtjhywpwouihj54giuhsw",
        .start = test9_start,
        .num_headers = 0,
        .name = NULL,
        .value = NULL,
        .body = NULL
    },
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"LIB_LEVEL_BLOCKWISE_URI_PATH" HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        .start = test9_start,
        .num_headers = TEST9_NUM_HEADERS,
        .name = test9_name,
        .value = test9_value,
        .body = "cnierugpuedg[sdklgw9045ut6sw]gmk045gtj0gbmw09igh[iwrtjhywpwouihj54giuhsw"
    }
};

test_http_client_data_t test9_data =
{
    .desc = "test 9: perform PUT and GET requests that invoke blockwise transfers from the server",
    .msg = test9_msg,
    .num_msg = TEST9_NUM_MSGS
};

#define TEST10_NUM_MSGS     2
#define TEST10_NUM_HEADERS  1

const char *test10_start[HTTP_MSG_NUM_START] = {"HTTP/1.1", "200", "OK"};
const char *test10_name[TEST10_NUM_HEADERS] = {"Content-Length"};
const char *test10_value[TEST10_NUM_HEADERS] = {"72"};

test_http_client_msg_t test10_msg[TEST10_NUM_MSGS] =
{
    {
        .req_str = "POST coaps://"SERVER_HOST":12436/"LIB_LEVEL_BLOCKWISE_URI_PATH" HTTP/1.1\r\nContent-Length: 72\r\n\r\n" \
                   "982gjwojkdfnsg9aqu84h3t89quagornzggvbjkqnafhjqb34gtuiohaeriuyjboiqgtasdq",
        .start = test10_start,
        .num_headers = 0,
        .name = test10_name,
        .value = test10_value,
        .body = "982gjwojkdfnsg9aqu84h3t89quagornzggvbjkqnafhjqb34gtuiohaeriuyjboiqgtasdq"
    },
    {
        .req_str = "GET coaps://"SERVER_HOST":12436/"LIB_LEVEL_BLOCKWISE_URI_PATH" HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        .start = test10_start,
        .num_headers = TEST10_NUM_HEADERS,
        .name = test10_name,
        .value = test10_value,
        .body = "982gjwojkdfnsg9aqu84h3t89quagornzggvbjkqnafhjqb34gtuiohaeriuyjboiqgtasdq"
    }
};

test_http_client_data_t test10_data =
{
    .desc = "test 10: perform POST and GET requests that invoke blockwise transfers from the server",
    .msg = test10_msg,
    .num_msg = TEST10_NUM_MSGS
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
static test_result_t check_start(test_http_client_msg_t *test_msg, http_msg_t *msg)
{
    unsigned i = 0;

    for (i = 0; i < HTTP_MSG_NUM_START; i++)
    {
        if (strcmp(http_msg_get_start(msg, i), test_msg->start[i]) != 0)
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
static test_result_t check_headers(test_http_client_msg_t *test_msg, http_msg_t *msg)
{
    unsigned i = 0;

    for (i = 0; i < test_msg->num_headers; i++)
    {
        if (check_header(msg, test_msg->name[i], test_msg->value[i]) != PASS)
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
static test_result_t check_body(test_http_client_msg_t *test_msg, http_msg_t *msg)
{
    size_t len = 0;

    if (test_msg->body == NULL)
    {
        if (http_msg_get_body(msg) != NULL)
        {
            return FAIL;
        }
    }
    else
    {
        len = strlen(test_msg->body);
        if (http_msg_get_body(msg) == NULL)
        {
            return FAIL;
        }
        if (http_msg_get_body_len(msg) != len)
        {
            return FAIL;
        }
        if (memcmp(http_msg_get_body(msg), test_msg->body, len) != 0)
        {
            return FAIL;
        }
    }
    return PASS;
}

/**
 *  @brief Send a reset message to the server
 *
 *  @returns Error code
 *  @retval 0 Success
 *  @retval <0 Error
 */
static test_result_t send_reset(void)
{
    const char *str = "GET coaps://"SERVER_HOST":12436/"RESET_URI_PATH" HTTP/1.1\r\n\r\n";
    tls_sock_t s = {0};
    char resp_buf[RESP_BUF_LEN] = {0};
    int ret = 0;

    coap_log_info("Sending reset message to the server via the proxy");

    ret = tls_sock_open(&s, &client, PROXY_HOST, PROXY_PORT, SERVER_COMMON_NAME, SOCKET_TIMEOUT);
    if (ret != SOCK_OK)
    {
        return -1;
    }
    ret = tls_sock_write_full(&s, (char *)str, strlen(str));
    if (ret <= 0)
    {
        tls_sock_close(&s);
        return -1;
    }
    coap_log_info("Sent:\n%s", str);
    ret = tls_sock_read(&s, resp_buf, sizeof(resp_buf));
    if (ret <= 0)
    {
        tls_sock_close(&s);
        return -1;
    }
    coap_log_info("Received:\n%s", resp_buf);
    tls_sock_close(&s);
    return 0;
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
    unsigned i = 0;
    char resp_buf[RESP_BUF_LEN] = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    send_reset();

    ret = tls_sock_open(&s, &client, PROXY_HOST, PROXY_PORT, SERVER_COMMON_NAME, SOCKET_TIMEOUT);
    if (ret != SOCK_OK)
    {
        return FAIL;
    }
    for (i = 0; i < test_data->num_msg; i++)
    {
        ret = tls_sock_write_full(&s, test_data->msg[i].req_str, strlen(test_data->msg[i].req_str));
        if (ret <= 0)
        {
            tls_sock_close(&s);
            return FAIL;
        }
        coap_log_info("Sent:\n%s", test_data->msg[i].req_str);
        ret = tls_sock_read(&s, resp_buf, sizeof(resp_buf));
        if (ret <= 0)
        {
            tls_sock_close(&s);
            return FAIL;
        }
        coap_log_info("Received:\n%s", resp_buf);
        http_msg_create(&resp_msg);
        ret = http_msg_parse(&resp_msg, resp_buf, strlen(resp_buf));
        if (ret <= 0)
        {
            http_msg_destroy(&resp_msg);
            tls_sock_close(&s);
            return FAIL;
        }
        if (check_start(&test_data->msg[i], &resp_msg) != PASS)
        {
            result = FAIL;
        }
        if (check_headers(&test_data->msg[i], &resp_msg) != PASS)
        {
            result = FAIL;
        }
        if (check_body(&test_data->msg[i], &resp_msg) != PASS)
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
    test_t tests[] = {{test_exchange_func, &test1_data},
                      {test_exchange_func, &test2_data},
                      {test_exchange_func, &test3_data},
                      {test_exchange_func, &test4_data},
                      {test_exchange_func, &test5_data},
                      {test_exchange_func, &test6_data},
                      {test_exchange_func, &test7_data},
                      {test_exchange_func, &test8_data},
                      {test_exchange_func, &test9_data},
                      {test_exchange_func, &test10_data}};

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
    default:
        num_tests = 10;
        num_pass = test_run(tests, num_tests);
    }

    tls_client_destroy(&client);
    tls_deinit();

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
