/*
 * Copyright (c) 2014 Keith Cullen.
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
 *  @file test_http_msg.c
 *
 *  @brief Source file for the FreeCoAP HTTP message parser/formatter unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "http_msg.h"
#include "test.h"

#define DIM(x) (sizeof(x) / sizeof(x[0]))                                       /**< Calculate the size of an array */

/**
 *  @brief HTTP message test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    const char *str;                                                            /**< String representation of a HTTP message */
    size_t str_len;                                                             /**< Length of the HTTP message string */
    size_t parse_buf_len;                                                       /**< Length of the buffer used to parse HTTP messages */
    size_t generate_buf_len;                                                    /**< Length of the buffer used to generate HTTP messages */
    size_t num_headers;                                                         /**< Number of headers in a HTTP message */
    const char **set_start;                                                     /**< Array of strings containing HTTP start values */
    const char **set_name;                                                      /**< Array of strings containing HTTP header names */
    const char **set_value;                                                     /**< Array of strings containing HTTP header values */
    const char *set_body;                                                       /**< String containing a HTTP body */
    ssize_t exp_set_start_ret;                                                  /**< Expected return value of the HTTP message set-start operation */
    ssize_t exp_set_header_ret;                                                 /**< Expected return value of the HTTP message set-header operation */
    ssize_t exp_set_body_ret;                                                   /**< Expected return value of the HTTP message set-body operation */
    ssize_t exp_parse_ret;                                                      /**< Expected return value of the HTTP message parse operation */
    size_t exp_generate_ret;                                                    /**< Expected return value of the HTTP message generate operation */
    const char **exp_start;                                                     /**< Array of strings containing expected HTTP start values */
    const char **exp_name;                                                      /**< Array of strings containing expected HTTP header names */
    const char **exp_value;                                                     /**< Array of strings containing expected HTTP header values */
    const char *exp_body;                                                       /**< String containing an expected HTTP body */
    const char *exp_str;                                                        /**< String containing an expected HTTP message */
    size_t exp_str_len;                                                         /**< Length of the string containing an expected HTTP message */
}
test_http_msg_data_t;

#define TEST1_NUM_HEADERS  2

const char *test1_start[] = {"GET", "/", "HTTP/1.1"};
const char *test1_name[TEST1_NUM_HEADERS] = {"name1", "name2"};
const char *test1_value[TEST1_NUM_HEADERS] = {"value1", "value2"};

test_http_msg_data_t test1_data =
{
    .desc = "test  1 : set message fields, check message fields",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 256,
    .num_headers = TEST1_NUM_HEADERS,
    .set_start = test1_start,
    .set_name = test1_name,
    .set_value = test1_value,
    .set_body = "body",
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 52,
    .exp_start = test1_start,
    .exp_name = test1_name,
    .exp_value = test1_value,
    .exp_body = "body",
    .exp_str = "GET / HTTP/1.1\r\nname1: value1\r\nname2: value2\r\n\r\nbody",
    .exp_str_len = 52
};

#define TEST2_NUM_HEADERS  2

const char *test2_start[] = {"GET", "/", "HTTP/1.1"};
const char *test2_name[TEST2_NUM_HEADERS] = {"name", "name"};
const char *test2_value[TEST2_NUM_HEADERS] = {"value1", "value2"};

test_http_msg_data_t test2_data =
{
    .desc = "test  2 : set message fields including duplicate headers, check message fields",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 256,
    .num_headers = TEST2_NUM_HEADERS,
    .set_start = test2_start,
    .set_name = test2_name,
    .set_value = test2_value,
    .set_body = "body",
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 50,
    .exp_start = test2_start,
    .exp_name = test2_name,
    .exp_value = test2_value,
    .exp_body = "body",
    .exp_str = "GET / HTTP/1.1\r\nname: value1\r\nname: value2\r\n\r\nbody",
    .exp_str_len = 50
};

#define TEST3_NUM_HEADERS  2

const char *test3_start[] = {"S1", "S2", "S3"};
const char *test3_name[TEST3_NUM_HEADERS] = {"Content-Length", "name"};
const char *test3_value[TEST3_NUM_HEADERS] = {"4", "value"};

test_http_msg_data_t test3_data =
{
    .desc = "test  3 : parse message, check message fields",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\nname: value\r\n\r\nbody",
    .str_len = 48,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST3_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 48,
    .exp_generate_ret = 0,
    .exp_start = test3_start,
    .exp_name = test3_name,
    .exp_value = test3_value,
    .exp_body = "body",
    .exp_str = NULL,
    .exp_str_len = 0
};

#define TEST4_NUM_HEADERS  3

const char *test4_start[] = {"S1", "S2", "S3"};
const char *test4_name[TEST4_NUM_HEADERS] = {"Content-Length", "name", "name"};
const char *test4_value[TEST4_NUM_HEADERS] = {"4", "value1", "value2"};

test_http_msg_data_t test4_data =
{
    .desc = "test  4 : parse message containing duplicate headers, check message fields",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\nname: value1\r\nname: value2\r\n\r\nbody",
    .str_len = 63,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST4_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 63,
    .exp_generate_ret = 0,
    .exp_start = test4_start,
    .exp_name = test4_name,
    .exp_value = test4_value,
    .exp_body = "body",
    .exp_str = NULL,
    .exp_str_len = 0
};

#define TEST5_NUM_HEADERS  2

const char *test5_start[] = {"S1", "S2", "S3"};
const char *test5_name[TEST5_NUM_HEADERS] = {"Content-Length", "name"};
const char *test5_value[TEST5_NUM_HEADERS] = {"4", "value"};

test_http_msg_data_t test5_data =
{
    .desc = "test  5 : parse message with terminating null character, check message fields",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\nname: value\r\n\r\nbody",
    .str_len = 49,    /* size of buffer not string */
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST5_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 48,
    .exp_generate_ret = 0,
    .exp_start = test5_start,
    .exp_name = test5_name,
    .exp_value = test5_value,
    .exp_body = "body",
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test6_data =
{
    .desc = "test  6 : parse message, generate message, check buffer",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\nname: value\r\n\r\nbody",
    .str_len = 48,
    .parse_buf_len = 256,
    .generate_buf_len = 256,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 48,
    .exp_generate_ret = 48,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "S1 S2 S3\r\nContent-Length: 4\r\nname: value\r\n\r\nbody",
    .exp_str_len = 48
};

#define TEST7_NUM_HEADERS  2

const char *test7_start[] = {"S1", "S2", "S3"};
const char *test7_name[TEST7_NUM_HEADERS] = {"Transfer-Encoding", "name"};
const char *test7_value[TEST7_NUM_HEADERS] = {"chunked", "value"};

test_http_msg_data_t test7_data =
{
    .desc = "test  7 : parse message with chunked transfer encoding, check message fields",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname: value\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n",
    .str_len = 80,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST7_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 80,
    .exp_generate_ret = 0,
    .exp_start = test7_start,
    .exp_name = test7_name,
    .exp_value = test7_value,
    .exp_body = "chunk1chunk2",
    .exp_str = NULL,
    .exp_str_len = 0
};

#define TEST8_NUM_HEADERS  2

const char *test8_start[] = {"S1", "S2", "S3"};
const char *test8_name[TEST8_NUM_HEADERS] = {"Transfer-Encoding", "name"};
const char *test8_value[TEST8_NUM_HEADERS] = {"chunked", "value"};

test_http_msg_data_t test8_data =
{
    .desc = "test  8 : parse message with chunked transfer encoding and chunk-size parameter, check message fields",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname: value\r\n\r\n6;name=value\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n",
    .str_len = 91,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST8_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 91,
    .exp_generate_ret = 0,
    .exp_start = test8_start,
    .exp_name = test8_name,
    .exp_value = test8_value,
    .exp_body = "chunk1chunk2",
    .exp_str = NULL,
    .exp_str_len = 0
};

#define TEST9_NUM_HEADERS  2

const char *test9_start[] = {"S1", "S2", "S3"};
const char *test9_name[TEST9_NUM_HEADERS] = {"Transfer-Encoding", "name"};
const char *test9_value[TEST9_NUM_HEADERS] = {"chunked", "value"};

test_http_msg_data_t test9_data =
{
    .desc = "test  9 : parse message with chunked transfer encoding and trailers, check message fields",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\nname: value\r\n\r\n",
    .str_len = 80,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST9_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 80,
    .exp_generate_ret = 0,
    .exp_start = test9_start,
    .exp_name = test9_name,
    .exp_value = test9_value,
    .exp_body = "chunk1chunk2",
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test10_data =
{
    .desc = "test 10 : parse message with chunked transfer encoding and trailers, generate message, check buffer",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname1: value1\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\nname2: value2\r\n\r\n",
    .str_len = 97,
    .parse_buf_len = 256,
    .generate_buf_len = 256,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 97,
    .exp_generate_ret = 82,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname1: value1\r\nname2: value2\r\n\r\nchunk1chunk2",
    .exp_str_len = 82
};

#define TEST11_NUM_HEADERS  2

const char *test11_start[] = {"S1", "S2", "S3"};
const char *test11_name[TEST11_NUM_HEADERS] = {"Content-Length", "name"};
const char *test11_value[TEST11_NUM_HEADERS] = {"4", "\" value \""};

test_http_msg_data_t test11_data =
{
    .desc = "test 11 : parse message containing quoted header value, check message fields",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\nname: \" value \"\r\n\r\nbody",
    .str_len = 52,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST11_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 52,
    .exp_generate_ret = 0,
    .exp_start = test11_start,
    .exp_name = test11_name,
    .exp_value = test11_value,
    .exp_body = "body",
    .exp_str = NULL,
    .exp_str_len = 0
};

#define TEST12_NUM_HEADERS  2

const char *test12_start[] = {"S1", "S2", "S3"};
const char *test12_name[TEST12_NUM_HEADERS] = {"Content-Length", "\" name \""};
const char *test12_value[TEST12_NUM_HEADERS] = {"4", "value"};

test_http_msg_data_t test12_data =
{
    .desc = "test 12 : parse message containing quoted header name, check message fields",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\n\" name \": value\r\n\r\nbody",
    .str_len = 52,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST12_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 52,
    .exp_generate_ret = 0,
    .exp_start = test12_start,
    .exp_name = test12_name,
    .exp_value = test12_value,
    .exp_body = "body",
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test13_data =
{
    .desc = "test 13 : parse messages back-to-back, generate messages, check buffer",
    .str = "S1 S2 S3\r\nContent-Length: 5\r\nname1: value1\r\n\r\nbody1T4 T5 T6\r\nContent-Length: 6\r\nname2: value2\r\n\r\nbody02",
    .str_len = 103,
    .parse_buf_len = 256,
    .generate_buf_len = 256,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 51,
    .exp_generate_ret = 51,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "S1 S2 S3\r\nContent-Length: 5\r\nname1: value1\r\n\r\nbody1T4 T5 T6\r\nContent-Length: 6\r\nname2: value2\r\n\r\nbody02",
    .exp_str_len = 103
};

test_http_msg_data_t test14_data =
{
    .desc = "test 14 : parse message, generate message to buffer of insufficient size, check buffer",
    .str = "S1 S2 S3\r\nContent-Length: 4\r\nname: value\r\n\r\nbody",
    .str_len = 48,
    .parse_buf_len = 256,
    .generate_buf_len = 16,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 48,
    .exp_generate_ret = 48,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "S1 S2 S3\r\nConte",
    .exp_str_len = 15
};

test_http_msg_data_t test15_data =
{
    .desc = "test 15 : parse message with incomplete start line field",
    .str = "S1\r\nname: value\r\n\r\n",
    .str_len = 19,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test16_data =
{
    .desc = "test 16 : parse message with incomplete start line field",
    .str = "S1 \r\nname: value\r\n\r\n",
    .str_len = 20,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test17_data =
{
    .desc = "test 17 : parse message with incomplete start line field",
    .str = "S1 S2\r\nname: value\r\n\r\n",
    .str_len = 22,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test18_data =
{
    .desc = "test 18 : parse message with incomplete start line field",
    .str = "S1 S2 \r\nname: value\r\n\r\n",
    .str_len = 23,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test19_data =
{
    .desc = "test 19 : parse message with incomplete start line field",
    .str = "S1  S3\r\nname: value\r\n\r\n",
    .str_len = 23,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test20_data =
{
    .desc = "test 20 : parse message with incomplete header name",
    .str = "S1 S2 S3\r\nname",
    .str_len = 14,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EAGAIN,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test21_data =
{
    .desc = "test 21 : parse message with incomplete header value",
    .str = "S1 S2 S3\r\nname: value",
    .str_len = 21,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EAGAIN,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test22_data =
{
    .desc = "test 22 : parse message with incomplete header",
    .str = "S1 S2 S3\r\nname1: value1\r\nname2: value2\r\n",
    .str_len = 40,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EAGAIN,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test23_data =
{
    .desc = "test 23 : parse message with incomplete body",
    .str = "S1 S2 S3\r\nContent-Length: 1024\r\n\r\nbody...",
    .str_len = 41,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EAGAIN,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test24_data =
{
    .desc = "test 24 : parse message with chunked transfer encoding and invalid chunk-size",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname: value\r\n\r\n6\r\nchunk1\r\nG\r\nchunk2\r\n0\r\n\r\n",
    .str_len = 80,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test25_data =
{
    .desc = "test 25 : parse message with chunked transfer encoding and incomplete chunk-size",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname: value\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0",
    .str_len = 76,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EAGAIN,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test26_data =
{
    .desc = "test 26 : parse message with chunked transfer encoding and invalid trailer",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname: value\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\nname\r\n\r\n",
    .str_len = 86,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EBADMSG,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test27_data =
{
    .desc = "test 27 : parse message with chunked transfer encoding and incomplete trailer",
    .str = "S1 S2 S3\r\nTransfer-Encoding: chunked\r\nname: value\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\nname: value\r\n",
    .str_len = 91,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = -EAGAIN,
    .exp_generate_ret = 0,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

const char *test28_start[] = {"S1", "S2", "S3"};
const char *test28_name[] = {""};
const char *test28_value[] = {""};

test_http_msg_data_t test28_data =
{
    .desc = "test 28 : parse message with no headers",
    .str = "S1 S2 S3\r\n\r\nbody",
    .str_len = 16,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 12,
    .exp_generate_ret = 0,
    .exp_start = test28_start,
    .exp_name = test28_name,
    .exp_value = test28_value,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

#define TEST29_NUM_HEADERS  1

const char *test29_start[] = {"S1", "S2", "S3"};
const char *test29_name[TEST29_NUM_HEADERS] = {"name"};
const char *test29_value[TEST29_NUM_HEADERS] = {"value"};

test_http_msg_data_t test29_data =
{
    .desc = "test 29 : parse message with no content-length or transfer-encoding headers",
    .str = "S1 S2 S3\r\nname: value\r\n\r\n",
    .str_len = 25,
    .parse_buf_len = 256,
    .generate_buf_len = 0,
    .num_headers = TEST29_NUM_HEADERS,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 25,
    .exp_generate_ret = 0,
    .exp_start = test29_start,
    .exp_name = test29_name,
    .exp_value = test29_value,
    .exp_body = NULL,
    .exp_str = NULL,
    .exp_str_len = 0
};

test_http_msg_data_t test30_data =
{
    .desc = "test 30 : generate chunk, check buffer",
    .str = "body",
    .str_len = 4,
    .parse_buf_len = 0,
    .generate_buf_len = 256,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 9,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "4\r\nbody\r\n",
    .exp_str_len = 9
};

test_http_msg_data_t test31_data =
{
    .desc = "test 31 : generate chunk to buffer of insufficient size, check buffer",
    .str = "0123456789ABCDEF",
    .str_len = 16,
    .parse_buf_len = 0,
    .generate_buf_len = 16,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 22,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "10\r\n0123456789A",
    .exp_str_len = 15
};

test_http_msg_data_t test32_data =
{
    .desc = "test 32 : generate last chunk, check buffer",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 256,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 3,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "0\r\n",
    .exp_str_len = 3
};

test_http_msg_data_t test33_data =
{
    .desc = "test 33 : generate last chunk to buffer of insufficient size, check buffer",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 3,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 3,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "0\r",
    .exp_str_len = 2
};

#define TEST34_NUM_HEADERS  1

const char *test34_name[TEST34_NUM_HEADERS] = {"name"};
const char *test34_value[TEST34_NUM_HEADERS] = {"value"};

test_http_msg_data_t test34_data =
{
    .desc = "test 34 : generate trailer, check buffer",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 256,
    .num_headers = TEST34_NUM_HEADERS,
    .set_start = NULL,
    .set_name = test34_name,
    .set_value = test34_value,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 13,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "name: value\r\n",
    .exp_str_len = 13
};

#define TEST35_NUM_HEADERS  1

const char *test35_name[TEST35_NUM_HEADERS] = {"name"};
const char *test35_value[TEST35_NUM_HEADERS] = {"value"};

test_http_msg_data_t test35_data =
{
    .desc = "test 35 : generate trailer to buffer of insufficient size, check buffer",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 10,
    .num_headers = TEST35_NUM_HEADERS,
    .set_start = NULL,
    .set_name = test35_name,
    .set_value = test35_value,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 13,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "name: val",
    .exp_str_len = 9
};

test_http_msg_data_t test36_data =
{
    .desc = "test 36 : generate blank line, check buffer",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 256,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 2,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "\r\n",
    .exp_str_len = 2
};

test_http_msg_data_t test37_data =
{
    .desc = "test 37 : generate blank line to buffer of insufficient size, check buffer",
    .str = NULL,
    .str_len = 0,
    .parse_buf_len = 0,
    .generate_buf_len = 2,
    .num_headers = 0,
    .set_start = NULL,
    .set_name = NULL,
    .set_value = NULL,
    .set_body = NULL,
    .exp_set_start_ret = 0,
    .exp_set_header_ret = 0,
    .exp_set_body_ret = 0,
    .exp_parse_ret = 0,
    .exp_generate_ret = 2,
    .exp_start = NULL,
    .exp_name = NULL,
    .exp_value = NULL,
    .exp_body = NULL,
    .exp_str = "\r",
    .exp_str_len = 1
};

/**
 *  @brief Check the start fields in a HTTP message
 *
 *  @param[out] result Pointer to a result object
 *  @param[in] msg Pointer to a HTTP message structure
 *  @param[in] start1 String containing the expected first start value
 *  @param[in] start2 String containing the expected second start value
 *  @param[in] start3 String containing the expected third start value
 */
static void test_check_start(test_result_t *result, http_msg_t *msg, const char *start1, const char *start2, const char *start3)
{
    if ((http_msg_get_start(msg, 0) == NULL)
     || (strcmp(http_msg_get_start(msg, 0), start1) != 0))
    {
        *result = FAIL;
    }
    if ((http_msg_get_start(msg, 1) == NULL)
     || (strcmp(http_msg_get_start(msg, 1), start2) != 0))
    {
        *result = FAIL;
    }
    if ((http_msg_get_start(msg, 2) == NULL)
     || (strcmp(http_msg_get_start(msg, 2), start3) != 0))
    {
        *result = FAIL;
    }
}

/**
 *  @brief Check a header in a HTTP message
 *
 *  @param[out] result Pointer to a result object
 *  @param[in] msg Pointer to a HTTP message structure
 *  @param[in] name String containing the expected header name
 *  @param[in] value String containing the expected header value
 */
static void test_check_header(test_result_t *result, http_msg_t *msg, const char *name, const char *value)
{
    http_msg_header_t *header = NULL;
    int match = 0;

    header = http_msg_get_first_header(msg);
    while (header != NULL)
    {
        if ((strcmp(http_msg_header_get_name(header), name) == 0)
         && (strcmp(http_msg_header_get_value(header), value) == 0))
        {
            match = 1;
        }
        header = http_msg_header_get_next(header);
    }
    if (!match)
    {
        *result = FAIL;
    }
}

/**
 *  @brief Check the body in a HTTP message
 *
 *  @param[out] result Pointer to a result object
 *  @param[in] msg Pointer to a HTTP message structure
 *  @param[in] str String containing the expected HTTP message body
 */
static void test_check_body(test_result_t *result, http_msg_t *msg, const char *str)
{
    size_t len = 0;

    if (str == NULL)
    {
        if (http_msg_get_body(msg) != NULL)
        {
            *result = FAIL;
        }
    }
    else
    {
        len = strlen(str);
        if ((http_msg_get_body(msg) == NULL)
         || (http_msg_get_body_len(msg) != len)
         || (memcmp(http_msg_get_body(msg), str, len) != 0))
        {
            *result = FAIL;
        }
    }
}

/**
 *  @brief Set HTTP message fields, check the message fields, generate a HTTP message and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_set_check_gen_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    size_t num = 0;
    size_t i = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];
    int ret = 0;

    printf("%s\n", test_data->desc);

    /* create message */
    http_msg_create(&msg);

    /* set start line */
    ret = http_msg_set_start(&msg, test_data->set_start[0], test_data->set_start[1], test_data->set_start[2]);
    if (ret != test_data->exp_set_start_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* add headers */
    for (i = 0; i < test_data->num_headers; i++)
    {
        ret = http_msg_set_header(&msg, test_data->set_name[i], test_data->set_value[i]);
        if (ret != test_data->exp_set_header_ret)
        {
            http_msg_destroy(&msg);
            return FAIL;
        }
    }

    /* set body */
    http_msg_set_body(&msg, test_data->set_body, strlen(test_data->set_body));
    if (ret != test_data->exp_set_body_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check start line */
    test_check_start(&result, &msg, test_data->exp_start[0], test_data->exp_start[1], test_data->exp_start[2]);

    /* check headers */
    for (i = 0; i < test_data->num_headers; i++)
    {
        test_check_header(&result, &msg, test_data->exp_name[i], test_data->exp_value[i]);
    }

    /* check body */
    test_check_body(&result, &msg, test_data->exp_body);

    /* generate message */
    num = http_msg_generate(&msg, generate_buf, sizeof(generate_buf));
    if (num != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Parse a HTTP message and check the message fields
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_parse_check_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    ssize_t num = 0;
    size_t i = 0;
    http_msg_t msg = {{0}};
    char parse_buf[test_data->parse_buf_len];

    printf("%s\n", test_data->desc);

    snprintf(parse_buf, sizeof(parse_buf), "%s", test_data->str);

    http_msg_create(&msg);

    /* parse message */
    num = http_msg_parse(&msg, parse_buf, test_data->str_len);
    if (num != test_data->exp_parse_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check start line */
    test_check_start(&result, &msg, test_data->exp_start[0], test_data->exp_start[1], test_data->exp_start[2]);

    /* check headers */
    for (i = 0; i < test_data->num_headers; i++)
    {
        test_check_header(&result, &msg, test_data->exp_name[i], test_data->exp_value[i]);
    }

    /* check body */
    test_check_body(&result, &msg, test_data->exp_body);

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Parse a HTTP message
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_parse_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    ssize_t num = 0;
    http_msg_t msg = {{0}};
    char parse_buf[test_data->parse_buf_len];

    printf("%s\n", test_data->desc);

    snprintf(parse_buf, sizeof(parse_buf), "%s", test_data->str);

    http_msg_create(&msg);

    /* parse message */
    num = http_msg_parse(&msg, parse_buf, test_data->str_len);
    if (num != test_data->exp_parse_ret)
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Parse a HTTP message, regenerate the message and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_parse_gen_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    ssize_t num = 0;
    size_t str_len = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];
    char parse_buf[test_data->parse_buf_len];

    printf("%s\n", test_data->desc);

    snprintf(parse_buf, sizeof(parse_buf), "%s", test_data->str);

    http_msg_create(&msg);

    /* parse message */
    num = http_msg_parse(&msg, parse_buf, test_data->str_len);
    if (num != test_data->exp_parse_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* generate message */
    str_len = http_msg_generate(&msg, generate_buf, sizeof(generate_buf));
    if (str_len != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Parse and regenerate two HTTP messages back-to-back
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_double_parse_gen_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    ssize_t num1 = 0;
    ssize_t num2 = 0;
    size_t str_len1 = 0;
    size_t str_len2 = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];
    char parse_buf[test_data->parse_buf_len];

    printf("%s\n", test_data->desc);

    snprintf(parse_buf, sizeof(parse_buf), "%s", test_data->str);

    http_msg_create(&msg);

    /* parse 1st message */
    num1 = http_msg_parse(&msg, parse_buf, test_data->str_len);
    if (num1 != test_data->exp_parse_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* generate 1st message */
    str_len1 = http_msg_generate(&msg, generate_buf, sizeof(generate_buf));
    if (str_len1 != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* parse 2nd message */
    num2 = http_msg_parse(&msg, parse_buf + num1, test_data->str_len - num1);
    if (num1 + num2 != test_data->str_len)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* generate 2nd message */
    str_len2 = http_msg_generate(&msg, generate_buf + str_len1, sizeof(generate_buf) - str_len1);
    if (str_len1 + str_len2 != test_data->exp_str_len)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Parse a HTTP message, check the message fields, regenerate the message and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_parse_check_gen_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    ssize_t num = 0;
    size_t str_len = 0;
    size_t i = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];
    char parse_buf[test_data->parse_buf_len];

    printf("%s\n", test_data->desc);

    snprintf(parse_buf, sizeof(parse_buf), "%s", test_data->str);

    http_msg_create(&msg);

    /* parse message */
    num = http_msg_parse(&msg, parse_buf, test_data->str_len);
    if (num != test_data->exp_parse_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check start line */
    test_check_start(&result, &msg, test_data->exp_start[0], test_data->exp_start[1], test_data->exp_start[2]);

    /* check headers */
    for (i = 0; i < test_data->num_headers; i++)
    {
        test_check_header(&result, &msg, test_data->exp_name[i], test_data->exp_value[i]);
    }

    /* check body */
    test_check_body(&result, &msg, test_data->exp_body);

    /* generate message */
    str_len = http_msg_generate(&msg, generate_buf, sizeof(generate_buf));
    if (str_len != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Generate a chunk of a HTTP message body and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
 test_result_t test_gen_chunk_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    size_t str_len = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];

    printf("%s\n", test_data->desc);

    /* generate chunk */
    str_len = http_msg_generate_chunk(generate_buf, sizeof(generate_buf), test_data->str, test_data->str_len);
    if (str_len != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Generate the last chunk of a HTTP message body and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_gen_last_chunk_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    size_t str_len = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];

    printf("%s\n", test_data->desc);

    /* generate last chunk */
    str_len = http_msg_generate_last_chunk(generate_buf, sizeof(generate_buf));
    if (str_len != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Generate a trailer in a HTTP message and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_gen_trailer_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    size_t str_len = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];

    printf("%s\n", test_data->desc);

    /* generate trailer */
    str_len = http_msg_generate_trailer(generate_buf, sizeof(generate_buf), test_data->set_name[0], test_data->set_value[0]);
    if (str_len != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Generate a blank line and check the result
 *
 *  @param[in] data Pointer to a HTTP message test data structure
 *
 *  @returns Test result
 */
test_result_t test_gen_blank_line_func(test_data_t data)
{
    test_http_msg_data_t *test_data = (test_http_msg_data_t *)data;
    test_result_t result = PASS;
    size_t str_len = 0;
    http_msg_t msg = {{0}};
    char generate_buf[test_data->generate_buf_len];

    printf("%s\n", test_data->desc);

    /* generate blank line */
    str_len = http_msg_generate_blank_line(generate_buf, sizeof(generate_buf));
    if (str_len != test_data->exp_generate_ret)
    {
        http_msg_destroy(&msg);
        return FAIL;
    }

    /* check buffer */
    if ((strlen(generate_buf) != test_data->exp_str_len)
     || (strcmp(generate_buf, test_data->exp_str) != 0))
    {
        result = FAIL;
    }

    http_msg_destroy(&msg);

    return result;
}

/**
 *  @brief Main function for the FreeCoAP HTTP message parser/formatter unit tests
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main()
{
    test_t tests[] = {{test_set_check_gen_func, &test1_data},
                      {test_set_check_gen_func, &test2_data},
                      {test_parse_check_func, &test3_data},
                      {test_parse_check_func, &test4_data},
                      {test_parse_check_func, &test5_data},
                      {test_parse_gen_func, &test6_data},
                      {test_parse_check_func, &test7_data},
                      {test_parse_check_func, &test8_data},
                      {test_parse_check_func, &test9_data},
                      {test_parse_gen_func, &test10_data},
                      {test_parse_check_func, &test11_data},
                      {test_parse_check_func, &test12_data},
                      {test_double_parse_gen_func, &test13_data},
                      {test_parse_gen_func, &test14_data},
                      {test_parse_func, &test15_data},
                      {test_parse_func, &test16_data},
                      {test_parse_func, &test17_data},
                      {test_parse_func, &test18_data},
                      {test_parse_func, &test19_data},
                      {test_parse_func, &test20_data},
                      {test_parse_func, &test21_data},
                      {test_parse_func, &test22_data},
                      {test_parse_func, &test23_data},
                      {test_parse_func, &test24_data},
                      {test_parse_func, &test25_data},
                      {test_parse_func, &test26_data},
                      {test_parse_func, &test27_data},
                      {test_parse_check_func, &test28_data},
                      {test_parse_check_func, &test29_data},
                      {test_gen_chunk_func, &test30_data},
                      {test_gen_chunk_func, &test31_data},
                      {test_gen_last_chunk_func, &test32_data},
                      {test_gen_last_chunk_func, &test33_data},
                      {test_gen_trailer_func, &test34_data},
                      {test_gen_trailer_func, &test35_data},
                      {test_gen_blank_line_func, &test36_data},
                      {test_gen_blank_line_func, &test37_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
