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
 *  @file test_coap_msg.c
 *
 *  @brief Source file for the FreeCoAP message parser/formatter unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "coap_msg.h"
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
 *  @brief Message option test data structure
 */
typedef struct
{
    unsigned num;                                                               /**< Option number */
    unsigned len;                                                               /**< Option length */
    char *val;                                                                  /**< Pointer to a buffer containing the option value */
    unsigned block_num;                                                         /**< Block number for Block1 or Block2 option */
    unsigned block_more;                                                        /**< More value for Block1 or Block2 option */
    unsigned block_size;                                                        /**< Block size (in bytes) for Block1 or Block2 option */
}
test_coap_msg_op_t;

/**
 *  @brief Message test data structure
 */
typedef struct
{
    const char *parse_desc;                                                     /**< Test description for the parse test */
    const char *format_desc;                                                    /**< Test description for the format test */
    const char *copy_desc;                                                      /**< Test description for the copy test */
    const char *recognize_desc;                                                 /**< Test description for the recognize test */
    const char *check_critical_desc;                                            /**< Test description for the check critical options test */
    const char *check_unsafe_desc;                                              /**< Test description for the check unsafe options test */
    const char *uri_path_to_str_desc;                                           /**< Test description for the URI path to string representation test */
    ssize_t parse_ret;                                                          /**< Expected return value for the parse function */
    int set_type_ret;                                                           /**< Expected return value for the set type function */
    int set_code_ret;                                                           /**< Expected return value for the set code function */
    int set_msg_id_ret;                                                         /**< Expected return value for the set message ID function */
    int set_token_ret;                                                          /**< Expected return value for the set token function */
    int *add_op_ret;                                                            /**< Expected return value for the add option function */
    int set_payload_ret;                                                        /**< Expected return value for the set payload function */
    ssize_t format_ret;                                                         /**< Expected return value for the format function */
    int copy_ret;                                                               /**< Expected return value for the copy function */
    int *recognize_ret;                                                         /**< Expected return value for the recognize function */
    unsigned check_critical_ops_ret;                                            /**< Expected return value for the check critical options function */
    unsigned check_unsafe_ops_ret;                                              /**< Expected return value for the check unsafe options function */
    size_t uri_path_to_str_ret;                                                 /**< Expected return value for the URI path to string function */
    char *buf;                                                                  /**< Buffer containing a message */
    size_t buf_len;                                                             /**< Length of the buffer containing a message */
    unsigned ver;                                                               /**< CoAP version */
    coap_msg_type_t type;                                                       /**< Message type */
    unsigned code_class;                                                        /**< Message code class */
    unsigned code_detail;                                                       /**< Message code detail */
    unsigned msg_id;                                                            /**< Message ID */
    char *token;                                                                /**< Buffer containing a token */
    size_t token_len;                                                           /**< Length of the buffer containing a token */
    test_coap_msg_op_t *ops;                                                    /**< Array of message option test data structures */
    unsigned num_ops;                                                           /**< Size of the array of message option test data structures */
    char *payload;                                                              /**< Buffer containing a payload */
    size_t payload_len;                                                         /**< Length of the buffer containing a payload */
}
test_coap_msg_data_t;

#define TEST1_BUF_LEN      (4 + 8 + 5 + 9 + 1 + 16)
#define TEST1_TOKEN_LEN    8
#define TEST1_OP1_LEN      4
#define TEST1_OP2_LEN      8
#define TEST1_NUM_OPS      2
#define TEST1_PAYLOAD_LEN  16

int test1_add_op_ret[TEST1_NUM_OPS] = {0, 0};
char test1_buf[TEST1_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0x18, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test1_token[TEST1_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test1_op1_val[TEST1_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test1_op2_val[TEST1_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
test_coap_msg_op_t test1_ops[TEST1_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST1_OP1_LEN,
        .val = test1_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 1,
        .len = TEST1_OP2_LEN,
        .val = test1_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test1_payload[TEST1_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test1_data =
{
    .parse_desc = "test  1: parse CoAP message with token, with options, with payload",
    .format_desc = "test 27: format CoAP message with token, with options, with payload",
    .copy_desc = "test 51: copy CoAP message with token, with options, with payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test1_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST1_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test1_buf,
    .buf_len = TEST1_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test1_token,
    .token_len = TEST1_TOKEN_LEN,
    .ops = test1_ops,
    .num_ops = TEST1_NUM_OPS,
    .payload = test1_payload,
    .payload_len = TEST1_PAYLOAD_LEN
};

#define TEST2_BUF_LEN      (4 + 5 + 9 + 1 + 16)
#define TEST2_OP1_LEN      4
#define TEST2_OP2_LEN      8
#define TEST2_NUM_OPS      2
#define TEST2_PAYLOAD_LEN  16

int test2_add_op_ret[TEST2_NUM_OPS] = {0, 0};
char test2_buf[TEST2_BUF_LEN] =
{
    /* header:         */ 0x50, 0x44, 0x12, 0x34,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0x18, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test2_op1_val[TEST2_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test2_op2_val[TEST2_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
test_coap_msg_op_t test2_ops[TEST2_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST2_OP1_LEN,
        .val = test2_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 1,
        .len = TEST2_OP2_LEN,
        .val = test2_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test2_payload[TEST2_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test2_data =
{
    .parse_desc = "test  2: parse CoAP message with no token, with options, with payload",
    .format_desc = "test 28: format CoAP message with no token, with options, with payload",
    .copy_desc = "test 52: copy CoAP message with no token, with options, with payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test2_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST2_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test2_buf,
    .buf_len = TEST2_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = test1_ops,
    .num_ops = TEST2_NUM_OPS,
    .payload = test1_payload,
    .payload_len = TEST2_PAYLOAD_LEN
};

#define TEST3_BUF_LEN      (4 + 8 + 1 + 16)
#define TEST3_TOKEN_LEN    8
#define TEST3_PAYLOAD_LEN  16

char test3_buf[TEST3_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test3_token[TEST3_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test3_payload[TEST3_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test3_data =
{
    .parse_desc = "test  3: parse CoAP message with token, with no options, with payload",
    .format_desc = "test 29: format CoAP message with token, with no options, with payload",
    .copy_desc = "test 53: copy CoAP message with token, with no options, with payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = TEST3_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test3_buf,
    .buf_len = TEST3_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test3_token,
    .token_len = TEST3_TOKEN_LEN,
    .ops = NULL,
    .num_ops = 0,
    .payload = test3_payload,
    .payload_len = TEST3_PAYLOAD_LEN
};

#define TEST4_BUF_LEN    (4 + 8 + 5 + 9)
#define TEST4_TOKEN_LEN  8
#define TEST4_OP1_LEN    4
#define TEST4_OP2_LEN    8
#define TEST4_NUM_OPS    2

int test4_add_op_ret[TEST4_NUM_OPS] = {0, 0};
char test4_buf[TEST4_BUF_LEN] =
{
    /* header:  */ 0x58, 0x44, 0x12, 0x34,
    /* token:   */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1: */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2: */ 0x18, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8
};
char test4_token[TEST4_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test4_op1_val[TEST4_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test4_op2_val[TEST4_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
test_coap_msg_op_t test4_ops[TEST4_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST4_OP1_LEN,
        .val = test4_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 1,
        .len = TEST4_OP2_LEN,
        .val = test4_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test4_data =
{
    .parse_desc = "test  4: parse CoAP message with token, with options, with no payload",
    .format_desc = "test 30: format CoAP message with token, with options, with no payload",
    .copy_desc = "test 54: copy CoAP message with token, with options, with no payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test4_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST4_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test4_buf,
    .buf_len = TEST4_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test4_token,
    .token_len = TEST4_TOKEN_LEN,
    .ops = test4_ops,
    .num_ops = TEST4_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST5_BUF_LEN      (4 + 1 + 16)
#define TEST5_PAYLOAD_LEN  16

char test5_buf[TEST5_BUF_LEN] =
{
    /* header:         */ 0x50, 0x44, 0x12, 0x34,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test5_payload[TEST5_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test5_data =
{
    .parse_desc = "test  5: parse CoAP message with no token, with no options, with payload",
    .format_desc = "test 31: format CoAP message with no token, with no options, with payload",
    .copy_desc = "test 55: copy CoAP message with no token, with no options, with payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = TEST5_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test5_buf,
    .buf_len = TEST5_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = test5_payload,
    .payload_len = TEST5_PAYLOAD_LEN
};

#define TEST6_BUF_LEN  (4 + 5 + 9)
#define TEST6_OP1_LEN  4
#define TEST6_OP2_LEN  8
#define TEST6_NUM_OPS  2

int test6_add_op_ret[TEST6_NUM_OPS] = {0, 0};
char test6_buf[TEST6_BUF_LEN] =
{
    /* header:  */ 0x50, 0x44, 0x12, 0x34,
    /* option1: */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2: */ 0x18, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8
};
char test6_op1_val[TEST6_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test6_op2_val[TEST6_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
test_coap_msg_op_t test6_ops[TEST6_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST6_OP1_LEN,
        .val = test6_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 1,
        .len = TEST6_OP2_LEN,
        .val = test6_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test6_data =
{
    .parse_desc = "test  6: parse CoAP message with no token, with options, with no payload",
    .format_desc = "test 32: format CoAP message with no token, with options, with no payload",
    .copy_desc = "test 56: copy CoAP message with no token, with options, with no payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test6_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST6_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test6_buf,
    .buf_len = TEST6_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = test6_ops,
    .num_ops = TEST6_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST7_BUF_LEN    (4 + 8)
#define TEST7_TOKEN_LEN  8

char test7_buf[TEST7_BUF_LEN] =
{
    /* header: */ 0x58, 0x44, 0x12, 0x34,
    /* token:  */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
char test7_token[TEST7_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

test_coap_msg_data_t test7_data =
{
    .parse_desc = "test  7: parse CoAP message with token, with no options, with no payload",
    .format_desc = "test 33: format CoAP message with token, with no options, with no payload",
    .copy_desc = "test 57: copy CoAP message with token, with no options, with no payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = TEST7_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test7_buf,
    .buf_len = TEST7_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test7_token,
    .token_len = TEST7_TOKEN_LEN,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST8_BUF_LEN  4

char test8_buf[TEST8_BUF_LEN] =
{
    /* header: */ 0x50, 0x44, 0x12, 0x34,
};

test_coap_msg_data_t test8_data =
{
    .parse_desc = "test  8: parse CoAP message with no token, with no options, with no payload",
    .format_desc = "test 34: format CoAP message with no token, with no options, with no payload",
    .copy_desc = "test 58: copy CoAP message with no token, with no options, with no payload",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = TEST8_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test8_buf,
    .buf_len = TEST8_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST9_BUF_LEN      (4 + 8 + 5 + 10 + 1 + 16)
#define TEST9_TOKEN_LEN    8
#define TEST9_OP1_LEN      4
#define TEST9_OP2_LEN      8
#define TEST9_NUM_OPS      2
#define TEST9_PAYLOAD_LEN  16

int test9_add_op_ret[TEST9_NUM_OPS] = {0, 0};
char test9_buf[TEST9_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0xd8, 0x01, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test9_token[TEST9_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test9_op1_val[TEST9_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test9_op2_val[TEST9_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
test_coap_msg_op_t test9_ops[TEST9_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST9_OP1_LEN,
        .val = test9_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 13 + 0x01,
        .len = TEST9_OP2_LEN,
        .val = test9_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test9_payload[TEST9_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test9_data =
{
    .parse_desc = "test  9: parse CoAP message with option delta extended by 1-byte",
    .format_desc = "test 35: format CoAP message with option delta extended by 1-byte",
    .copy_desc = "test 59: copy CoAP message with option delta extended by 1-byte",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test9_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST9_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test9_buf,
    .buf_len = TEST9_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test9_token,
    .token_len = TEST9_TOKEN_LEN,
    .ops = test9_ops,
    .num_ops = TEST9_NUM_OPS,
    .payload = test9_payload,
    .payload_len = TEST9_PAYLOAD_LEN
};

#define TEST10_BUF_LEN      (4 + 8 + 5 + 11 + 1 + 16)
#define TEST10_TOKEN_LEN    8
#define TEST10_OP1_LEN      4
#define TEST10_OP2_LEN      8
#define TEST10_NUM_OPS      2
#define TEST10_PAYLOAD_LEN  16

int test10_add_op_ret[TEST10_NUM_OPS] = {0, 0};
char test10_buf[TEST10_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0xe8, 0x01, 0x02, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test10_token[TEST10_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test10_op1_val[TEST10_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test10_op2_val[TEST10_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
test_coap_msg_op_t test10_ops[TEST10_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST10_OP1_LEN,
        .val = test10_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 269 + 0x0102,
        .len = TEST10_OP2_LEN,
        .val = test10_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test10_payload[TEST10_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test10_data =
{
    .parse_desc = "test 10: parse CoAP message with option delta extended by 2-bytes",
    .format_desc = "test 36: format CoAP message with option delta extended by 2-bytes",
    .copy_desc = "test 60: copy CoAP message with option delta extended by 2-bytes",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test10_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST10_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test10_buf,
    .buf_len = TEST10_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test10_token,
    .token_len = TEST10_TOKEN_LEN,
    .ops = test10_ops,
    .num_ops = TEST10_NUM_OPS,
    .payload = test10_payload,
    .payload_len = TEST10_PAYLOAD_LEN
};

#define TEST11_BUF_LEN      (4 + 8 + 5 + 16 + 1 + 16)
#define TEST11_TOKEN_LEN    8
#define TEST11_OP1_LEN      4
#define TEST11_OP2_LEN      (13 + 0x01)
#define TEST11_NUM_OPS      2
#define TEST11_PAYLOAD_LEN  16

int test11_add_op_ret[TEST11_NUM_OPS] = {0, 0};
char test11_buf[TEST11_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0x1d, 0x01, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test11_token[TEST11_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test11_op1_val[TEST11_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test11_op2_val[TEST11_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe};
test_coap_msg_op_t test11_ops[TEST11_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST11_OP1_LEN,
        .val = test11_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 1,
        .len = TEST11_OP2_LEN,
        .val = test11_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test11_payload[TEST11_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test11_data =
{
    .parse_desc = "test 11: parse CoAP message with option length extended by 1-byte",
    .format_desc = "test 37: format CoAP message with option length extended by 1-byte",
    .copy_desc = "test 61: copy CoAP message with option length extended by 1-byte",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test11_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST11_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test11_buf,
    .buf_len = TEST11_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test11_token,
    .token_len = TEST11_TOKEN_LEN,
    .ops = test11_ops,
    .num_ops = TEST11_NUM_OPS,
    .payload = test11_payload,
    .payload_len = TEST11_PAYLOAD_LEN
};

#define TEST12_BUF_LEN      (4 + 8 + 5 + 530 + 1 + 16)
#define TEST12_TOKEN_LEN    8
#define TEST12_OP1_LEN      4
#define TEST12_OP2_LEN      (269 + 0x0102)
#define TEST12_NUM_OPS      2
#define TEST12_PAYLOAD_LEN  16

int test12_add_op_ret[TEST12_NUM_OPS] = {0, 0};
char test12_buf[TEST12_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0x1e, 0x01, 0x02, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test12_token[TEST12_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test12_op1_val[TEST12_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test12_op2_val[TEST12_OP2_LEN] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e};
test_coap_msg_op_t test12_ops[TEST12_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST12_OP1_LEN,
        .val = test12_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 1,
        .len = TEST12_OP2_LEN,
        .val = test12_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test12_payload[TEST12_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test12_data =
{
    .parse_desc = "test 12: parse CoAP message with option length extended by 2-bytes",
    .format_desc = "test 38: format CoAP message with option length extended by 2-bytes",
    .copy_desc = "test 62: copy CoAP message with option length extended by 2-bytes",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test12_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST12_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test12_buf,
    .buf_len = TEST12_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test12_token,
    .token_len = TEST12_TOKEN_LEN,
    .ops = test12_ops,
    .num_ops = TEST12_NUM_OPS,
    .payload = test12_payload,
    .payload_len = TEST12_PAYLOAD_LEN
};

#define TEST13_BUF_LEN      (4 + 8 + 5 + 17 + 1 + 16)
#define TEST13_TOKEN_LEN    8
#define TEST13_OP1_LEN      4
#define TEST13_OP2_LEN      (13 + 0x01)
#define TEST13_NUM_OPS      2
#define TEST13_PAYLOAD_LEN  16

int test13_add_op_ret[TEST13_NUM_OPS] = {0, 0};
char test13_buf[TEST13_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0xdd, 0x02, 0x01, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test13_token[TEST13_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test13_op1_val[TEST13_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test13_op2_val[TEST13_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe};
test_coap_msg_op_t test13_ops[TEST13_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST13_OP1_LEN,
        .val = test13_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 13 + 0x02,
        .len = TEST13_OP2_LEN,
        .val = test13_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test13_payload[TEST13_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test13_data =
{
    .parse_desc = "test 13: parse CoAP message with option delta extended by 1-byte and option length extended by 1-byte",
    .format_desc = "test 39: format CoAP message with option delta extended by 1-byte and option length extended by 1-byte",
    .copy_desc = "test 63: parse CoAP message with option delta extended by 1-byte and option length extended by 1-byte",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test13_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST13_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test13_buf,
    .buf_len = TEST13_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test13_token,
    .token_len = TEST13_TOKEN_LEN,
    .ops = test13_ops,
    .num_ops = TEST13_NUM_OPS,
    .payload = test13_payload,
    .payload_len = TEST13_PAYLOAD_LEN
};

#define TEST14_BUF_LEN      (4 + 8 + 5 + 18 + 1 + 16)
#define TEST14_TOKEN_LEN    8
#define TEST14_OP1_LEN      4
#define TEST14_OP2_LEN      (13 + 0x01)
#define TEST14_NUM_OPS      2
#define TEST14_PAYLOAD_LEN  16

int test14_add_op_ret[TEST14_NUM_OPS] = {0, 0};
char test14_buf[TEST14_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0xed, 0x02, 0x03, 0x01, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test14_token[TEST14_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test14_op1_val[TEST14_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test14_op2_val[TEST14_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe};
test_coap_msg_op_t test14_ops[TEST14_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST14_OP1_LEN,
        .val = test14_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 269 + 0x0203,
        .len = TEST14_OP2_LEN,
        .val = test14_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test14_payload[TEST14_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test14_data =
{
    .parse_desc = "test 14: parse CoAP message with option delta extended by 2-bytes and option length extended by 1-byte",
    .format_desc = "test 40: format CoAP message with option delta extended by 2-bytes and option length extended by 1-byte",
    .copy_desc = "test 64: copy CoAP message with option delta extended by 2-bytes and option length extended by 1-byte",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test14_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST14_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test14_buf,
    .buf_len = TEST14_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test14_token,
    .token_len = TEST14_TOKEN_LEN,
    .ops = test14_ops,
    .num_ops = TEST14_NUM_OPS,
    .payload = test14_payload,
    .payload_len = TEST14_PAYLOAD_LEN
};

#define TEST15_BUF_LEN      (4 + 8 + 5 + 531 + 1 + 16)
#define TEST15_TOKEN_LEN    8
#define TEST15_OP1_LEN      4
#define TEST15_OP2_LEN      (269 + 0x0102)
#define TEST15_NUM_OPS      2
#define TEST15_PAYLOAD_LEN  16

int test15_add_op_ret[TEST15_NUM_OPS] = {0, 0};
char test15_buf[TEST15_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0xde, 0x03, 0x01, 0x02, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test15_token[TEST15_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test15_op1_val[TEST15_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test15_op2_val[TEST15_OP2_LEN] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e};
test_coap_msg_op_t test15_ops[TEST15_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST15_OP1_LEN,
        .val = test15_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 13 + 0x03,
        .len = TEST15_OP2_LEN,
        .val = test15_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test15_payload[TEST15_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test15_data =
{
    .parse_desc = "test 15: parse CoAP message with option delta extended by 1-byte and option length extended by 2-bytes",
    .format_desc = "test 41: format CoAP message with option delta extended by 1-byte and option length extended by 2-bytes",
    .copy_desc = "test 65: copy CoAP message with option delta extended by 1-byte and option length extended by 2-bytes",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test15_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST15_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test15_buf,
    .buf_len = TEST15_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test15_token,
    .token_len = TEST15_TOKEN_LEN,
    .ops = test15_ops,
    .num_ops = TEST15_NUM_OPS,
    .payload = test15_payload,
    .payload_len = TEST15_PAYLOAD_LEN
};

#define TEST16_BUF_LEN      (4 + 8 + 5 + 532 + 1 + 16)
#define TEST16_TOKEN_LEN    8
#define TEST16_OP1_LEN      4
#define TEST16_OP2_LEN      (269 + 0x0102)
#define TEST16_NUM_OPS      2
#define TEST16_PAYLOAD_LEN  16

int test16_add_op_ret[TEST16_NUM_OPS] = {0, 0};
char test16_buf[TEST16_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0xee, 0x03, 0x04, 0x01, 0x02, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test16_token[TEST16_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test16_op1_val[TEST16_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test16_op2_val[TEST16_OP2_LEN] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e};
test_coap_msg_op_t test16_ops[TEST16_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = TEST16_OP1_LEN,
        .val = test16_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 269 + 0x0304,
        .len = TEST16_OP2_LEN,
        .val = test16_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test16_payload[TEST16_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test16_data =
{
    .parse_desc = "test 16: parse CoAP message with option delta extended by 2-bytes and option length extended by 2-bytes",
    .format_desc = "test 42: format CoAP message with option delta extended by 2-bytes and option length extended by 2-bytes",
    .copy_desc = "test 66: copy CoAP message with option delta extended by 2-bytes and option length extended by 2-bytes",
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test16_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST16_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test16_buf,
    .buf_len = TEST16_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test16_token,
    .token_len = TEST16_TOKEN_LEN,
    .ops = test16_ops,
    .num_ops = TEST16_NUM_OPS,
    .payload = test16_payload,
    .payload_len = TEST16_PAYLOAD_LEN
};

#define TEST17_BUF_LEN  4

char test17_buf[TEST17_BUF_LEN] =
{
    /* header: */ 0x90, 0x44, 0x12, 0x34
};

test_coap_msg_data_t test17_data =
{
    .parse_desc = "test 17: parse CoAP message with invalid version",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EINVAL,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test17_buf,
    .buf_len = TEST17_BUF_LEN,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST18_BUF_LEN  4

char test18_buf[TEST18_BUF_LEN] =
{
    /* header: */ 0x50, 0x00, 0x12, 0x34
};

test_coap_msg_data_t test18_data =
{
    .parse_desc = "test 18: parse empty non-confirmable CoAP message",
    .format_desc = "test 43: format empty non-confirmable CoAP message",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = -EBADMSG,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test18_buf,
    .buf_len = TEST18_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST19_BUF_LEN  4

char test19_buf[TEST19_BUF_LEN] =
{
    /* header: */ 0x70, 0x44, 0x12, 0x34
};

test_coap_msg_data_t test19_data =
{
    .parse_desc = "test 19: parse non-empty reset CoAP message",
    .format_desc = "test 44: format non-empty reset CoAP message",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = -EBADMSG,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test19_buf,
    .buf_len = TEST19_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_RST,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST20_BUF_LEN    (4 + 9)
#define TEST20_TOKEN_LEN  9

char test20_buf[TEST20_BUF_LEN] =
{
    /* header: */ 0x59, 0x44, 0x12, 0x34,
    /* token:  */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
};
char test20_token[TEST20_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

test_coap_msg_data_t test20_data =
{
    .parse_desc = "test 20: parse CoAP message with invalid token length (9)",
    .format_desc = "test 45: format CoAP message with invalid token length (9)",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = -EINVAL,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test20_buf,
    .buf_len = TEST20_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test20_token,
    .token_len = TEST20_TOKEN_LEN,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST21_BUF_LEN    (4 + 15)
#define TEST21_TOKEN_LEN  15

char test21_buf[TEST21_BUF_LEN] =
{
    /* header: */ 0x5f, 0x44, 0x12, 0x34,
    /* token:  */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
char test21_token[TEST21_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

test_coap_msg_data_t test21_data =
{
    .parse_desc = "test 21: parse CoAP message with invalid token length (15)",
    .format_desc = "test 46: format CoAP message with invalid token length (15)",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = -EINVAL,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test21_buf,
    .buf_len = TEST21_BUF_LEN,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = test21_token,
    .token_len = TEST21_TOKEN_LEN,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST22_BUF_LEN    (4 + 8)
#define TEST22_TOKEN_LEN  8

char test22_buf[TEST22_BUF_LEN] =
{
    /* header: */ 0x58, 0x00, 0x12, 0x34,
    /* token:  */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
char test22_token[TEST22_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

test_coap_msg_data_t test22_data =
{
    .parse_desc = "test 22: parse empty CoAP message with non-zero token length",
    .format_desc = "test 47: format empty CoAP message with non-zero token length",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = -EBADMSG,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test22_buf,
    .buf_len = TEST22_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_CON,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0x1234,
    .token = test22_token,
    .token_len = TEST22_TOKEN_LEN,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST23_BUF_LEN      (4 + 1 + 16)
#define TEST23_PAYLOAD_LEN  16

char test23_buf[TEST23_BUF_LEN] =
{
    /* header:         */ 0x50, 0x00, 0x12, 0x34,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test23_payload[TEST23_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test23_data =
{
    .parse_desc = "test 23: parse empty CoAP message with payload",
    .format_desc = "test 48: format empty CoAP message with payload",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = -EBADMSG,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test23_buf,
    .buf_len = TEST23_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_CON,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0X3412,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = test23_payload,
    .payload_len = TEST23_PAYLOAD_LEN
};

#define TEST24_BUF_LEN  (4 + 5 + 9)

char test24_buf[TEST24_BUF_LEN] =
{
    /* header:  */ 0x50, 0x44, 0x12, 0x34,
    /* option1: */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2: */ 0xf8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8
};

test_coap_msg_data_t test24_data =
{
    .parse_desc = "test 24: parse CoAP message with invalid option delta",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test24_buf,
    .buf_len = TEST24_BUF_LEN,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST25_BUF_LEN  (4 + 5 + 16)

char test25_buf[TEST25_BUF_LEN] =
{
    /* header:  */ 0x50, 0x44, 0x12, 0x34,
    /* option1: */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2: */ 0x1f, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};

test_coap_msg_data_t test25_data =
{
    .parse_desc = "test 25: parse CoAP message with invalid option length",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test25_buf,
    .buf_len = TEST25_BUF_LEN,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST26_BUF_LEN  5

char test26_buf[TEST26_BUF_LEN] =
{
    /* header:         */ 0x50, 0x44, 0x12, 0x34,
    /* payload marker: */ 0xff
};

test_coap_msg_data_t test26_data =
{
    .parse_desc = "test 26: parse CoAP message with payload marker but no payload",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test26_buf,
    .buf_len = TEST26_BUF_LEN,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST27_BUF_LEN  4

char test27_buf[TEST27_BUF_LEN] =
{
    /* header: */ 0x50, 0x44, 0x12, 0x34
};

test_coap_msg_data_t test27_data =
{
    .parse_desc = "test 49: parse valid type and message ID",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test27_buf,
    .buf_len = TEST27_BUF_LEN,
    .ver = 0,
    .type = COAP_MSG_NON,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST28_BUF_LEN  3

char test28_buf[TEST28_BUF_LEN] =
{
    /* header: */ 0x50, 0x44, 0x12
};

test_coap_msg_data_t test28_data =
{
    .parse_desc = "test 50: parse invalid type and message ID",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EBADMSG,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test28_buf,
    .buf_len = TEST28_BUF_LEN,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
};

#define TEST29_OP1_LEN   1
#define TEST29_OP2_LEN   1
#define TEST29_OP3_LEN   1
#define TEST29_OP4_LEN   1
#define TEST29_OP5_LEN   1
#define TEST29_OP6_LEN   1
#define TEST29_OP7_LEN   1
#define TEST29_OP8_LEN   1
#define TEST29_OP9_LEN   1
#define TEST29_OP10_LEN  1
#define TEST29_OP11_LEN  1
#define TEST29_OP12_LEN  1
#define TEST29_OP13_LEN  1
#define TEST29_OP14_LEN  1
#define TEST29_OP15_LEN  1
#define TEST29_OP16_LEN  1
#define TEST29_OP17_LEN  1
#define TEST29_OP18_LEN  1
#define TEST29_OP19_LEN  1
#define TEST29_OP20_LEN  1
#define TEST29_NUM_OPS  20

int test29_recognize_ret[TEST29_NUM_OPS] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0};

char test29_op1_val[TEST29_OP1_LEN] = {0x01};
char test29_op2_val[TEST29_OP2_LEN] = {0x02};
char test29_op3_val[TEST29_OP3_LEN] = {0x03};
char test29_op4_val[TEST29_OP4_LEN] = {0x04};
char test29_op5_val[TEST29_OP5_LEN] = {0x05};
char test29_op6_val[TEST29_OP6_LEN] = {0x06};
char test29_op7_val[TEST29_OP7_LEN] = {0x07};
char test29_op8_val[TEST29_OP8_LEN] = {0x08};
char test29_op9_val[TEST29_OP9_LEN] = {0x09};
char test29_op10_val[TEST29_OP10_LEN] = {0x0a};
char test29_op11_val[TEST29_OP11_LEN] = {0x0b};
char test29_op12_val[TEST29_OP12_LEN] = {0x0c};
char test29_op13_val[TEST29_OP13_LEN] = {0x0d};
char test29_op14_val[TEST29_OP14_LEN] = {0x0e};
char test29_op15_val[TEST29_OP15_LEN] = {0x0f};
char test29_op16_val[TEST29_OP16_LEN] = {0x10};
char test29_op17_val[TEST29_OP17_LEN] = {0x11};
char test29_op18_val[TEST29_OP18_LEN] = {0x12};
char test29_op19_val[TEST29_OP19_LEN] = {0x13};
char test29_op20_val[TEST29_OP20_LEN] = {0x14};
test_coap_msg_op_t test29_ops[TEST29_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,
        .len = TEST29_OP1_LEN,
        .val = test29_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_URI_HOST,
        .len = TEST29_OP2_LEN,
        .val = test29_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_ETAG,
        .len = TEST29_OP3_LEN,
        .val = test29_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [3] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,
        .len = TEST29_OP4_LEN,
        .val = test29_op4_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [4] =
    {
        .num = COAP_MSG_URI_PORT,
        .len = TEST29_OP5_LEN,
        .val = test29_op5_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [5] =
    {
        .num = COAP_MSG_LOCATION_PATH,
        .len = TEST29_OP6_LEN,
        .val = test29_op6_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [6] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST29_OP7_LEN,
        .val = test29_op7_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [7] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,
        .len = TEST29_OP8_LEN,
        .val = test29_op8_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [8] =
    {
        .num = COAP_MSG_MAX_AGE,
        .len = TEST29_OP9_LEN,
        .val = test29_op9_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [9] =
    {
        .num = COAP_MSG_URI_QUERY,
        .len = TEST29_OP10_LEN,
        .val = test29_op10_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [10] =
    {
        .num = COAP_MSG_ACCEPT,
        .len = TEST29_OP11_LEN,
        .val = test29_op11_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [11] =
    {
        .num = COAP_MSG_LOCATION_QUERY,
        .len = TEST29_OP12_LEN,
        .val = test29_op12_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [12] =
    {
        .num = COAP_MSG_PROXY_URI,
        .len = TEST29_OP13_LEN,
        .val = test29_op13_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [13] =
    {
        .num = COAP_MSG_PROXY_SCHEME,
        .len = TEST29_OP14_LEN,
        .val = test29_op14_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [14] =
    {
        .num = COAP_MSG_SIZE1,
        .len = TEST29_OP15_LEN,
        .val = test29_op15_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [15] =
    {
        .num = 0x61,  /* unrecognized option number */
        .len = TEST29_OP16_LEN,
        .val = test29_op16_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [16] =
    {
        .num = 0x62,  /* unrecognized option number */
        .len = TEST29_OP17_LEN,
        .val = test29_op17_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [17] =
    {
        .num = 0x63,  /* unrecognized option number */
        .len = TEST29_OP18_LEN,
        .val = test29_op18_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [18] =
    {
        .num = 0x64,  /* unrecognized option number */
        .len = TEST29_OP19_LEN,
        .val = test29_op19_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [19] =
    {
        .num = 0x65,  /* unrecognized option number */
        .len = TEST29_OP20_LEN,
        .val = test29_op20_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test29_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = "test 67: Recognize option numbers",
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = test29_recognize_ret,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test29_ops,
    .num_ops = TEST29_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST30_OP1_LEN  1
#define TEST30_OP2_LEN  1
#define TEST30_OP3_LEN  1
#define TEST30_NUM_OPS  3

char test30_op1_val[TEST30_OP1_LEN] = {0x01};
char test30_op2_val[TEST30_OP2_LEN] = {0x02};
char test30_op3_val[TEST30_OP3_LEN] = {0x03};
test_coap_msg_op_t test30_ops[TEST30_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST30_OP1_LEN,
        .val = test30_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST30_OP2_LEN,
        .val = test30_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST30_OP3_LEN,
        .val = test30_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test30_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 68: Check recognized elective options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test30_ops,
    .num_ops = TEST30_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST31_OP1_LEN  1
#define TEST31_OP2_LEN  1
#define TEST31_OP3_LEN  1
#define TEST31_NUM_OPS  3

char test31_op1_val[TEST31_OP1_LEN] = {0x01};
char test31_op2_val[TEST31_OP2_LEN] = {0x02};
char test31_op3_val[TEST31_OP3_LEN] = {0x03};
test_coap_msg_op_t test31_ops[TEST31_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized critical */
        .len = TEST31_OP1_LEN,
        .val = test31_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST31_OP2_LEN,
        .val = test31_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST31_OP3_LEN,
        .val = test31_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test31_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 69: Check recognized elective and recognized critical options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test31_ops,
    .num_ops = TEST31_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST32_OP1_LEN  1
#define TEST32_OP2_LEN  1
#define TEST32_OP3_LEN  1
#define TEST32_NUM_OPS  3

char test32_op1_val[TEST32_OP1_LEN] = {0x01};
char test32_op2_val[TEST32_OP2_LEN] = {0x02};
char test32_op3_val[TEST32_OP3_LEN] = {0x03};
test_coap_msg_op_t test32_ops[TEST32_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST32_OP1_LEN,
        .val = test32_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_URI_HOST,  /* recognized critical */
        .len = TEST32_OP2_LEN,
        .val = test32_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST32_OP3_LEN,
        .val = test32_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test32_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 70: Check recognized elective and recognized critical options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test32_ops,
    .num_ops = TEST32_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST33_OP1_LEN  1
#define TEST33_OP2_LEN  1
#define TEST33_OP3_LEN  1
#define TEST33_NUM_OPS  3

char test33_op1_val[TEST33_OP1_LEN] = {0x01};
char test33_op2_val[TEST33_OP2_LEN] = {0x02};
char test33_op3_val[TEST33_OP3_LEN] = {0x03};
test_coap_msg_op_t test33_ops[TEST33_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST33_OP1_LEN,
        .val = test33_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST33_OP2_LEN,
        .val = test33_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized critical */
        .len = TEST33_OP3_LEN,
        .val = test33_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test33_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 71: Check recognized elective and recognized critical options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test33_ops,
    .num_ops = TEST33_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST34_OP1_LEN  1
#define TEST34_OP2_LEN  1
#define TEST34_OP3_LEN  1
#define TEST34_NUM_OPS  3

char test34_op1_val[TEST34_OP1_LEN] = {0x01};
char test34_op2_val[TEST34_OP2_LEN] = {0x02};
char test34_op3_val[TEST34_OP3_LEN] = {0x03};
test_coap_msg_op_t test34_ops[TEST34_NUM_OPS] =
{
    [0] =
    {
        .num = 0x62,  /* unrecognized elective */
        .len = TEST34_OP1_LEN,
        .val = test34_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST34_OP2_LEN,
        .val = test34_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST34_OP3_LEN,
        .val = test34_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test34_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 72: Check recognized and unrecognized elective options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test34_ops,
    .num_ops = TEST34_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST35_OP1_LEN  1
#define TEST35_OP2_LEN  1
#define TEST35_OP3_LEN  1
#define TEST35_NUM_OPS  3

char test35_op1_val[TEST35_OP1_LEN] = {0x01};
char test35_op2_val[TEST35_OP2_LEN] = {0x02};
char test35_op3_val[TEST35_OP3_LEN] = {0x03};
test_coap_msg_op_t test35_ops[TEST35_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST35_OP1_LEN,
        .val = test35_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 0x64,  /* unrecognized elective */
        .len = TEST35_OP2_LEN,
        .val = test35_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST35_OP3_LEN,
        .val = test35_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test35_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 73: Check recognized and unrecognized elective options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test35_ops,
    .num_ops = TEST35_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST36_OP1_LEN  1
#define TEST36_OP2_LEN  1
#define TEST36_OP3_LEN  1
#define TEST36_NUM_OPS  3

char test36_op1_val[TEST36_OP1_LEN] = {0x01};
char test36_op2_val[TEST36_OP2_LEN] = {0x02};
char test36_op3_val[TEST36_OP3_LEN] = {0x03};
test_coap_msg_op_t test36_ops[TEST36_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST36_OP1_LEN,
        .val = test36_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST36_OP2_LEN,
        .val = test36_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = 0x66,  /* unrecognized elective */
        .len = TEST36_OP3_LEN,
        .val = test36_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test36_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 74: Check recognized and unrecognized elective options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test36_ops,
    .num_ops = TEST36_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST37_OP1_LEN  1
#define TEST37_OP2_LEN  1
#define TEST37_OP3_LEN  1
#define TEST37_NUM_OPS  3

char test37_op1_val[TEST37_OP1_LEN] = {0x01};
char test37_op2_val[TEST37_OP2_LEN] = {0x02};
char test37_op3_val[TEST37_OP3_LEN] = {0x03};
test_coap_msg_op_t test37_ops[TEST37_NUM_OPS] =
{
    [0] =
    {
        .num = 0x61,  /* unrecognized critical */
        .len = TEST37_OP1_LEN,
        .val = test37_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST37_OP2_LEN,
        .val = test37_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST37_OP3_LEN,
        .val = test37_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test37_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 75: Check recognized elective and unrecognized critical options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0x61,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test37_ops,
    .num_ops = TEST37_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST38_OP1_LEN  1
#define TEST38_OP2_LEN  1
#define TEST38_OP3_LEN  1
#define TEST38_NUM_OPS  3

char test38_op1_val[TEST38_OP1_LEN] = {0x01};
char test38_op2_val[TEST38_OP2_LEN] = {0x02};
char test38_op3_val[TEST38_OP3_LEN] = {0x03};
test_coap_msg_op_t test38_ops[TEST38_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST38_OP1_LEN,
        .val = test38_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 0x63,  /* unrecognized critical */
        .len = TEST38_OP2_LEN,
        .val = test38_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_CONTENT_FORMAT,  /* recognized elective */
        .len = TEST38_OP3_LEN,
        .val = test38_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test38_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 76: Check recognized elective and unrecognized critical options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0x63,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test38_ops,
    .num_ops = TEST38_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST39_OP1_LEN  1
#define TEST39_OP2_LEN  1
#define TEST39_OP3_LEN  1
#define TEST39_NUM_OPS  3

char test39_op1_val[TEST39_OP1_LEN] = {0x01};
char test39_op2_val[TEST39_OP2_LEN] = {0x02};
char test39_op3_val[TEST39_OP3_LEN] = {0x03};
test_coap_msg_op_t test39_ops[TEST39_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_ETAG,  /* recognized elective */
        .len = TEST39_OP1_LEN,
        .val = test39_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_LOCATION_PATH,  /* recognized elective */
        .len = TEST39_OP2_LEN,
        .val = test39_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = 0x65,  /* unrecognized critical */
        .len = TEST39_OP3_LEN,
        .val = test39_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test39_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = "test 77: Check recognized elective and unrecognized critical options",
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0x65,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test39_ops,
    .num_ops = TEST39_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST40_OP1_LEN  1
#define TEST40_OP2_LEN  1
#define TEST40_OP3_LEN  1
#define TEST40_NUM_OPS  3

char test40_op1_val[TEST40_OP1_LEN] = {0x01};
char test40_op2_val[TEST40_OP2_LEN] = {0x02};
char test40_op3_val[TEST40_OP3_LEN] = {0x03};
test_coap_msg_op_t test40_ops[TEST40_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST40_OP1_LEN,
        .val = test40_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST40_OP2_LEN,
        .val = test40_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST40_OP3_LEN,
        .val = test40_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test40_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 78: Check recognized safe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test40_ops,
    .num_ops = TEST40_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST41_OP1_LEN  1
#define TEST41_OP2_LEN  1
#define TEST41_OP3_LEN  1
#define TEST41_NUM_OPS  3

char test41_op1_val[TEST41_OP1_LEN] = {0x01};
char test41_op2_val[TEST41_OP2_LEN] = {0x02};
char test41_op3_val[TEST41_OP3_LEN] = {0x03};
test_coap_msg_op_t test41_ops[TEST41_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_URI_HOST,  /* recognized unsafe */
        .len = TEST41_OP1_LEN,
        .val = test41_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST41_OP2_LEN,
        .val = test41_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST41_OP3_LEN,
        .val = test41_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test41_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 79: Check recognized safe and recognized unsafe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test41_ops,
    .num_ops = TEST41_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST42_OP1_LEN  1
#define TEST42_OP2_LEN  1
#define TEST42_OP3_LEN  1
#define TEST42_NUM_OPS  3

char test42_op1_val[TEST42_OP1_LEN] = {0x01};
char test42_op2_val[TEST42_OP2_LEN] = {0x02};
char test42_op3_val[TEST42_OP3_LEN] = {0x03};
test_coap_msg_op_t test42_ops[TEST42_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST42_OP1_LEN,
        .val = test42_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_URI_PORT,  /* recognized unsafe */
        .len = TEST42_OP2_LEN,
        .val = test42_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST42_OP3_LEN,
        .val = test42_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test42_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 80: Check recognized safe and recognized unsafe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test42_ops,
    .num_ops = TEST42_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST43_OP1_LEN  1
#define TEST43_OP2_LEN  1
#define TEST43_OP3_LEN  1
#define TEST43_NUM_OPS  3

char test43_op1_val[TEST43_OP1_LEN] = {0x01};
char test43_op2_val[TEST43_OP2_LEN] = {0x02};
char test43_op3_val[TEST43_OP3_LEN] = {0x03};
test_coap_msg_op_t test43_ops[TEST43_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST43_OP1_LEN,
        .val = test43_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST43_OP2_LEN,
        .val = test43_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_URI_PATH,  /* recognized unsafe */
        .len = TEST43_OP3_LEN,
        .val = test43_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test43_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 81: Check recognized safe and recognized unsafe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test43_ops,
    .num_ops = TEST43_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST44_OP1_LEN  1
#define TEST44_OP2_LEN  1
#define TEST44_OP3_LEN  1
#define TEST44_NUM_OPS  3

char test44_op1_val[TEST44_OP1_LEN] = {0x01};
char test44_op2_val[TEST44_OP2_LEN] = {0x02};
char test44_op3_val[TEST44_OP3_LEN] = {0x03};
test_coap_msg_op_t test44_ops[TEST44_NUM_OPS] =
{
    [0] =
    {
        .num = 0x61,  /* unrecognized safe */
        .len = TEST44_OP1_LEN,
        .val = test44_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST44_OP2_LEN,
        .val = test44_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST44_OP3_LEN,
        .val = test44_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test44_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 82: Check recognized and unrecognized safe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test44_ops,
    .num_ops = TEST44_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST45_OP1_LEN  1
#define TEST45_OP2_LEN  1
#define TEST45_OP3_LEN  1
#define TEST45_NUM_OPS  3

char test45_op1_val[TEST45_OP1_LEN] = {0x01};
char test45_op2_val[TEST45_OP2_LEN] = {0x02};
char test45_op3_val[TEST45_OP3_LEN] = {0x03};
test_coap_msg_op_t test45_ops[TEST45_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST45_OP1_LEN,
        .val = test45_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 0x64,  /* unrecognized safe */
        .len = TEST45_OP2_LEN,
        .val = test45_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST45_OP3_LEN,
        .val = test45_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test45_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 83: Check recognized and unrecognized safe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test45_ops,
    .num_ops = TEST45_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST46_OP1_LEN  1
#define TEST46_OP2_LEN  1
#define TEST46_OP3_LEN  1
#define TEST46_NUM_OPS  3

char test46_op1_val[TEST46_OP1_LEN] = {0x01};
char test46_op2_val[TEST46_OP2_LEN] = {0x02};
char test46_op3_val[TEST46_OP3_LEN] = {0x03};
test_coap_msg_op_t test46_ops[TEST46_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST46_OP1_LEN,
        .val = test46_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST46_OP2_LEN,
        .val = test46_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = 0x65,  /* unrecognized safe */
        .len = TEST46_OP3_LEN,
        .val = test46_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test46_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 84: Check recognized and unrecognized safe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test46_ops,
    .num_ops = TEST46_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST47_OP1_LEN  1
#define TEST47_OP2_LEN  1
#define TEST47_OP3_LEN  1
#define TEST47_NUM_OPS  3

char test47_op1_val[TEST47_OP1_LEN] = {0x01};
char test47_op2_val[TEST47_OP2_LEN] = {0x02};
char test47_op3_val[TEST47_OP3_LEN] = {0x03};
test_coap_msg_op_t test47_ops[TEST47_NUM_OPS] =
{
    [0] =
    {
        .num = 0x62,  /* unrecognized unsafe */
        .len = TEST47_OP1_LEN,
        .val = test47_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST47_OP2_LEN,
        .val = test47_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST47_OP3_LEN,
        .val = test47_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test47_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 85: Check recognized safe and unrecognized unsafe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0x62,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test47_ops,
    .num_ops = TEST47_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST48_OP1_LEN  1
#define TEST48_OP2_LEN  1
#define TEST48_OP3_LEN  1
#define TEST48_NUM_OPS  3

char test48_op1_val[TEST48_OP1_LEN] = {0x01};
char test48_op2_val[TEST48_OP2_LEN] = {0x02};
char test48_op3_val[TEST48_OP3_LEN] = {0x03};
test_coap_msg_op_t test48_ops[TEST48_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST48_OP1_LEN,
        .val = test48_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 0x63,  /* unrecognized unsafe */
        .len = TEST48_OP2_LEN,
        .val = test48_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_IF_NONE_MATCH,  /* recognized safe */
        .len = TEST48_OP3_LEN,
        .val = test48_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test48_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 86: Check recognized safe and unrecognized unsafe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0x63,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test48_ops,
    .num_ops = TEST48_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST49_OP1_LEN  1
#define TEST49_OP2_LEN  1
#define TEST49_OP3_LEN  1
#define TEST49_NUM_OPS  3

char test49_op1_val[TEST49_OP1_LEN] = {0x01};
char test49_op2_val[TEST49_OP2_LEN] = {0x02};
char test49_op3_val[TEST49_OP3_LEN] = {0x03};
test_coap_msg_op_t test49_ops[TEST49_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_IF_MATCH,  /* recognized safe */
        .len = TEST49_OP1_LEN,
        .val = test49_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_ETAG,  /* recognized safe */
        .len = TEST49_OP2_LEN,
        .val = test49_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = 0x66,  /* unrecognized unsafe */
        .len = TEST49_OP3_LEN,
        .val = test49_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test49_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = "test 87: Check recognized safe and unrecognized unsafe options",
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = NULL,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0x66,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test49_ops,
    .num_ops = TEST49_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST50_BUF_LEN      (4 + 8 + 5 + 9 + 5 + 5 + 5 + 1 + 16)
#define TEST50_TOKEN_LEN    8
#define TEST50_OP1_LEN      4
#define TEST50_OP2_LEN      8
#define TEST50_OP3_LEN      4
#define TEST50_OP4_LEN      4
#define TEST50_OP5_LEN      4
#define TEST50_NUM_OPS      5
#define TEST50_PAYLOAD_LEN  16

int test50_add_op_ret[TEST50_NUM_OPS] = {0, 0, 0, 0, 0};
char test50_buf[TEST50_BUF_LEN] =
{
    /* header:         */ 0x58, 0x44, 0x12, 0x34,
    /* token:          */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /* option1:        */ 0x04, 0xa1, 0xa2, 0xa3, 0xa4,
    /* option2:        */ 0x18, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    /* option3:        */ 0x04, 0xc1, 0xc2, 0xc3, 0xc4,
    /* option4:        */ 0x14, 0xd1, 0xd2, 0xd3, 0xd4,
    /* option5:        */ 0x14, 0xe1, 0xe2, 0xe3, 0xe4,
    /* payload marker: */ 0xff,
    /* payload:        */ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
char test50_token[TEST50_TOKEN_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char test50_op1_val[TEST50_OP1_LEN] = {0xa1, 0xa2, 0xa3, 0xa4};
char test50_op2_val[TEST50_OP2_LEN] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
char test50_op3_val[TEST50_OP3_LEN] = {0xc1, 0xc2, 0xc3, 0xc4};
char test50_op4_val[TEST50_OP4_LEN] = {0xd1, 0xd2, 0xd3, 0xd4};
char test50_op5_val[TEST50_OP5_LEN] = {0xe1, 0xe2, 0xe3, 0xe4};
test_coap_msg_op_t test50_ops[TEST50_NUM_OPS] =
{
    [0] =
    {
        /* option 4 */
        .num = 2,
        .len = TEST50_OP4_LEN,
        .val = test50_op4_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        /* option 1 */
        .num = 0,
        .len = TEST50_OP1_LEN,
        .val = test50_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        /* option 2 */
        .num = 1,
        .len = TEST50_OP2_LEN,
        .val = test50_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [3] =
    {
        /* option 5 */
        .num = 3,
        .len = TEST50_OP5_LEN,
        .val = test50_op5_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [4] =
    {
        /* option 3 */
        .num = 1,
        .len = TEST50_OP3_LEN,
        .val = test50_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};
char test50_payload[TEST50_PAYLOAD_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

test_coap_msg_data_t test50_data =
{
    .parse_desc = NULL,
    .format_desc = "test 88: format CoAP message with token, with options presented in the wrong order, with payload",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = test50_add_op_ret,
    .set_payload_ret = 0,
    .format_ret = TEST50_BUF_LEN,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = test50_buf,
    .buf_len = TEST50_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = test50_token,
    .token_len = TEST50_TOKEN_LEN,
    .ops = test50_ops,
    .num_ops = TEST50_NUM_OPS,
    .payload = test50_payload,
    .payload_len = TEST50_PAYLOAD_LEN
};

#define TEST51_OP1_LEN  1
#define TEST51_OP2_LEN  1
#define TEST51_OP3_LEN  2
#define TEST51_OP4_LEN  2
#define TEST51_OP5_LEN  3
#define TEST51_OP6_LEN  3
#define TEST51_NUM_OPS  6

char test51_op1_val[TEST51_OP1_LEN] = {0x00};
char test51_op2_val[TEST51_OP2_LEN] = {0xf9};
char test51_op3_val[TEST51_OP3_LEN] = {0x12, 0x32};
char test51_op4_val[TEST51_OP4_LEN] = {0xed, 0xcb};
char test51_op5_val[TEST51_OP5_LEN] = {0x45, 0x67, 0x84};
char test51_op6_val[TEST51_OP6_LEN] = {0xba, 0x98, 0x7d};
test_coap_msg_op_t test51_ops[TEST51_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST51_OP1_LEN,
        .val = test51_op1_val,
        .block_num = 0x0,
        .block_more = 0,
        .block_size = 16
    },
    [1] =
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST51_OP2_LEN,
        .val = test51_op2_val,
        .block_num = 0xf,
        .block_more = 1,
        .block_size = 32
    },
    [2] =
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST51_OP3_LEN,
        .val = test51_op3_val,
        .block_num = 0x123,
        .block_more = 0,
        .block_size = 64
    },
    [3] =
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST51_OP4_LEN,
        .val = test51_op4_val,
        .block_num = 0xedc,
        .block_more = 1,
        .block_size = 128
    },
    [4] =
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST51_OP5_LEN,
        .val = test51_op5_val,
        .block_num = 0x45678,
        .block_more = 0,
        .block_size = 256
    },
    [5] =
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST51_OP6_LEN,
        .val = test51_op6_val,
        .block_num = 0xba987,
        .block_more = 1,
        .block_size = 512
    }
};

test_coap_msg_data_t test51_data =
{
    .parse_desc = "test 89: parse CoAP Block1 and Block2 option values",
    .format_desc = "test 91: format CoAP Block1 and Block2 option values",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test51_ops,
    .num_ops = TEST51_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST52_OP1_LEN  1
#define TEST52_OP2_LEN  1
#define TEST52_OP3_LEN  2
#define TEST52_OP4_LEN  2
#define TEST52_OP5_LEN  3
#define TEST52_OP6_LEN  3
#define TEST52_NUM_OPS  6

char test52_op1_val[TEST52_OP1_LEN] = {0x07};
char test52_op2_val[TEST52_OP2_LEN] = {0xff};
char test52_op3_val[TEST52_OP3_LEN] = {0x12, 0x37};
char test52_op4_val[TEST52_OP4_LEN] = {0xed, 0xcf};
char test52_op5_val[TEST52_OP5_LEN] = {0x45, 0x67, 0x87};
char test52_op6_val[TEST52_OP6_LEN] = {0xba, 0x98, 0x7f};
test_coap_msg_op_t test52_ops[TEST52_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST52_OP1_LEN,
        .val = test52_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST52_OP2_LEN,
        .val = test52_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST52_OP3_LEN,
        .val = test52_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [3] =
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST52_OP4_LEN,
        .val = test52_op4_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [4] =
    {
        .num = COAP_MSG_BLOCK1,
        .len = TEST52_OP5_LEN,
        .val = test52_op5_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [5] =
    {
        .num = COAP_MSG_BLOCK2,
        .len = TEST52_OP6_LEN,
        .val = test52_op6_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test52_data =
{
    .parse_desc = "test 90: parse invalid CoAP Block1 and Block2 option values",
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = -EINVAL,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test52_ops,
    .num_ops = TEST52_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST53_NUM_OPS  6

test_coap_msg_op_t test53_ops[TEST53_NUM_OPS] =
{
    [0] =
    {
        .num = 0,
        .len = 0,
        .val = NULL,
        .block_num = (1 << 4),
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = 0,
        .len = 0,
        .val = NULL,
        .block_num = 0,
        .block_more = 0,
        .block_size = 1
    },
    [2] =
    {
        .num = 0,
        .len = 0,
        .val = NULL,
        .block_num = (1 << 12),
        .block_more = 0,
        .block_size = 0
    },
    [3] =
    {
        .num = 0,
        .len = 0,
        .val = NULL,
        .block_num = 0,
        .block_more = 0,
        .block_size = 257
    },
    [4] =
    {
        .num = 0,
        .len = 0,
        .val = NULL,
        .block_num = (1 << 20),
        .block_more = 0,
        .block_size = 0
    },
    [5] =
    {
        .num = 0,
        .len = 0,
        .val = NULL,
        .block_num = 0,
        .block_more = 0,
        .block_size = (1 << 11)
    }
};

test_coap_msg_data_t test53_data =
{
    .parse_desc = NULL,
    .format_desc = "test 92: format invalid CoAP Block1 and Block2 option values",
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = NULL,
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = -EINVAL,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 0,
    .buf = NULL,
    .buf_len = 0,
    .ver = 0,
    .type = 0,
    .code_class = 0,
    .code_detail = 0,
    .msg_id = 0,
    .token = NULL,
    .token_len = 0,
    .ops = test53_ops,
    .num_ops = TEST53_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST54_BUF_LEN  64
#define TEST54_OP1_LEN  4
#define TEST54_NUM_OPS  1

char test54_buf[TEST54_BUF_LEN] = "/path";
char test54_op1_val[TEST54_OP1_LEN + 1] = "path";
test_coap_msg_op_t test54_ops[TEST54_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST54_OP1_LEN,
        .val = test54_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test54_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = "test 93: convert the URI path in a message to a string representation",
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 5,
    .buf = test54_buf,
    .buf_len = TEST54_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = test54_ops,
    .num_ops = TEST54_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST55_BUF_LEN  64
#define TEST55_OP1_LEN  4
#define TEST55_OP2_LEN  2
#define TEST55_OP3_LEN  8
#define TEST55_NUM_OPS  3

char test55_buf[TEST55_BUF_LEN] = "/path/to/resource";
char test55_op1_val[TEST55_OP1_LEN + 1] = "path";
char test55_op2_val[TEST55_OP2_LEN + 1] = "to";
char test55_op3_val[TEST55_OP3_LEN + 1] = "resource";
test_coap_msg_op_t test55_ops[TEST55_NUM_OPS] =
{
    [0] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST55_OP1_LEN,
        .val = test55_op1_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [1] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST55_OP2_LEN,
        .val = test55_op2_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    },
    [2] =
    {
        .num = COAP_MSG_URI_PATH,
        .len = TEST55_OP3_LEN,
        .val = test55_op3_val,
        .block_num = 0,
        .block_more = 0,
        .block_size = 0
    }
};

test_coap_msg_data_t test55_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = "test 94: convert the URI path in a message to a string representation",
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 17,
    .buf = test55_buf,
    .buf_len = TEST55_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = test55_ops,
    .num_ops = TEST55_NUM_OPS,
    .payload = NULL,
    .payload_len = 0
};

#define TEST56_BUF_LEN  64

char test56_buf[TEST56_BUF_LEN] = "/";

test_coap_msg_data_t test56_data =
{
    .parse_desc = NULL,
    .format_desc = NULL,
    .copy_desc = NULL,
    .recognize_desc = NULL,
    .check_critical_desc = NULL,
    .check_unsafe_desc = NULL,
    .uri_path_to_str_desc = "test 95: convert the URI path in a message to a string representation",
    .parse_ret = 0,
    .set_type_ret = 0,
    .set_code_ret = 0,
    .set_msg_id_ret = 0,
    .set_token_ret = 0,
    .add_op_ret = 0,
    .set_payload_ret = 0,
    .format_ret = 0,
    .copy_ret = 0,
    .recognize_ret = NULL,
    .check_critical_ops_ret = 0,
    .check_unsafe_ops_ret = 0,
    .uri_path_to_str_ret = 1,
    .buf = test56_buf,
    .buf_len = TEST56_BUF_LEN,
    .ver = COAP_MSG_VER,
    .type = COAP_MSG_NON,
    .code_class = 0x2,
    .code_detail = 0x4,
    .msg_id = 0x1234,
    .token = NULL,
    .token_len = 0,
    .ops = NULL,
    .num_ops = 0,
    .payload = NULL,
    .payload_len = 0
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
 *  @brief Print buffer as an array of hexadecimal byte values
 *
 *  @param[in] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 */
static void print_buf(char *buf, size_t len)
{
#ifdef DEBUG
    unsigned i = 0;

    printf("buffer:");
    for (i = 0; i < len; i++)
    {
        printf(" 0x%02x", (unsigned char)buf[i]);
    }
    printf("\n");
#endif
}

/**
 *  @brief Parse test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_parse_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    coap_msg_op_t *op = NULL;
    coap_msg_t msg = {0};
    unsigned i = 0;
    ssize_t num = 0;

    printf("%s\n", test_data->parse_desc);

    coap_msg_create(&msg);
    num = coap_msg_parse(&msg, test_data->buf, test_data->buf_len);
    if (num != test_data->parse_ret)
    {
        result = FAIL;
    }
    if (test_data->parse_ret < 0)
    {
        coap_msg_destroy(&msg);
        return result;
    }
    print_coap_msg("Parsed message:", &msg);
    if (msg.ver != test_data->ver)
    {
        result = FAIL;
    }
    if (msg.type != test_data->type)
    {
        result = FAIL;
    }
    if (msg.token_len != test_data->token_len)
    {
        result = FAIL;
    }
    if (msg.code_class != test_data->code_class)
    {
        result = FAIL;
    }
    if (msg.code_detail != test_data->code_detail)
    {
        result = FAIL;
    }
    if (msg.msg_id != test_data->msg_id)
    {
        result = FAIL;
    }
    if (memcmp(msg.token, test_data->token, test_data->token_len) != 0)
    {
        result = FAIL;
    }
    op = coap_msg_get_first_op(&msg);
    for (i = 0; i < test_data->num_ops; i++)
    {
        if (op == NULL)
        {
            result = FAIL;
            break;
        }
        if (coap_msg_op_get_num(op) != test_data->ops[i].num)
        {
            result = FAIL;
        }
        if (coap_msg_op_get_len(op) != test_data->ops[i].len)
        {
            result = FAIL;
        }
        if (memcmp(coap_msg_op_get_val(op), test_data->ops[i].val, test_data->ops[i].len) != 0)
        {
            result = FAIL;
        }
        op = coap_msg_op_get_next(op);
    }
    if (op != NULL)
    {
        result = FAIL;
    }
    if (test_data->payload != NULL)
    {
        if ((msg.payload == NULL)
         || (memcmp(msg.payload, test_data->payload, test_data->payload_len) != 0))
        {
            result = FAIL;
        }
    }
    else
    {
        if (msg.payload != NULL)
        {
            result = FAIL;
        }
    }
    if (msg.payload_len != test_data->payload_len)
    {
        result = FAIL;
    }
    coap_msg_destroy(&msg);
    return result;
}

/**
 *  @brief Format test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_format_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    coap_msg_t msg = {0};
    unsigned i = 0;
    ssize_t num = 0;
    char tmp[test_data->buf_len];
    int ret = 0;

    printf("%s\n", test_data->format_desc);

    coap_msg_create(&msg);
    ret = coap_msg_set_type(&msg, test_data->type);
    if (ret != test_data->set_type_ret)
    {
        result = FAIL;
    }
    if (test_data->set_type_ret < 0)
    {
        coap_msg_destroy(&msg);
        return result;
    }
    ret = coap_msg_set_code(&msg, test_data->code_class, test_data->code_detail);
    if (ret != test_data->set_code_ret)
    {
        result = FAIL;
    }
    if (test_data->set_code_ret < 0)
    {
        coap_msg_destroy(&msg);
        return result;
    }
    ret = coap_msg_set_msg_id(&msg, test_data->msg_id);
    if (ret != test_data->set_msg_id_ret)
    {
        result = FAIL;
    }
    if (test_data->set_msg_id_ret < 0)
    {
        coap_msg_destroy(&msg);
        return result;
    }
    if (test_data->token_len > 0)
    {
        ret = coap_msg_set_token(&msg, test_data->token, test_data->token_len);
        if (ret != test_data->set_token_ret)
        {
            result = FAIL;
        }
        if (test_data->set_token_ret < 0)
        {
            coap_msg_destroy(&msg);
            return result;
        }
    }
    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_add_op(&msg, test_data->ops[i].num, test_data->ops[i].len, test_data->ops[i].val);
        if (ret != test_data->add_op_ret[i])
        {
            result = FAIL;
        }
        if (test_data->add_op_ret[i] != 0)
        {
            coap_msg_destroy(&msg);
            return result;
        }
    }
    if (test_data->payload_len > 0)
    {
        ret = coap_msg_set_payload(&msg, test_data->payload, test_data->payload_len);
        if (ret != test_data->set_payload_ret)
        {
            result = FAIL;
        }
        if (test_data->set_payload_ret < 0)
        {
            coap_msg_destroy(&msg);
            return result;
        }
    }
    num = coap_msg_format(&msg, tmp, sizeof(tmp));
    if (num != test_data->format_ret)
    {
        result = FAIL;
    }
    if (test_data->format_ret < 0)
    {
        coap_msg_destroy(&msg);
        return result;
    }
    if (memcmp(tmp, test_data->buf, test_data->buf_len) != 0)
    {
        result = FAIL;
    }
    print_buf(tmp, sizeof(tmp));
    coap_msg_destroy(&msg);
    return result;
}

/**
 *  @brief Parse type and message ID test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_parse_type_msg_id_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    unsigned msg_id = 0;
    unsigned type = 0;
    int ret = 0;

    printf("%s\n", test_data->parse_desc);

    ret = coap_msg_parse_type_msg_id(test_data->buf, test_data->buf_len, &type, &msg_id);
    if (ret != test_data->parse_ret)
    {
        result = FAIL;
    }
    if (test_data->parse_ret == 0)
    {
        if (type != test_data->type)
        {
            result = FAIL;
        }
        if (msg_id != test_data->msg_id)
        {
            result = FAIL;
        }
    }
    return result;
}

/**
 *  @brief Copy test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_copy_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    coap_msg_op_t *op = NULL;
    coap_msg_t src = {0};
    coap_msg_t dst = {0};
    unsigned i = 0;
    ssize_t num = 0;
    int ret = 0;

    printf("%s\n", test_data->copy_desc);

    coap_msg_create(&src);
    num = coap_msg_parse(&src, test_data->buf, test_data->buf_len);
    if (num != 0)
    {
        coap_msg_destroy(&src);
        return FAIL;
    }
    coap_msg_create(&dst);
    ret = coap_msg_copy(&dst, &src);
    if (ret != test_data->copy_ret)
    {
        result = FAIL;
    }
    if (test_data->copy_ret < 0)
    {
        coap_msg_destroy(&dst);
        coap_msg_destroy(&src);
        return result;
    }
    print_coap_msg("Destination message:", &dst);
    if (dst.ver != test_data->ver)
    {
        result = FAIL;
    }
    if (dst.type != test_data->type)
    {
        result = FAIL;
    }
    if (dst.token_len != test_data->token_len)
    {
        result = FAIL;
    }
    if (dst.code_class != test_data->code_class)
    {
        result = FAIL;
    }
    if (dst.code_detail != test_data->code_detail)
    {
        result = FAIL;
    }
    if (dst.msg_id != test_data->msg_id)
    {
        result = FAIL;
    }
    if (memcmp(dst.token, test_data->token, test_data->token_len) != 0)
    {
        result = FAIL;
    }
    op = coap_msg_get_first_op(&dst);
    for (i = 0; i < test_data->num_ops; i++)
    {
        if (op == NULL)
        {
            result = FAIL;
            break;
        }
        if (coap_msg_op_get_num(op) != test_data->ops[i].num)
        {
            result = FAIL;
        }
        if (coap_msg_op_get_len(op) != test_data->ops[i].len)
        {
            result = FAIL;
        }
        if (memcmp(coap_msg_op_get_val(op), test_data->ops[i].val, test_data->ops[i].len) != 0)
        {
            result = FAIL;
        }
        op = coap_msg_op_get_next(op);
    }
    if (op != NULL)
    {
        result = FAIL;
    }
    if (test_data->payload != NULL)
    {
        if ((dst.payload == NULL)
         || (memcmp(dst.payload, test_data->payload, test_data->payload_len) != 0))
        {
            result = FAIL;
        }
    }
    else
    {
        if (dst.payload != NULL)
        {
            result = FAIL;
        }
    }
    if (dst.payload_len != test_data->payload_len)
    {
        result = FAIL;
    }
    coap_msg_destroy(&dst);
    coap_msg_destroy(&src);
    return result;
}

/**
 *  @brief Recognize option number test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_recognize_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    unsigned i = 0;
    int ret = 0;

    printf("%s\n", test_data->recognize_desc);

    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_op_num_is_recognized(test_data->ops[i].num);
        if (ret != test_data->recognize_ret[i])
        {
            result = FAIL;
        }
    }
    return result;
}

/**
 *  @brief Check critical options test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_check_critical_ops_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    coap_msg_t msg = {0};
    unsigned num = 0;
    unsigned i = 0;
    int ret = 0;

    printf("%s\n", test_data->check_critical_desc);

    coap_msg_create(&msg);
    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_add_op(&msg, test_data->ops[i].num, test_data->ops[i].len, test_data->ops[i].val);
        if (ret < 0)
        {
            result = FAIL;
            break;
        }
    }
    num = coap_msg_check_critical_ops(&msg);
    if (num != test_data->check_critical_ops_ret)
    {
        result = FAIL;
    }
    coap_msg_destroy(&msg);
    return result;
}

/**
 *  @brief Check unsafe options test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_check_unsafe_ops_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    coap_msg_t msg = {0};
    unsigned num = 0;
    unsigned i = 0;
    int ret = 0;

    printf("%s\n", test_data->check_unsafe_desc);

    coap_msg_create(&msg);
    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_add_op(&msg, test_data->ops[i].num, test_data->ops[i].len, test_data->ops[i].val);
        if (ret < 0)
        {
            result = FAIL;
            break;
        }
    }
    num = coap_msg_check_unsafe_ops(&msg);
    if (num != test_data->check_unsafe_ops_ret)
    {
        result = FAIL;
    }
    coap_msg_destroy(&msg);
    return result;
}

/**
 *  @brief Parse Block1 and Block2 option values test fucntion
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_parse_block_op_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    unsigned size = 0;
    unsigned more = 0;
    unsigned num = 0;
    unsigned i = 0;
    int ret = 0;

    printf("%s\n", test_data->parse_desc);

    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_op_parse_block_val(&num, &more, &size, test_data->ops[i].val, test_data->ops[i].len);
        if (ret != test_data->parse_ret)
        {
            result = FAIL;
        }
        if (test_data->parse_ret == 0)
        {
            if ((num != test_data->ops[i].block_num)
             || (more != test_data->ops[i].block_more)
             || (size != test_data->ops[i].block_size))
            {
                result = FAIL;
            }
        }
    }
    return result;
}

/**
 *  @brief Format Block1 and Block2 option values test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_format_block_op_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    unsigned i = 0;
    char val[COAP_MSG_OP_MAX_BLOCK_VAL_LEN] = {0};
    int ret = 0;

    printf("%s\n", test_data->format_desc);

    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_op_format_block_val(val, test_data->ops[i].len,
                                           test_data->ops[i].block_num,
                                           test_data->ops[i].block_more,
                                           test_data->ops[i].block_size);
        if (test_data->format_ret < 0)
        {
            /* check error cases */
            if (ret != test_data->format_ret)
            {
                result = FAIL;
            }
        }
        else
        {
            /* check valid cases */
            if ((ret != test_data->ops[i].len)
             || (memcmp(val, test_data->ops[i].val, test_data->ops[i].len) != 0))
            {
                result = FAIL;
            }
        }
    }
    return result;
}

/**
 *  @brief Convert the URI path in a message to a string representation test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_uri_path_to_str_func(test_data_t data)
{
    test_coap_msg_data_t *test_data = (test_coap_msg_data_t *)data;
    test_result_t result = PASS;
    coap_msg_t msg = {0};
    size_t num = 0;
    char tmp[test_data->buf_len];
    int ret = 0;
    int i = 0;

    printf("%s\n", test_data->uri_path_to_str_desc);

    coap_msg_create(&msg);
    ret = coap_msg_set_type(&msg, test_data->type);
    if (ret < 0)
    {
        coap_msg_destroy(&msg);
        return FAIL;
    }
    ret = coap_msg_set_code(&msg, test_data->code_class, test_data->code_detail);
    if (ret < 0)
    {
        coap_msg_destroy(&msg);
        return FAIL;
    }
    ret = coap_msg_set_msg_id(&msg, test_data->msg_id);
    if (ret < 0)
    {
        coap_msg_destroy(&msg);
        return FAIL;
    }
    for (i = 0; i < test_data->num_ops; i++)
    {
        ret = coap_msg_add_op(&msg, test_data->ops[i].num, test_data->ops[i].len, test_data->ops[i].val);
        if (ret < 0)
        {
            coap_msg_destroy(&msg);
            return FAIL;
        }
    }
    num = coap_msg_format(&msg, tmp, sizeof(tmp));
    if (num < 0)
    {
        coap_msg_destroy(&msg);
        return FAIL;
    }
    ret = coap_msg_uri_path_to_str(&msg, tmp, test_data->buf_len);
    if (ret != test_data->uri_path_to_str_ret)
    {
        coap_msg_destroy(&msg);
        return FAIL;
    }
    if (strcmp(tmp, test_data->buf) != 0)
    {
        result = FAIL;
    }
    coap_msg_destroy(&msg);
    return result;
}

/**
 *  @brief Main function for the FreeCoAP message parser/formatter unit tests
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(void)
{
    test_t tests[] = {{test_parse_func,              &test1_data},
                      {test_parse_func,              &test2_data},
                      {test_parse_func,              &test3_data},
                      {test_parse_func,              &test4_data},
                      {test_parse_func,              &test5_data},
                      {test_parse_func,              &test6_data},
                      {test_parse_func,              &test7_data},
                      {test_parse_func,              &test8_data},
                      {test_parse_func,              &test9_data},
                      {test_parse_func,              &test10_data},
                      {test_parse_func,              &test11_data},
                      {test_parse_func,              &test12_data},
                      {test_parse_func,              &test13_data},
                      {test_parse_func,              &test14_data},
                      {test_parse_func,              &test15_data},
                      {test_parse_func,              &test16_data},
                      {test_parse_func,              &test17_data},
                      {test_parse_func,              &test18_data},
                      {test_parse_func,              &test19_data},
                      {test_parse_func,              &test20_data},
                      {test_parse_func,              &test21_data},
                      {test_parse_func,              &test22_data},
                      {test_parse_func,              &test23_data},
                      {test_parse_func,              &test24_data},
                      {test_parse_func,              &test25_data},
                      {test_parse_func,              &test26_data},
                      {test_format_func,             &test1_data},
                      {test_format_func,             &test2_data},
                      {test_format_func,             &test3_data},
                      {test_format_func,             &test4_data},
                      {test_format_func,             &test5_data},
                      {test_format_func,             &test6_data},
                      {test_format_func,             &test7_data},
                      {test_format_func,             &test8_data},
                      {test_format_func,             &test9_data},
                      {test_format_func,             &test10_data},
                      {test_format_func,             &test11_data},
                      {test_format_func,             &test12_data},
                      {test_format_func,             &test13_data},
                      {test_format_func,             &test14_data},
                      {test_format_func,             &test15_data},
                      {test_format_func,             &test16_data},
                      {test_format_func,             &test18_data},
                      {test_format_func,             &test19_data},
                      {test_format_func,             &test20_data},
                      {test_format_func,             &test21_data},
                      {test_format_func,             &test22_data},
                      {test_format_func,             &test23_data},
                      {test_parse_type_msg_id_func,  &test27_data},
                      {test_parse_type_msg_id_func,  &test28_data},
                      {test_copy_func,               &test1_data},
                      {test_copy_func,               &test2_data},
                      {test_copy_func,               &test3_data},
                      {test_copy_func,               &test4_data},
                      {test_copy_func,               &test5_data},
                      {test_copy_func,               &test6_data},
                      {test_copy_func,               &test7_data},
                      {test_copy_func,               &test8_data},
                      {test_copy_func,               &test9_data},
                      {test_copy_func,               &test10_data},
                      {test_copy_func,               &test11_data},
                      {test_copy_func,               &test12_data},
                      {test_copy_func,               &test13_data},
                      {test_copy_func,               &test14_data},
                      {test_copy_func,               &test15_data},
                      {test_copy_func,               &test16_data},
                      {test_recognize_func,          &test29_data},
                      {test_check_critical_ops_func, &test30_data},
                      {test_check_critical_ops_func, &test31_data},
                      {test_check_critical_ops_func, &test32_data},
                      {test_check_critical_ops_func, &test33_data},
                      {test_check_critical_ops_func, &test34_data},
                      {test_check_critical_ops_func, &test35_data},
                      {test_check_critical_ops_func, &test36_data},
                      {test_check_critical_ops_func, &test37_data},
                      {test_check_critical_ops_func, &test38_data},
                      {test_check_critical_ops_func, &test39_data},
                      {test_check_unsafe_ops_func,   &test40_data},
                      {test_check_unsafe_ops_func,   &test41_data},
                      {test_check_unsafe_ops_func,   &test42_data},
                      {test_check_unsafe_ops_func,   &test43_data},
                      {test_check_unsafe_ops_func,   &test44_data},
                      {test_check_unsafe_ops_func,   &test45_data},
                      {test_check_unsafe_ops_func,   &test46_data},
                      {test_check_unsafe_ops_func,   &test47_data},
                      {test_check_unsafe_ops_func,   &test48_data},
                      {test_check_unsafe_ops_func,   &test49_data},
                      {test_format_func,             &test50_data},
                      {test_parse_block_op_func,     &test51_data},
                      {test_parse_block_op_func,     &test52_data},
                      {test_format_block_op_func,    &test51_data},
                      {test_format_block_op_func,    &test53_data},
                      {test_uri_path_to_str_func,    &test54_data},
                      {test_uri_path_to_str_func,    &test55_data},
                      {test_uri_path_to_str_func,    &test56_data}
    };
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
