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
 *  @file test_data_buf.c
 *
 *  @brief Source file for the FreeCoAP data buffer unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "data_buf.h"
#include "test.h"

#define DIM(x) (sizeof(x) / sizeof(x[0]))

static size_t test_data_buf_memcpy(data_buf_t *buf, const char *data, size_t len)
{
    size_t space = 0;
    size_t num = 0;
    char *next = NULL;

    next = data_buf_get_next(buf);
    space = data_buf_get_space(buf);
    if (len <= space)
        num = len;
    else
        num = space;
    memcpy(next, data, num);
    return data_buf_add(buf, num);
}

typedef struct
{
    const char *desc;
    size_t size;
    size_t max_size;
    const char *str;
    size_t str_len;
    const char *str1;
    size_t str1_len;
    const char *str2;
    size_t str2_len;
}
test_data_buf_data_t;

static test_data_buf_data_t test1_data =
{
    .desc = "test 1: add, consume",
    .size = 16,
    .max_size = 32,
    .str = "abcdefghijkl",
    .str_len = 12,
    .str1 = "abcdefghijklabcdabcdefghijklabcd",
    .str1_len = 32,
    .str2 = "abcdefghijklabcd",
    .str2_len = 16
};

test_result_t test1_func(test_data_t data)
{
    test_data_buf_data_t *test_data = (test_data_buf_data_t *)data;
    data_buf_t buf = {0};
    size_t num = 0;
    char *p = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = data_buf_create(&buf, test_data->size, test_data->max_size);
    if (ret != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_create failed\n");
        return FAIL;
    }
    if (data_buf_get_count(&buf) != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* first read */
    num = test_data_buf_memcpy(&buf, test_data->str, test_data->str_len);
    if (num != test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to data_buf_read failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != test_data->size - test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* second read */
    num = test_data_buf_memcpy(&buf, test_data->str, test_data->str_len);
    if (num != test_data->size - test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to test_data_buf_memcpy failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* third read */
    num = test_data_buf_memcpy(&buf, test_data->str, test_data->str_len);
    if (num != 0)
    {
        DEBUG_PRINT("Fail: call to test_data_buf_memcpy failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* expand */
    num = data_buf_expand(&buf);
    if (num != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_expand failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* fourth read */
    num = test_data_buf_memcpy(&buf, test_data->str, test_data->str_len);
    if (num != test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to test_data_buf_memcpy failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != test_data->size + test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != test_data->size - test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* fifth read */
    num = test_data_buf_memcpy(&buf, test_data->str, test_data->str_len);
    if (num != test_data->size - test_data->str_len)
    {
        DEBUG_PRINT("Fail: call to test_data_buf_memcpy failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != 2 * test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* sixth read */
    num = test_data_buf_memcpy(&buf, test_data->str, test_data->str_len);
    if (num != 0)
    {
        DEBUG_PRINT("Fail: call to test_data_buf_memcpy failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != 2 * test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* attempt to expand again */
    num = data_buf_expand(&buf);
    if (num != -EINVAL)
    {
        DEBUG_PRINT("Fail: call to data_buf_expand failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_count(&buf) != 2 * test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_count failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    if (data_buf_get_space(&buf) != 0)
    {
        DEBUG_PRINT("Fail: call to data_buf_get_space failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* check 1 */
    num = data_buf_get_count(&buf);
    if (num != test_data->str1_len)
    {
        DEBUG_PRINT("Fail: Incorrect final string length\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    p = data_buf_get_data(&buf);
    if (strcmp(p, test_data->str1) != 0)
    {
        DEBUG_PRINT("Fail: Incorrect final string\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    DEBUG_PRINT("str1: '%s'\n", p);

    /* consume some data */
    num = data_buf_consume(&buf, test_data->size);
    if (num != test_data->size)
    {
        DEBUG_PRINT("Fail: call to data_buf_consume failed\n");
        data_buf_destroy(&buf);
        return FAIL;
    }

    /* check 2 */
    num = data_buf_get_count(&buf);
    if (num != test_data->str2_len)
    {
        DEBUG_PRINT("Fail: Incorrect final string length\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    p = data_buf_get_data(&buf);
    if (strcmp(p, test_data->str2) != 0)
    {
        DEBUG_PRINT("Fail: Incorrect final string\n");
        data_buf_destroy(&buf);
        return FAIL;
    }
    DEBUG_PRINT("str2: '%s'\n", p);

    data_buf_destroy(&buf);

    return PASS;
}

int main(void)
{
    test_t tests[] = {{test1_func, &test1_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
