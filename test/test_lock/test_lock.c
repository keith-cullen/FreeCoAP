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
 *  @file test_lock.c
 *
 *  @brief Source file for the FreeCoAP lock unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include "lock.h"
#include "test.h"

#define DIM(x) (sizeof(x) / sizeof(x[0]))

typedef struct
{
    const char *desc;
}
test_lock_data1_t;

test_lock_data1_t test1_data =
{
    .desc = "test 1: get, put",
};

test_result_t test1_func(test_data_t data)
{
    test_lock_data1_t *test_data = (test_lock_data1_t *)data;
    test_result_t result = PASS;
    lock_t lock;
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = lock_create(&lock);
    if (ret != 0)
    {
        result = FAIL;
    }
    else
    {
        ret = lock_get(&lock);
        if (ret != 0)
        {
            result = FAIL;
        }
        else
        {
            ret = lock_put(&lock);
            if (ret != 0)
            {
                result = FAIL;
            }
        }
        lock_destroy(&lock);
    }
    return result;
}

typedef struct
{
    const char *desc;
}
test_lock_data2_t;

test_lock_data2_t test2_data =
{
    .desc = "test 2: attempt to get the same lock twice",
};

test_result_t test2_func(test_data_t data)
{
    test_lock_data2_t *test_data = (test_lock_data2_t *)data;
    test_result_t result = PASS;
    lock_t lock;
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = lock_create(&lock);
    if (ret != 0)
    {
        result = FAIL;
    }
    else
    {
        ret = lock_get(&lock);
        if (ret != 0)
        {
            result = FAIL;
        }
        else
        {
            ret = lock_get(&lock);
            if (ret != -1)
            {
                result = FAIL;
            }
        }
        lock_destroy(&lock);
    }
    return result;
}

typedef struct
{
    const char *desc;
}
test_lock_data3_t;

test_lock_data3_t test3_data =
{
    .desc = "test 3: attempt to release the same lock twice",
};

test_result_t test3_func(test_data_t data)
{
    test_lock_data3_t *test_data = (test_lock_data3_t *)data;
    test_result_t result = PASS;
    lock_t lock;
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = lock_create(&lock);
    if (ret != 0)
    {
        result = FAIL;
    }
    else
    {
        ret = lock_get(&lock);
        if (ret != 0)
        {
            result = FAIL;
        }
        else
        {
            ret = lock_put(&lock);
            if (ret != 0)
            {
                result = FAIL;
            }
            else
            {
                ret = lock_put(&lock);
                if (ret != -1)
                {
                    result = FAIL;
                }
            }
        }
        lock_destroy(&lock);
    }
    return result;
}

typedef struct
{
    const char *desc;
}
test_lock_data4_t;

test_lock_data4_t test4_data =
{
    .desc = "test 4: attempt to release a lock that was not acquired",
};

test_result_t test4_func(test_data_t data)
{
    test_lock_data4_t *test_data = (test_lock_data4_t *)data;
    test_result_t result = PASS;
    lock_t lock;
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = lock_create(&lock);
    if (ret != 0)
    {
        result = FAIL;
    }
    else
    {
        ret = lock_put(&lock);
        if (ret != -1)
        {
            result = FAIL;
        }
        lock_destroy(&lock);
    }
    return result;
}

int main()
{
    test_t tests[] = {{test1_func, &test1_data},
                      {test2_func, &test2_data},
                      {test3_func, &test3_data},
                      {test4_func, &test4_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
