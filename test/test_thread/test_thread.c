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
 *  @file test_thread.c
 *
 *  @brief Source file for the FreeCoAP thread unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include "thread.h"
#include "test.h"

#define DIM(x) (sizeof(x) / sizeof(x[0]))

static inline void short_sleep(void)
{
    struct timespec ts = {0};

    ts.tv_sec = 0;
    ts.tv_nsec = 1000;
    nanosleep(&ts, NULL);
}

static inline void long_sleep(void)
{
    struct timespec ts = {0};

    ts.tv_sec = 0;
    ts.tv_nsec = 500000000;
    nanosleep(&ts, NULL);
}

typedef struct
{
    const char *desc;
    unsigned long val;
    unsigned long thread1_result;
    unsigned long thread2_result;
}
test_thread_data_t;

test_thread_data_t test1_data =
{
    .desc = "test 1: joinable threads",
    .val = 10,
    .thread1_result = 11,
    .thread2_result = 12
};

void *test1_func1(void *data)
{
    unsigned long x = (unsigned long)data;
    return (void *)(x + 1);
}

void *test1_func2(void *data)
{
    unsigned long x = (unsigned long)data;
    return (void *)(x + 2);
}

test_result_t test1_func(test_data_t data)
{
    test_thread_data_t *test_data = (test_thread_data_t *)data;
    unsigned long thread1_result = 0;
    unsigned long thread2_result = 0;
    thread_ctx_t ctx = {0};
    thread_t thread1 = {0};
    thread_t thread2 = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = thread_joinable_ctx_create(&ctx);
    if (ret != 0)
    {
        return FAIL;
    }
    ret = thread_init(&thread1, &ctx, test1_func1, (void *)test_data->val);
    if (ret != 0)
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    ret = thread_init(&thread2, &ctx, test1_func2, (void *)test_data->val);
    if (ret != 0)
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    ret = thread_join(&thread1, (void **)&thread1_result);
    if (ret != 0)
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    ret = thread_join(&thread2, (void **)&thread2_result);
    if (ret != 0)
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    if ((thread1_result != test_data->thread1_result)
     || (thread2_result != test_data->thread2_result))
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    thread_ctx_destroy(&ctx);
    return PASS;
}

test_thread_data_t test2_data =
{
    .desc = "test 2: detached threads",
    .val = 20,
    .thread1_result = 21,
    .thread2_result = 22
};

unsigned long test2_func1_data = 0;
unsigned long test2_func2_data = 0;

void *test2_func1(void *data)
{
    unsigned long x = (unsigned long)data;
    test2_func1_data = x + 1;
    return NULL;
}

void *test2_func2(void *data)
{
    unsigned long x = (unsigned long)data;
    test2_func2_data = x + 2;
    return NULL;
}

test_result_t test2_func(test_data_t data)
{
    test_thread_data_t *test_data = (test_thread_data_t *)data;
    thread_ctx_t ctx = {0};
    thread_t thread1 = {0};
    thread_t thread2 = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    ret = thread_detached_ctx_create(&ctx);
    if (ret != 0)
    {
        return FAIL;
    }
    ret = thread_init(&thread1, &ctx, test2_func1, (void *)test_data->val);
    if (ret != 0)
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    ret = thread_init(&thread2, &ctx, test2_func2, (void *)test_data->val);
    if (ret != 0)
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    while ((test2_func1_data == 0)
        && (test2_func2_data == 0))
    {
        short_sleep();
    }
    if ((test2_func1_data != test_data->thread1_result)
     && (test2_func2_data != test_data->thread2_result))
    {
        thread_ctx_destroy(&ctx);
        return FAIL;
    }
    thread_ctx_destroy(&ctx);
    return PASS;
}

int main()
{
    test_t tests[] = {{test1_func, &test1_data},
                      {test2_func, &test2_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
