/*
 * Copyright (c) 2019 Keith Cullen.
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
 *  @file test_coap_mem.c
 *
 *  @brief Source file for the FreeCoAP memory allocator test application
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <coap_mem.h>
#include "coap_log.h"
#include "test.h"

#define DIM(x) (sizeof(x) / sizeof(x[0]))                                       /**< Calculate the size of an array */

/**
 *  @brief Memory allocator test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    size_t num;                                                                 /**< Number of buffers */
    size_t len;                                                                 /**< Length of each buffer */
}
test_coap_mem_data_t;

test_coap_mem_data_t test1_coap_mem_data =
{
    .desc = "test  1: create a memory allocator with 16 buffers of 8 bytes each",
    .num = 16,
    .len = 8
};

test_coap_mem_data_t test2_coap_mem_data =
{
    .desc = "test  2: attempt to create a memory allocator with invalid arguments of 4 buffers of 8 bytes each",
    .num = 4,
    .len = 8
};

test_coap_mem_data_t test3_coap_mem_data =
{
    .desc = "test  3: attempt to create a memory allocator with invalid arguments of 12 buffers of 8 bytes each",
    .num = 12,
    .len = 8
};

test_coap_mem_data_t test4_coap_mem_data =
{
    .desc = "test  4: attempt to create a memory allocator with invalid arguments of 8 buffers of 0 bytes each",
    .num = 8,
    .len = 0
};

test_coap_mem_data_t test5_coap_mem_data =
{
    .desc = "test  5: create the small memory allocator with 16 buffers of 8 bytes each",
    .num = 16,
    .len = 8
};

test_coap_mem_data_t test6_coap_mem_data =
{
    .desc = "test  6: attempt to create the small memory allocator with invalid arguments of 4 buffers of 8 bytes each",
    .num = 4,
    .len = 8
};

test_coap_mem_data_t test7_coap_mem_data =
{
    .desc = "test  7: attempt to create the small memory allocator with invalid arguments of 12 buffers of 8 bytes each",
    .num = 12,
    .len = 8
};

test_coap_mem_data_t test8_coap_mem_data =
{
    .desc = "test  8: attempt to create the small memory allocator with invalid arguments of 8 buffers of 0 bytes each",
    .num = 8,
    .len = 0
};

test_coap_mem_data_t test9_coap_mem_data =
{
    .desc = "test  9: create the medium memory allocator with 16 buffers of 64 bytes each",
    .num = 16,
    .len = 64
};

test_coap_mem_data_t test10_coap_mem_data =
{
    .desc = "test 10: attempt to create the medium memory allocator with invalid arguments of 4 buffers of 8 bytes each",
    .num = 4,
    .len = 8
};

test_coap_mem_data_t test11_coap_mem_data =
{
    .desc = "test 11: attempt to create the medium memory allocator with invalid arguments of 12 buffers of 8 bytes each",
    .num = 12,
    .len = 8
};

test_coap_mem_data_t test12_coap_mem_data =
{
    .desc = "test 12: attempt to create the medium memory allocator with invalid arguments of 8 buffers of 0 bytes each",
    .num = 8,
    .len = 0
};

test_coap_mem_data_t test13_coap_mem_data =
{
    .desc = "test 13: create the large memory allocator with 16 buffers of 128 bytes each",
    .num = 16,
    .len = 128
};

test_coap_mem_data_t test14_coap_mem_data =
{
    .desc = "test 14: attempt to create the large memory allocator with invalid arguments of 4 buffers of 8 bytes each",
    .num = 4,
    .len = 8
};

test_coap_mem_data_t test15_coap_mem_data =
{
    .desc = "test 15: attempt to create the large memory allocator with invalid arguments of 12 buffers of 8 bytes each",
    .num = 12,
    .len = 8
};

test_coap_mem_data_t test16_coap_mem_data =
{
    .desc = "test 16: attempt to create the large memory allocator with invalid arguments of 8 buffers of 0 bytes each",
    .num = 8,
    .len = 0
};

test_coap_mem_data_t test17_coap_mem_data =
{
    .desc = "test 17: create all memory allocators with 16 buffers of 128 bytes each",
    .num = 16,
    .len = 128
};

test_coap_mem_data_t test18_coap_mem_data =
{
    .desc = "test 18: attempt to create all memory allocators with invalid arguments of 4 buffers of 8 bytes each",
    .num = 4,
    .len = 8
};

test_coap_mem_data_t test19_coap_mem_data =
{
    .desc = "test 19: attempt to create all memory allocators with invalid arguments of 12 buffers of 8 bytes each",
    .num = 12,
    .len = 8
};

test_coap_mem_data_t test20_coap_mem_data =
{
    .desc = "test 20: attempt to create all memory allocators with invalid arguments of 8 buffers of 0 bytes each",
    .num = 8,
    .len = 0
};

/**
 *  @brief Coap memory allocator test function
 *
 *  @param[in] data Pointer to a memory allocator test data structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    coap_log_level_t log_level = 0;
    coap_mem_t mem = {0};
    test_result_t result = PASS;
    unsigned char mask = 0;
    size_t byte = 0;
    size_t bit = 0;
    size_t i = 0;
    size_t j = 0;
    char active[test_data->num >> 3];
    char *p[test_data->num];
    char *q = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);
    memset(active, 0, sizeof(active));
    memset(p, 0, sizeof(p));
    log_level = coap_log_get_level();
    ret = coap_mem_create(&mem, test_data->num, test_data->len);
    if (ret < 0)
    {
        coap_log_error("Failed to create memory allocator");
        return FAIL;
    }
    /* allocate buffers */
    for (byte = 0; byte < coap_mem_get_active_len(&mem); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            p[8 * byte + bit] = (char *)coap_mem_alloc(&mem, test_data->len);
            if (p[8 * byte + bit] == NULL)
            {
                coap_log_error("Failed to allocate buffer");
                coap_mem_destroy(&mem);
                return FAIL;
            }
            mask = (1 << bit);
            active[byte] |= mask;
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_get_active_len(&mem); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_get_active(&mem) + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_get_active_len(&mem); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_get_active(&mem), active, coap_mem_get_active_len(&mem)) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer allocation");
                coap_mem_destroy(&mem);
                return FAIL;
            }
        }
    }
    /* try to allocate one too many buffers */
    q = (char *)coap_mem_alloc(&mem, test_data->len);
    if (q != NULL)
    {
        coap_log_error("Too many buffers allocated");
        coap_mem_destroy(&mem);
        return FAIL;
    }
    /* try to allocate a buffer that is too large */
    q = (char *)coap_mem_alloc(&mem, test_data->len + 1);
    if (q != NULL)
    {
        coap_log_error("Over-sized buffer allocated");
        coap_mem_destroy(&mem);
        return FAIL;
    }
    /* write data to the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            p[i][j] = (char)i;
        }
    }
    if (log_level >= COAP_LOG_INFO)
    {
        for (i = 0; i < test_data->num; i++)
        {
            printf("write buffer %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
            }
            printf(" ]\n");
        }
        /* read the data back from the buffers */
        for (i = 0; i < test_data->num; i++)
        {
            printf("read buffer  %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
                if (p[i][j] != (char)i)
                {
                    result = FAIL;
                }
            }
            printf(" ]\n");
        }
    }
    /* check the data in the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            if (p[i][j] != (char)i)
            {
                result = FAIL;
            }
        }
    }
    /* free buffers */
    for (byte = 0; byte < coap_mem_get_active_len(&mem); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            coap_mem_free(&mem, p[8 * byte + bit]);
            mask = (1 << bit);
            active[byte] &= (unsigned char)(~mask);
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_get_active_len(&mem); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_get_active(&mem) + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_get_active_len(&mem); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_get_active(&mem), active, coap_mem_get_active_len(&mem)) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer free");
                coap_mem_destroy(&mem);
                return FAIL;
            }
         }
    }
    coap_mem_destroy(&mem);
    return result;
}

/**
 *  @brief Coap memory allocator invalid test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_invalid_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    coap_mem_t mem = {0};
    test_result_t result = PASS;
    int ret = 0;

    printf("%s\n", test_data->desc);
    ret = coap_mem_create(&mem, test_data->num, test_data->len);
    if (ret != -EINVAL)
    {
        coap_mem_destroy(&mem);
        return FAIL;
    }
    return result;
}

/**
 *  @brief Coap small memory allocator test function
 *
 *  @param[in] data Pointer to a memory allocator test data structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_small_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    coap_log_level_t log_level = 0;
    test_result_t result = PASS;
    unsigned char mask = 0;
    size_t byte = 0;
    size_t bit = 0;
    size_t i = 0;
    size_t j = 0;
    char active[test_data->num >> 3];
    char *p[test_data->num];
    char *q = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);
    memset(active, 0, sizeof(active));
    memset(p, 0, sizeof(p));
    log_level = coap_log_get_level();
    ret = coap_mem_small_create(test_data->num, test_data->len);
    if (ret < 0)
    {
        coap_log_error("Failed to create memory allocator");
        return FAIL;
    }
    /* allocate buffers */
    for (byte = 0; byte < coap_mem_small_get_active_len(); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            p[8 * byte + bit] = (char *)coap_mem_small_alloc(test_data->len);
            if (p[8 * byte + bit] == NULL)
            {
                coap_log_error("Failed to allocate buffer");
                coap_mem_small_destroy();
                return FAIL;
            }
            mask = (1 << bit);
            active[byte] |= mask;
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_small_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_small_get_active() + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_small_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_small_get_active(), active, coap_mem_small_get_active_len()) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer allocation");
                coap_mem_small_destroy();
                return FAIL;
            }
        }
    }
    /* try to allocate one too many buffers */
    q = (char *)coap_mem_small_alloc(test_data->len);
    if (q != NULL)
    {
        coap_log_error("Too many buffers allocated");
        coap_mem_small_destroy();
        return FAIL;
    }
    /* try to allocate a buffer that is too large */
    q = (char *)coap_mem_small_alloc(test_data->len + 1);
    if (q != NULL)
    {
        coap_log_error("Over-sized buffer allocated");
        coap_mem_small_destroy();
        return FAIL;
    }
    /* write data to the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            p[i][j] = (char)i;
        }
    }
    if (log_level >= COAP_LOG_INFO)
    {
        for (i = 0; i < test_data->num; i++)
        {
            printf("write buffer %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
            }
            printf(" ]\n");
        }
        /* read the data back from the buffers */
        for (i = 0; i < test_data->num; i++)
        {
            printf("read buffer  %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
                if (p[i][j] != (char)i)
                {
                    result = FAIL;
                }
            }
            printf(" ]\n");
        }
    }
    /* check the data in the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            if (p[i][j] != (char)i)
            {
                result = FAIL;
            }
        }
    }
    /* free buffers */
    for (byte = 0; byte < coap_mem_small_get_active_len(); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            coap_mem_small_free(p[8 * byte + bit]);
            mask = (1 << bit);
            active[byte] &= (unsigned char)(~mask);
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_small_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_small_get_active() + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_small_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_small_get_active(), active, coap_mem_small_get_active_len()) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer free");
                coap_mem_small_destroy();
                return FAIL;
            }
         }
    }
    coap_mem_small_destroy();
    return result;
}

/**
 *  @brief Coap small memory allocator invalid test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_small_invalid_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    test_result_t result = PASS;
    int ret = 0;

    printf("%s\n", test_data->desc);
    ret = coap_mem_small_create(test_data->num, test_data->len);
    if (ret != -EINVAL)
    {
        coap_mem_small_destroy();
        return FAIL;
    }
    return result;
}

/**
 *  @brief Coap medium memory allocator test function
 *
 *  @param[in] data Pointer to a memory allocator test data structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_medium_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    coap_log_level_t log_level = 0;
    test_result_t result = PASS;
    unsigned char mask = 0;
    size_t byte = 0;
    size_t bit = 0;
    size_t i = 0;
    size_t j = 0;
    char active[test_data->num >> 3];
    char *p[test_data->num];
    char *q = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);
    memset(active, 0, sizeof(active));
    memset(p, 0, sizeof(p));
    log_level = coap_log_get_level();
    ret = coap_mem_medium_create(test_data->num, test_data->len);
    if (ret < 0)
    {
        coap_log_error("Failed to create memory allocator");
        return FAIL;
    }
    /* allocate buffers */
    for (byte = 0; byte < coap_mem_medium_get_active_len(); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            p[8 * byte + bit] = (char *)coap_mem_medium_alloc(test_data->len);
            if (p[8 * byte + bit] == NULL)
            {
                coap_log_error("Failed to allocate buffer");
                coap_mem_medium_destroy();
                return FAIL;
            }
            mask = (1 << bit);
            active[byte] |= mask;
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_medium_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_medium_get_active() + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_medium_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_medium_get_active(), active, coap_mem_medium_get_active_len()) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer allocation");
                coap_mem_medium_destroy();
                return FAIL;
            }
        }
    }
    /* try to allocate one too many buffers */
    q = (char *)coap_mem_medium_alloc(test_data->len);
    if (q != NULL)
    {
        coap_log_error("Too many buffers allocated");
        coap_mem_medium_destroy();
        return FAIL;
    }
    /* try to allocate a buffer that is too large */
    q = (char *)coap_mem_medium_alloc(test_data->len + 1);
    if (q != NULL)
    {
        coap_log_error("Over-sized buffer allocated");
        coap_mem_medium_destroy();
        return FAIL;
    }
    /* write data to the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            p[i][j] = (char)i;
        }
    }
    if (log_level >= COAP_LOG_INFO)
    {
        for (i = 0; i < test_data->num; i++)
        {
            printf("write buffer %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
            }
            printf(" ]\n");
        }
        /* read the data back from the buffers */
        for (i = 0; i < test_data->num; i++)
        {
            printf("read buffer  %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
                if (p[i][j] != (char)i)
                {
                    result = FAIL;
                }
            }
            printf(" ]\n");
        }
    }
    /* check the data in the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            if (p[i][j] != (char)i)
            {
                result = FAIL;
            }
        }
    }
    /* free buffers */
    for (byte = 0; byte < coap_mem_medium_get_active_len(); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            coap_mem_medium_free(p[8 * byte + bit]);
            mask = (1 << bit);
            active[byte] &= (unsigned char)(~mask);
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_medium_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_medium_get_active() + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_medium_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_medium_get_active(), active, coap_mem_medium_get_active_len()) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer free");
                coap_mem_medium_destroy();
                return FAIL;
            }
         }
    }
    coap_mem_medium_destroy();
    return result;
}

/**
 *  @brief Coap medium memory allocator invalid test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_medium_invalid_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    test_result_t result = PASS;
    int ret = 0;

    printf("%s\n", test_data->desc);
    ret = coap_mem_medium_create(test_data->num, test_data->len);
    if (ret != -EINVAL)
    {
        coap_mem_medium_destroy();
        return FAIL;
    }
    return result;
}

/**
 *  @brief Coap large memory allocator test function
 *
 *  @param[in] data Pointer to a memory allocator test data structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_large_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    coap_log_level_t log_level = 0;
    test_result_t result = PASS;
    unsigned char mask = 0;
    size_t byte = 0;
    size_t bit = 0;
    size_t i = 0;
    size_t j = 0;
    char active[test_data->num >> 3];
    char *p[test_data->num];
    char *q = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);
    memset(active, 0, sizeof(active));
    memset(p, 0, sizeof(p));
    log_level = coap_log_get_level();
    ret = coap_mem_large_create(test_data->num, test_data->len);
    if (ret < 0)
    {
        coap_log_error("Failed to create memory allocator");
        return FAIL;
    }
    /* allocate buffers */
    for (byte = 0; byte < coap_mem_large_get_active_len(); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            p[8 * byte + bit] = (char *)coap_mem_large_alloc(test_data->len);
            if (p[8 * byte + bit] == NULL)
            {
                coap_log_error("Failed to allocate buffer");
                coap_mem_large_destroy();
                return FAIL;
            }
            mask = (1 << bit);
            active[byte] |= mask;
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_large_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_large_get_active() + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_large_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_large_get_active(), active, coap_mem_large_get_active_len()) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer allocation");
                coap_mem_large_destroy();
                return FAIL;
            }
        }
    }
    /* try to allocate one too many buffers */
    q = (char *)coap_mem_large_alloc(test_data->len);
    if (q != NULL)
    {
        coap_log_error("Too many buffers allocated");
        coap_mem_large_destroy();
        return FAIL;
    }
    /* try to allocate a buffer that is too large */
    q = (char *)coap_mem_large_alloc(test_data->len + 1);
    if (q != NULL)
    {
        coap_log_error("Over-sized buffer allocated");
        coap_mem_large_destroy();
        return FAIL;
    }
    /* write data to the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            p[i][j] = (char)i;
        }
    }
    if (log_level >= COAP_LOG_INFO)
    {
        for (i = 0; i < test_data->num; i++)
        {
            printf("write buffer %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
            }
            printf(" ]\n");
        }
        /* read the data back from the buffers */
        for (i = 0; i < test_data->num; i++)
        {
            printf("read buffer  %2zu: [", i);
            for (j = 0; j < test_data->len; j++)
            {
                printf(" 0x%02x", p[i][j]);
                if (p[i][j] != (char)i)
                {
                    result = FAIL;
                }
            }
            printf(" ]\n");
        }
    }
    /* check the data in the buffers */
    for (i = 0; i < test_data->num; i++)
    {
        for (j = 0; j < test_data->len; j++)
        {
            if (p[i][j] != (char)i)
            {
                result = FAIL;
            }
        }
    }
    /* free buffers */
    for (byte = 0; byte < coap_mem_large_get_active_len(); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            coap_mem_large_free(p[8 * byte + bit]);
            mask = (1 << bit);
            active[byte] &= (unsigned char)(~mask);
            if (log_level >= COAP_LOG_INFO)
            {
                printf("mem.active: [");
                for (i = 0; i < coap_mem_large_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)(*(coap_mem_large_get_active() + i)));
                }
                printf(" ]\n");
                printf("active:     [");
                for (i = 0; i < coap_mem_large_get_active_len(); i++)
                {
                    printf(" 0x%02x", (unsigned char)active[i]);
                }
                printf(" ]\n");
            }
            if (memcmp(coap_mem_large_get_active(), active, coap_mem_large_get_active_len()) != 0)
            {
                coap_log_error("Incorrect active bitset encountered during buffer free");
                coap_mem_large_destroy();
                return FAIL;
            }
         }
    }
    coap_mem_large_destroy();
    return result;
}

/**
 *  @brief Coap large memory allocator invalid test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_large_invalid_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    test_result_t result = PASS;
    int ret = 0;

    printf("%s\n", test_data->desc);
    ret = coap_mem_large_create(test_data->num, test_data->len);
    if (ret != -EINVAL)
    {
        coap_mem_large_destroy();
        return FAIL;
    }
    return result;
}

/**
 *  @brief Coap all memory allocators test function
 *
 *  @param[in] data Pointer to a memory allocator test data structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_all_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    test_result_t result = PASS;
    int ret = 0;

    printf("%s\n", test_data->desc);
    ret = coap_mem_all_create(test_data->num, test_data->len,
                              test_data->num, test_data->len,
                              test_data->num, test_data->len);
    if (ret < 0)
    {
        coap_log_error("Failed to create memory allocators");
        return FAIL;
    }
    coap_mem_all_destroy();
    return result;
}

/**
 *  @brief Coap all memory allocators invalid test function
 *
 *  @param[in] data Pointer to a message test structure
 *
 *  @returns Test result
 */
static test_result_t test_coap_mem_all_invalid_func(test_data_t data)
{
    test_coap_mem_data_t *test_data = (test_coap_mem_data_t *)data;
    test_result_t result = PASS;
    int ret = 0;

    printf("%s\n", test_data->desc);
    ret = coap_mem_all_create(test_data->num, test_data->len,
                              test_data->num, test_data->len,
                              test_data->num, test_data->len);
    if (ret != -EINVAL)
    {
        coap_mem_all_destroy();
        return FAIL;
    }
    return result;
}

/**
 *  @brief Main function for the FreeCoAP memory allocator test application
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(void)
{
    test_t tests[] = {{test_coap_mem_func,                &test1_coap_mem_data},
                      {test_coap_mem_invalid_func,        &test2_coap_mem_data},
                      {test_coap_mem_invalid_func,        &test3_coap_mem_data},
                      {test_coap_mem_invalid_func,        &test4_coap_mem_data},
                      {test_coap_mem_small_func,          &test5_coap_mem_data},
                      {test_coap_mem_small_invalid_func,  &test6_coap_mem_data},
                      {test_coap_mem_small_invalid_func,  &test7_coap_mem_data},
                      {test_coap_mem_small_invalid_func,  &test8_coap_mem_data},
                      {test_coap_mem_medium_func,         &test9_coap_mem_data},
                      {test_coap_mem_medium_invalid_func, &test10_coap_mem_data},
                      {test_coap_mem_medium_invalid_func, &test11_coap_mem_data},
                      {test_coap_mem_medium_invalid_func, &test12_coap_mem_data},
                      {test_coap_mem_large_func,          &test13_coap_mem_data},
                      {test_coap_mem_large_invalid_func,  &test14_coap_mem_data},
                      {test_coap_mem_large_invalid_func,  &test15_coap_mem_data},
                      {test_coap_mem_large_invalid_func,  &test16_coap_mem_data},
                      {test_coap_mem_all_func,            &test17_coap_mem_data},
                      {test_coap_mem_all_invalid_func,    &test18_coap_mem_data},
                      {test_coap_mem_all_invalid_func,    &test19_coap_mem_data},
                      {test_coap_mem_all_invalid_func,    &test20_coap_mem_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    coap_log_set_level(COAP_LOG_ERROR);
    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
