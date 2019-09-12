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
 *  @file coap_mem.c
 *
 *  @brief Source file for the FreeCoAP memory allocator
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "coap_mem.h"

int coap_mem_create(coap_mem_t *mem, size_t num, size_t len)
{
    memset(mem, 0, sizeof(coap_mem_t));
    if (((num & 0x7) != 0) || (len == 0))
    {
        return -EINVAL;
    }
    mem->buf = (char *)malloc(num * len);
    if (mem->buf == NULL)
    {
        return -ENOMEM;
    }
    mem->num = num;
    mem->len = len;
    mem->active = (char *)calloc(num >> 3, 1);
    if (mem->active == NULL)
    {
        free(mem->buf);
        memset(mem, 0, sizeof(coap_mem_t));
        return -ENOMEM;
    }
    return 0;
}

void coap_mem_destroy(coap_mem_t *mem)
{
    free(mem->active);
    free(mem->buf);
    memset(mem, 0, sizeof(coap_mem_t));
}

void *coap_mem_alloc(coap_mem_t *mem, size_t len)
{
    unsigned char mask = 0;
    size_t byte = 0;
    size_t bit = 0;
    void *mem_buf = NULL;

    if (len > mem->len)
    {
        return NULL;
    }
    for (byte = 0; byte < coap_mem_get_active_len(mem); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            mask = (1 << bit);
            if ((mem->active[byte] & mask) == 0)
            {
                mem->active[byte] |= mask;
                mem_buf = &mem->buf[(8 * byte + bit) * mem->len];
                return mem_buf;
            }
        }
    }
    return NULL;
}

void coap_mem_free(coap_mem_t *mem, void *buf)
{
    unsigned char mask = 0;
    size_t byte = 0;
    size_t bit = 0;
    void *mem_buf = NULL;

    for (byte = 0; byte < coap_mem_get_active_len(mem); byte++)
    {
        for (bit = 0; bit < 8; bit++)
        {
            mem_buf = &mem->buf[(8 * byte + bit) * mem->len];
            if (buf == mem_buf)
            {
                mask = ~(1 << bit);
                mem->active[byte] &= mask;
            }
        }
    }
}

/**
 *  Small memory allocator
 *
 *  This memory allocator can be used by any part of the CoAP library.
 */
static coap_mem_t coap_mem_small = {0};

int coap_mem_small_create(size_t num, size_t len)
{
    return coap_mem_create(&coap_mem_small, num, len);
}

void coap_mem_small_destroy(void)
{
    coap_mem_destroy(&coap_mem_small);
}

char *coap_mem_small_get_buf(void)
{
    return coap_mem_get_buf(&coap_mem_small);
}

size_t coap_mem_small_get_num(void)
{
    return coap_mem_get_num(&coap_mem_small);
}

size_t coap_mem_small_get_len(void)
{
    return coap_mem_get_len(&coap_mem_small);
}

size_t coap_mem_small_get_active_len(void)
{
    return coap_mem_get_active_len(&coap_mem_small);
}

char *coap_mem_small_get_active(void)
{
    return coap_mem_small.active;
}

void *coap_mem_small_alloc(size_t len)
{
    return coap_mem_alloc(&coap_mem_small, len);
}

void coap_mem_small_free(void *buf)
{
    coap_mem_free(&coap_mem_small, buf);
}

/**
 *  Medium memory allocator
 *
 *  This memory allocator can be used by any part of the CoAP library.
 */
static coap_mem_t coap_mem_medium = {0};

int coap_mem_medium_create(size_t num, size_t len)
{
    return coap_mem_create(&coap_mem_medium, num, len);
}

void coap_mem_medium_destroy(void)
{
    coap_mem_destroy(&coap_mem_medium);
}

char *coap_mem_medium_get_buf(void)
{
    return coap_mem_get_buf(&coap_mem_medium);
}

size_t coap_mem_medium_get_num(void)
{
    return coap_mem_get_num(&coap_mem_medium);
}

size_t coap_mem_medium_get_len(void)
{
    return coap_mem_get_len(&coap_mem_medium);
}

size_t coap_mem_medium_get_active_len(void)
{
    return coap_mem_get_active_len(&coap_mem_medium);
}

char *coap_mem_medium_get_active(void)
{
    return coap_mem_medium.active;
}

void *coap_mem_medium_alloc(size_t len)
{
    return coap_mem_alloc(&coap_mem_medium, len);
}

void coap_mem_medium_free(void *buf)
{
    coap_mem_free(&coap_mem_medium, buf);
}

/**
 *  Large memory allocator
 *
 *  This memory allocator can be used by any part of the CoAP library.
 */
static coap_mem_t coap_mem_large = {0};

int coap_mem_large_create(size_t num, size_t len)
{
    return coap_mem_create(&coap_mem_large, num, len);
}

void coap_mem_large_destroy(void)
{
    coap_mem_destroy(&coap_mem_large);
}

char *coap_mem_large_get_buf(void)
{
    return coap_mem_get_buf(&coap_mem_large);
}

size_t coap_mem_large_get_num(void)
{
    return coap_mem_get_num(&coap_mem_large);
}

size_t coap_mem_large_get_len(void)
{
    return coap_mem_get_len(&coap_mem_large);
}

size_t coap_mem_large_get_active_len(void)
{
    return coap_mem_get_active_len(&coap_mem_large);
}

char *coap_mem_large_get_active(void)
{
    return coap_mem_large.active;
}

void *coap_mem_large_alloc(size_t len)
{
    return coap_mem_alloc(&coap_mem_large, len);
}

void coap_mem_large_free(void *buf)
{
    coap_mem_free(&coap_mem_large, buf);
}

int coap_mem_all_create(size_t small_num, size_t small_len,
                        size_t medium_num, size_t medium_len,
                        size_t large_num, size_t large_len)
{
    int ret = 0;

    ret = coap_mem_small_create(small_num, small_len);
    if (ret < 0)
    {
        return ret;
    }
    ret = coap_mem_medium_create(medium_num, medium_len);
    if (ret < 0)
    {
        coap_mem_small_destroy();
        return ret;
    }
    ret = coap_mem_large_create(large_num, large_len);
    if (ret < 0)
    {
        coap_mem_medium_destroy();
        coap_mem_small_destroy();
        return ret;
    }
    return 0;
}

void coap_mem_all_destroy(void)
{
    coap_mem_large_destroy();
    coap_mem_medium_destroy();
    coap_mem_small_destroy();
}
