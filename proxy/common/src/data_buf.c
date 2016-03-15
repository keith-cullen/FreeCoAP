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
 *  @file data_buf.c
 *
 *  @brief Source file for the FreeCoAP proxy data buffer module
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "data_buf.h"

int data_buf_create(data_buf_t *buf, size_t size, size_t max_size)
{
    memset(buf, 0, sizeof(data_buf_t));
    if (size > max_size)
    {
        return -EINVAL;
    }
    buf->data = (char *)calloc(size + 1, 1);
    if (buf->data == NULL)
    {
        return -ENOMEM;
    }
    buf->size = size;
    buf->max_size = max_size;
    return 0;
}

void data_buf_destroy(data_buf_t *buf)
{
    free(buf->data);
    memset(buf, 0, sizeof(data_buf_t));
}

int data_buf_expand(data_buf_t *buf)
{
    size_t new_size = 0;
    char *new_data = NULL;

    new_size = 2 * buf->size;
    if (new_size > buf->max_size)
    {
        return -EINVAL;
    }
    new_data = (char *)malloc(new_size + 1);
    if (new_data == NULL)
    {
        return -ENOMEM;
    }
    memcpy(new_data, buf->data, buf->count);
    memset(new_data + buf->count, 0, new_size - buf->count);
    free(buf->data);
    buf->data = new_data;
    buf->size = new_size;
    return 0;
}

size_t data_buf_add(data_buf_t *buf, size_t num)
{
    size_t space = 0;

    space = data_buf_get_space(buf);
    if (num > space)
        num = space;
    buf->count += num;
    return num;
}

size_t data_buf_consume(data_buf_t *buf, size_t num)
{
    if (num > buf->count)
        num = buf->count;
    memmove(buf->data, buf->data + num, buf->size - num);
    memset(buf->data + buf->size - num, 0, num);
    buf->count -= num;
    return num;
}
