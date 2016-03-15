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
 *  @file data_buf.h
 *
 *  @brief Include file for the FreeCoAP proxy data buffer module
 */

#ifndef DATA_BUF_H
#define DATA_BUF_H

/*   0                      count     size
 *   |                        |         |
 *   +------------------------+---------+
 *   |XXXXXXXXXXXXXXXXXXXXXXXX|         |
 *   +------------------------+---------+
 *   |<         used         >|< space >|
 *  data                    next
 */

#define DATA_BUF_INIT_SIZE       1024
#define DATA_BUF_MAX_SIZE        4096

#define data_buf_get_count(buf)     ((buf)->count)
#define data_buf_get_size(buf)      ((buf)->size)
#define data_buf_get_max_size(buf)  ((buf)->max_size)
#define data_buf_get_data(buf)      ((buf)->data)
#define data_buf_get_space(buf)     (((buf)->size) - ((buf)->count))  /* number of free byte positions beginning at count */
#define data_buf_get_next(buf)      ((buf)->data + (buf)->count)

typedef struct
{
    size_t count;     /* number of bytes stored in the buffer */
    size_t size;      /* current size of buffer */
    size_t max_size;  /* max allowed size of buffer */
    char *data;       /* pointer to actual buffer */
}
data_buf_t;

int data_buf_create(data_buf_t *buf, size_t size, size_t max_size);
void data_buf_destroy(data_buf_t *buf);
int data_buf_expand(data_buf_t *buf);
size_t data_buf_add(data_buf_t *buf, size_t num);
size_t data_buf_consume(data_buf_t *buf, size_t num);

#endif
