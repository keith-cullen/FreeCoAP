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
 *  @file thread.h
 *
 *  @brief Include file for the FreeCoAP thread module
 */

#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

typedef enum
{
    THREAD_TYPE_JOINABLE = 0,
    THREAD_TYPE_DETACHED
}
thread_type_t;

typedef struct
{
    thread_type_t type;
    pthread_attr_t attr;
}
thread_ctx_t;

typedef struct
{
    thread_type_t type;
    pthread_t id;
}
thread_t;

int thread_joinable_ctx_create(thread_ctx_t *ctx);
int thread_detached_ctx_create(thread_ctx_t *ctx);
void thread_ctx_destroy(thread_ctx_t *ctx);

int thread_init(thread_t *thread, thread_ctx_t *ctx, void *(start_func)(void *), void *data);
int thread_join(thread_t *thread, void **result);
void thread_block_signals(void);

#endif
