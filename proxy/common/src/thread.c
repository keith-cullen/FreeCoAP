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
 *  @file thread.c
 *
 *  @brief Source file for the FreeCoAP thread module
 */

#include <signal.h>
#include "thread.h"

static int thread_ctx_create(thread_ctx_t *ctx, thread_type_t type)
{
    int detach_state = 0;
    int ret = 0;

    ctx->type = type;
    detach_state = (type == THREAD_TYPE_JOINABLE)
                 ? PTHREAD_CREATE_JOINABLE
                 : PTHREAD_CREATE_DETACHED;
    ret = pthread_attr_init(&ctx->attr);
    if (ret != 0)
    {
        return -1;
    }
    ret = pthread_attr_setdetachstate(&ctx->attr, detach_state);
    if (ret != 0)
    {
        return -1;
    }
    return 0;
}

int thread_joinable_ctx_create(thread_ctx_t *ctx)
{
    return thread_ctx_create(ctx, THREAD_TYPE_JOINABLE);
}

int thread_detached_ctx_create(thread_ctx_t *ctx)
{
    return thread_ctx_create(ctx, THREAD_TYPE_DETACHED);
}

void thread_ctx_destroy(thread_ctx_t *ctx)
{
    pthread_attr_destroy(&ctx->attr);
}

int thread_init(thread_t *thread, thread_ctx_t *ctx, void *(start_func)(void *), void *data)
{
    int ret = 0;

    thread->type = ctx->type;
    ret = pthread_create(&thread->id, &ctx->attr, start_func, data);
    if (ret != 0)
    {
        return -1;
    }
    return 0;
}

int thread_join(thread_t *thread, void **result)
{
    int ret = 0;

    if (thread->type == THREAD_TYPE_JOINABLE)
    {
        ret = pthread_join(thread->id, result);
        if (ret != 0)
        {
            *result = NULL;
            return -1;
        }
    }
    else  /* detached thread */
    {
        *result = NULL;
    }
    return 0;
}

/* block all signals */
void thread_block_signals(void)
{
    sigset_t signal_set = {{0}};

    sigfillset(&signal_set);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
}
