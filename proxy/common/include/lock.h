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
 *  @file lock.h
 *
 *  @brief Include file for the FreeCoAP lock module
 */

#ifndef LOCK_H
#define LOCK_H

#include <pthread.h>

typedef pthread_mutex_t lock_t;

static inline int lock_create(lock_t *lock)
{
    pthread_mutexattr_t attr;
    int ret = 0;

    ret = pthread_mutexattr_init(&attr);
    if (ret != 0)
    {
        return -1;
    }
    ret = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    if (ret != 0)
    {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }
    ret = pthread_mutex_init(lock, &attr);
    if (ret != 0)
    {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }
    ret = pthread_mutexattr_destroy(&attr);
    if (ret != 0)
    {
        return -1;
    }
    return 0;
}

static inline void lock_destroy(lock_t *lock)
{
    pthread_mutex_destroy(lock);
}

static inline int lock_get(lock_t *lock)
{
    int ret = 0;

    ret = pthread_mutex_lock(lock);
    if (ret != 0)
    {
        return -1;
    }
    return 0;
}

static inline int lock_put(lock_t *lock)
{
    int ret = 0;

    ret = pthread_mutex_unlock(lock);
    if (ret != 0)
    {
        return -1;
    }
    return 0;
}

#endif
