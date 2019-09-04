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
 *  @file coap_mem.h
 *
 *  @brief Include file for the FreeCoAP memory allocator
 */

#ifndef COAP_MEM_H
#define COAP_MEM_H

#include <stddef.h>

#define coap_mem_get_buf(mem)         ((mem)->buf)                              /**< Get the array of buffers in a memory allocator */
#define coap_mem_get_num(mem)         ((mem)->num)                              /**< Get the number of buffers in a memory allocator */
#define coap_mem_get_len(mem)         ((mem)->len)                              /**< Get the length of each buffer in a memory allocator */
#define coap_mem_get_active(mem)      ((mem)->active)                           /**< Get the active bitset from a memory allocator */
#define coap_mem_get_active_len(mem)  ((mem)->num >> 3)                         /**< Get the length of the active bitset from a memory allocator */

/**
 *  @brief Memory allocator structure
 */
typedef struct
{
    char *buf;                                                                  /**< Pointer to an array of buffers */
    size_t num;                                                                 /**< Number of buffers */
    size_t len;                                                                 /**< Length of each buffer */
    char *active;                                                               /**< Bitset marking active buffers */
}
coap_mem_t;

/**
 *  @brief Initialise a memory allocator structure
 *
 *  @param[out] mem Pointer to a memory allocator
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_mem_create(coap_mem_t *mem, size_t num, size_t len);

/**
 *  @brief Deinitialise a memory allocator structure
 *
 *  @param[in,out] mem Pointer to a memory allocator
 */
void coap_mem_destroy(coap_mem_t *mem);

/**
 *  @brief Allocate a buffer from a memory allocator
 *
 *  @param[in,out] mem Pointer to a memory allocator
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *coap_mem_alloc(coap_mem_t *mem, size_t len);

/**
 *  @brief Return a buffer back to a memory allocator
 *
 *  @param[in,out] mem Pointer to a memory allocator
 *  @param[in] buf Pointer to a buffer
 */
void coap_mem_free(coap_mem_t *mem, void *buf);

/**
 *  @brief Initialise the small memory allocator
 *
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_mem_small_create(size_t num, size_t len);

/**
 *  @brief Deinitialise the small memory allocator
 */
void coap_mem_small_destroy(void);

/**
 *  @brief Get the array of buffers in the small memory allocator
 *
 *  @returns Pointer to the array of buffers
 */
char *coap_mem_small_get_buf(void);

/**
 *  @brief Get the number of buffers in the small memory allocator
 *
 *  @returns Number of buffers
 */
size_t coap_mem_small_get_num(void);

/**
 *  @brief Get the length of each buffer in the small memory allocator
 *
 *  @returns Length of each buffer
 */
size_t coap_mem_small_get_len(void);

/**
 *  @brief Get the length of the active bitset from the small memory allocator
 *
 *  @returns Length of the active bitset from the small memory allocator
 */
size_t coap_mem_small_get_active_len(void);

/**
 *  @brief Get the active bitset from the small memory allocator
 *
 *  @returns the active bitset from the small memory allocator
 */
char *coap_mem_small_get_active(void);

/**
 *  @brief Allocate a buffer from the small memory allocator
 *
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *coap_mem_small_alloc(size_t len);

/**
 *  @brief Return a buffer back to the small memory allocator
 *
 *  @param[in] buf Pointer to a buffer
 */
void coap_mem_small_free(void *buf);

/**
 *  @brief Initialise the medium memory allocator
 *
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_mem_medium_create(size_t num, size_t len);

/**
 *  @brief Deinitialise the medium memory allocator
 */
void coap_mem_medium_destroy(void);

/**
 *  @brief Get the array of buffers in the medium memory allocator
 *
 *  @returns Pointer to the array of buffers
 */
char *coap_mem_medium_get_buf(void);

/**
 *  @brief Get the number of buffers in the medium memory allocator
 *
 *  @returns Number of buffers
 */
size_t coap_mem_medium_get_num(void);

/**
 *  @brief Get the length of each buffer in the medium memory allocator
 *
 *  @returns Length of each buffer
 */
size_t coap_mem_medium_get_len(void);

/**
 *  @brief Get the length of the active bitset from the medium memory allocator
 *
 *  @returns Length of the active bitset from the medium memory allocator
 */
size_t coap_mem_medium_get_active_len(void);

/**
 *  @brief Get the active bitset from the medium memory allocator
 *
 *  @returns the active bitset from the medium memory allocator
 */
char *coap_mem_medium_get_active(void);

/**
 *  @brief Allocate a buffer from the medium memory allocator
 *
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *coap_mem_medium_alloc(size_t len);

/**
 *  @brief Return a buffer back to the medium memory allocator
 *
 *  @param[in] buf Pointer to a buffer
 */
void coap_mem_medium_free(void *buf);

/**
 *  @brief Initialise the large memory allocator
 *
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_mem_large_create(size_t num, size_t len);

/**
 *  @brief Deinitialise the large memory allocator
 */
void coap_mem_large_destroy(void);

/**
 *  @brief Get the array of buffers in the large memory allocator
 *
 *  @returns Pointer to the array of buffers
 */
char *coap_mem_large_get_buf(void);

/**
 *  @brief Get the number of buffers in the large memory allocator
 *
 *  @returns Number of buffers
 */
size_t coap_mem_large_get_num(void);

/**
 *  @brief Get the length of each buffer in the large memory allocator
 *
 *  @returns Length of each buffer
 */
size_t coap_mem_large_get_len(void);

/**
 *  @brief Get the length of the active bitset from the large memory allocator
 *
 *  @returns Length of the active bitset from the large memory allocator
 */
size_t coap_mem_large_get_active_len(void);

/**
 *  @brief Get the active bitset from the large memory allocator
 *
 *  @returns the active bitset from the large memory allocator
 */
char *coap_mem_large_get_active(void);

/**
 *  @brief Allocate a buffer from the large memory allocator
 *
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *coap_mem_large_alloc(size_t len);

/**
 *  @brief Return a buffer back to the large memory allocator
 *
 *  @param[in] buf Pointer to a buffer
 */
void coap_mem_large_free(void *buf);

/**
 *  @brief Initialise all memory allocators
 *
 *  @param[in] small_num Number of small buffers
 *  @param[in] small_len Length of each small buffer
 *  @param[in] medium_num Number of medium buffers
 *  @param[in] medium_len Length of each medium buffer
 *  @param[in] large_num Number of large buffers
 *  @param[in] large_len Length of each large buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_mem_all_create(size_t small_num, size_t small_len,
                        size_t medium_num, size_t medium_len,
                        size_t large_num, size_t large_len);

/**
 *  @brief Deinitialise all memory allocators
 */
void coap_mem_all_destroy(void);

#endif
