/*
 * Copyright (c) 2015 Keith Cullen.
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
 *  @file test.h
 *
 *  @brief Include file for the FreeCoAP test harness
 */

#ifndef TEST_H
#define TEST_H

#define DEBUG_PRINT(fmt, ...) //printf(fmt, ## __VA_ARGS__)                     /**< Debug print */

/**
 *  @brief Test result enumeration
 */
typedef enum {FAIL = 0, PASS} test_result_t;

/**
 *  @brief Test data typedef
 */
typedef void *test_data_t;

/**
 *  @brief Test function typedef
 */
typedef test_result_t (*test_func_t)(test_data_t);

/**
 *  @brief Test structure
 */
typedef struct
{
    test_func_t func;                                                           /**< Test function */
    test_data_t data;                                                           /**< Test data */
}
test_t;

/**
 *  @brief Run the tests
 *
 *  @param[in] test Pointer to an array of test structures
 *  @param[in] num_tests Number of test structures in the array
 *
 *  @returns Number of tests that passed
 */
unsigned test_run(test_t *test, unsigned num_tests);

#endif
