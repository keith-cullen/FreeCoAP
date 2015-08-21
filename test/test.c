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
 *  @file test.c
 *
 *  @brief Source file for the FreeCoAP test harness
 */

#include <stdlib.h>
#include <stdio.h>
#include "test.h"

#define START_STR   "\n----------------------------------------\n"              /**< String printed at the start of a test */
#define PASS_STR    "-----------------<pass>-----------------\n"                /**< String printed at the end of a test that passed */
#define FAIL_STR    "*****************[FAIL]*****************\n"                /**< String printed at the end of a test that failed */

unsigned test_run(test_t *test, unsigned num_tests)
{
    test_result_t result = 0;
    unsigned num_passed = 0;  
    unsigned i = 0;

    printf(START_STR);
    for (i = 0; i < num_tests; i++)
    {
        result = (*test[i].func)(test[i].data);
        if (result == PASS)
        {
            num_passed++;
            printf(PASS_STR);
        }
        else
        {
            printf(FAIL_STR);
        }
    }
    if (num_passed < num_tests)
        printf("\n[Total: %u, Pass: %u, Fail: %u]\n\n", num_tests, num_passed, num_tests - num_passed);
    else
        printf("\n[Total: %u, Pass: %u]\n\n", num_tests, num_passed);

    return num_passed;
}
