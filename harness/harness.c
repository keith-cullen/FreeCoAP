/****************************
 *    Copyright (c) 2013    *
 *    Keith Cullen          *
 ****************************/

#include <stdlib.h>
#include <stdio.h>
#include "harness.h"

#define START_STR "\n----------------------------------------\n"
#define PASS_STR    "-----------------<pass>-----------------\n"
#define FAIL_STR    "*****************[FAIL]*****************\n"

size_t harness_run(harness_test *test, size_t num_tests)
{
    harness_result result = 0;
    size_t num_passed = 0;  
    size_t i = 0;

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
        printf("\n[Total: %zd, Pass: %zd, Fail: %zd]\n\n", num_tests, num_passed, num_tests - num_passed);
    else
        printf("\n[Total: %zd, Pass: %zd]\n\n", num_tests, num_passed);

    return num_passed;
}
