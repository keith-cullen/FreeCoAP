/****************************
 *    Copyright (c) 2013    *
 *    Keith Cullen          *
 ****************************/

#ifndef HARNESS_H
#define HARNESS_H

#define DEBUG_PRINT(fmt, ...) //printf(fmt, ## __VA_ARGS__)

typedef enum {FAIL = 0, PASS} harness_result;
typedef void *harness_data;
typedef harness_result (*harness_func)(harness_data);
typedef struct {harness_func func; harness_data data;} harness_test;

size_t harness_run(harness_test *test, size_t num_tests);

#endif
