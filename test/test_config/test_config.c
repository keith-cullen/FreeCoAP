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
 *  @file test_config.c
 *
 *  @brief Source file for the FreeCoAP configuration library unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "test.h"

#define BUF_LEN  128

#define DIM(x) (sizeof(x) / sizeof(x[0]))

typedef struct
{
    const char section_name[BUF_LEN + 1];
    const char entry_name[BUF_LEN + 1];
    const char entry_value[BUF_LEN + 1];
}
entry_t;

typedef struct
{
    const char *desc;
    const char *str;
    entry_t *set_entries;
    entry_t *get_entries;
    unsigned num_set_entries;
    unsigned num_get_entries;
    unsigned parse_ret;
    unsigned parse_line;
    unsigned parse_col;
}
test_config_data_t;

entry_t test1_entries[] =
{
    {"", "str", "text"},
    {"", "num", "123"}
};

test_config_data_t test1_data =
{
    .desc = "test 1: set and get multiple assignments in default section",
    .str = NULL,
    .set_entries = test1_entries,
    .get_entries = test1_entries,
    .num_set_entries = DIM(test1_entries),
    .num_get_entries = DIM(test1_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

entry_t test2_entries[] =
{
    {"sectionA", "str1", "text1"},
    {"sectionA", "num1", "123"},
    {"sectionB", "str2", "text2"},
    {"sectionB", "num2", "456"}
};

test_config_data_t test2_data =
{
    .desc = "test 2: set and get multiple assignments in multiple sections",
    .str = NULL,
    .set_entries = test2_entries,
    .get_entries = test2_entries,
    .num_set_entries = DIM(test2_entries),
    .num_get_entries = DIM(test2_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

entry_t test3_set_entries[] =
{
    {"sectionA", "str1", "text1"},
    {"sectionA", "num1", "123"},
    {"sectionB", "str2", "text2"},
    {"sectionB", "num2", "456"},
    {"sectionA", "str3", "text3"},
    {"sectionA", "num3", "789"},
};

entry_t test3_get_entries[] =
{
    {"sectionA", "str1", "text1"},
    {"sectionA", "num1", "123"},
    {"sectionA", "str3", "text3"},
    {"sectionA", "num3", "789"},
    {"sectionB", "str2", "text2"},
    {"sectionB", "num2", "456"}
};

test_config_data_t test3_data =
{
    .desc = "test 3: set and get multiple assignments in duplicate sections",
    .str = NULL,
    .set_entries = test3_set_entries,
    .get_entries = test3_get_entries,
    .num_set_entries = DIM(test3_set_entries),
    .num_get_entries = DIM(test3_get_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

entry_t test4_set_entries[] =
{
    {"sectionA", "str1", "text1"},
    {"sectionA", "num1", "123"},
    {"sectionB", "str2", "text2"},
    {"sectionB", "num2", "456"},
    {"sectionA", "str1", "text3"},
    {"sectionA", "num1", "789"},
};

entry_t test4_get_entries[] =
{
    {"sectionA", "str1", "text3"},
    {"sectionA", "num1", "789"},
    {"sectionB", "str2", "text2"},
    {"sectionB", "num2", "456"}
};

test_config_data_t test4_data =
{
    .desc = "test 4: set and get duplicate assignments in duplicate sections",
    .str = NULL,
    .set_entries = test4_set_entries,
    .get_entries = test4_get_entries,
    .num_set_entries = DIM(test4_set_entries),
    .num_get_entries = DIM(test4_get_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

test_config_data_t test5_data =
{
    .desc = "test 5: parse mulltiple assignments in default section",
    .str = "str=text\nnum=123\n",
    .set_entries = NULL,
    .get_entries = test1_entries,  /* re-use test1 params */
    .num_set_entries = 0,
    .num_get_entries = DIM(test1_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

test_config_data_t test6_data =
{
    .desc = "test 6: parse multiple ssignments in multiple sections",
    .str = "[sectionA]\nstr1=text1\nnum1=123\n[sectionB]\nstr2=text2\nnum2=456\n",
    .set_entries = NULL,
    .get_entries = test2_entries,  /* re-use test2 params */
    .num_set_entries = 0,
    .num_get_entries = DIM(test2_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

test_config_data_t test7_data =
{
    .desc = "test 7: parse multiple assignments in duplicate sections",
    .str = "[sectionA]\nstr1=text1\nnum1=123\n[sectionB]\nstr2=text2\nnum2=456\n[sectionA]\nstr3=text3\nnum3=789\n",
    .set_entries = NULL,
    .get_entries = test3_get_entries,  /* re-use test3 params */
    .num_set_entries = 0,
    .num_get_entries = DIM(test3_get_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

test_config_data_t test8_data =
{
    .desc = "test 8: parse duplicate assignments in duplicate sections",
    .str = "[sectionA]\nstr1=text1\nnum1=123\n[sectionB]\nstr2=text2\nnum2=456\n[sectionA]\nstr1=text3\nnum1=789\n",
    .set_entries = NULL,
    .get_entries = test4_get_entries,  /* re-use test4 params */
    .num_set_entries = 0,
    .num_get_entries = DIM(test4_get_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

entry_t test9_entries[] =
{
    {"sectionA", "str1", "text1"},
    {"sectionB", "num1", "123"},
    {"sectionC", "str2", "text2"},
    {"sectionD", "num2", "456"}
};

test_config_data_t test9_data =
{
    .desc = "test 9: parse assignments in multiple sections with whitespace",
    .str = " [ sectionA ] \n str1 = text1 \n\t[\tsectionB\t]\t\n\tnum1\t=\t123\t\n \t[ \tsectionC\t ]\t \n \tstr2\t = \ttext2\t \n \t [ \t sectionD \t ] \t \n \t num2 \t = \t 456 \t \n",
    .set_entries = NULL,
    .get_entries = test9_entries,
    .num_set_entries = 0,
    .num_get_entries = DIM(test9_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

test_config_data_t test10_data =
{
    .desc = "test 10: parse assignments in multiple sections with comments",
    .str = "[sectionA];section\nstr1=text1;assignment\n[sectionB] ;section\nnum1=123 ;assignment\n[sectionC]\t;section\nstr2=text2\t;assignment\n[sectionD] \t;section\nnum2=456 \t;assignment\n",
    .set_entries = NULL,
    .get_entries = test9_entries,  /* re-use test9 params */
    .num_set_entries = 0,
    .num_get_entries = DIM(test9_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

entry_t test11_entries[] =
{
    {"sectionA", "str1", "text1"},
    {"sectionA", "str2",  " text2 "},
    {"sectionB", "str3",  "\ttext3\t"},
    {"sectionB", "str4",  "\\\"text4\\\""}
};

test_config_data_t test11_data =
{
    .desc = "test 11: parse multiple assignments in multiple sections with quoted values",
    .str = "[sectionA]\nstr1=\"text1\"\nstr2=\" text2 \"\n[sectionB]\nstr3=\"\ttext3\t\"\nstr4=\"\\\"text4\\\"\"\n",
    .set_entries = NULL,
    .get_entries = test11_entries,
    .num_set_entries = 0,
    .num_get_entries = DIM(test11_entries),
    .parse_ret = 0,
    .parse_line = 0,
    .parse_col = 0
};

test_config_data_t test12_data =
{
    .desc = "test 12: parse invalid section",
    .str = "[",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 2
};

test_config_data_t test13_data =
{
    .desc = "test 13: parse invalid section",
    .str = "[sectionA",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 10
};

test_config_data_t test14_data =
{
    .desc = "test 14: parse invalid section",
    .str = "[sectionA\n]",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 10
};

test_config_data_t test15_data =
{
    .desc = "test 15: parse invalid section",
    .str = "[1sectionA]",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 2
};

test_config_data_t test16_data =
{
    .desc = "test 16: parse invalid section",
    .str = "[123]",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 2
};

test_config_data_t test17_data =
{
    .desc = "test 17: parse invalid section",
    .str = "[sectionA extra]",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 11
};

test_config_data_t test18_data =
{
    .desc = "test 18: parse invalid section",
    .str = "[sectionA] extra",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 12
};

test_config_data_t test19_data =
{
    .desc = "test 19: parse invalid section",
    .str = "[\"sectionA\"]",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 2
};

test_config_data_t test20_data =
{
    .desc = "test 20: parse invalid assignment",
    .str = "name",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 5
};

test_config_data_t test21_data =
{
    .desc = "test 21: parse invalid assignment",
    .str = "name=",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 6
};

test_config_data_t test22_data =
{
    .desc = "test 22: parse invalid assignment",
    .str = "name=\nvalue",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 6
};

test_config_data_t test23_data =
{
    .desc = "test 23: parse invalid assignment",
    .str = "1name=value",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 1
};

test_config_data_t test24_data =
{
    .desc = "test 24: parse invalid assignment",
    .str = "name=1value",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 7
};

test_config_data_t test25_data =
{
    .desc = "test 25: parse invalid assignment",
    .str = "name extra=value",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 6
};

test_config_data_t test26_data =
{
    .desc = "test 26: parse invalid assignment",
    .str = "name=value extra",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 12
};

test_config_data_t test27_data =
{
    .desc = "test 27: parse invalid assignment",
    .str = "name=12 3",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 9
};

test_config_data_t test28_data =
{
    .desc = "test 28: parse invalid assignment",
    .str = "\"name\"=value",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 1
};

test_config_data_t test29_data =
{
    .desc = "test 29: parse invalid assignment",
    .str = "name=\"value\" \"extra\"",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ESYNTAX,
    .parse_line = 1,
    .parse_col = 14
};

test_config_data_t test30_data =
{
    .desc = "test 30: parse invalid symbol",
    .str = "#comment",
    .set_entries = NULL,
    .get_entries = NULL,
    .num_set_entries = 0,
    .num_get_entries = 0,
    .parse_ret = CONFIG_ELEXICAL,
    .parse_line = 1,
    .parse_col = 1
};

test_result_t test_set_get_func(test_data_t data)
{
    test_config_data_t *test_data = (test_config_data_t *)data;
    test_result_t result = PASS;
    unsigned i = 0;
    config_t config = {0};
    const char *section_name = NULL;
    const char *entry_name = NULL;
    const char *entry_value = NULL;
    const char *val = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);

    config_create(&config);

    for (i = 0; i < test_data->num_set_entries; i++)
    {
        section_name = test_data->set_entries[i].section_name;
        entry_name = test_data->set_entries[i].entry_name;
        entry_value = test_data->set_entries[i].entry_value;

        ret = config_set(&config, section_name, entry_name, entry_value);
        if (ret != 0)
        {
            result = FAIL;
        }

        DEBUG_PRINT("set: section: '%s', name: '%s', value: '%s'\n", section_name, entry_name, entry_value);
    }
    DEBUG_PRINT("\n");
    for (i = 0; i < test_data->num_get_entries; i++)
    {
        section_name = test_data->get_entries[i].section_name;
        entry_name = test_data->get_entries[i].entry_name;
        entry_value = test_data->get_entries[i].entry_value;

        val = config_get(&config, section_name, entry_name);
        if ((val == NULL) || (strcmp(val, entry_value) != 0))
        {
            result = FAIL;
        }

        DEBUG_PRINT("get: section: '%s', name: '%s', value: '%s'\n", section_name, entry_name, entry_value);
    }

    config_destroy(&config);

    return result;
}

test_result_t test_parse_func(test_data_t data)
{
    test_config_data_t *test_data = (test_config_data_t *)data;
    test_result_t result = PASS;
    unsigned line = 0;
    unsigned col = 0;
    unsigned i = 0;
    config_t config = {0};
    const char *section_name = NULL;
    const char *entry_name = NULL;
    const char *entry_value = NULL;
    const char *val = NULL;
    int ret = 0;

    printf("%s\n", test_data->desc);

    DEBUG_PRINT("%s\n", test_data->str);

    config_create(&config);

    ret = config_parse(&config, test_data->str, &line, &col);
    if ((ret != test_data->parse_ret) || (line != test_data->parse_line) || (col != test_data->parse_col))
    {
        DEBUG_PRINT("Error: config_parse returned: %d, '%s', line: %d, col: %d\n", ret, config_strerr(ret), line, col);
        result = FAIL;
    }

    for (i = 0; i < test_data->num_get_entries; i++)
    {
        section_name = test_data->get_entries[i].section_name;
        entry_name = test_data->get_entries[i].entry_name;
        entry_value = test_data->get_entries[i].entry_value;

        val = config_get(&config, section_name, entry_name);
        if ((val == NULL) || (strcmp(val, entry_value) != 0))
        {
            result = FAIL;
        }

        DEBUG_PRINT("get: section: '%s', name: '%s', value: '%s'\n", section_name, entry_name, entry_value);
    }

    config_destroy(&config);

    return result;
}

test_result_t test_parse_invalid(test_data_t data)
{
    test_config_data_t *test_data = (test_config_data_t *)data;
    test_result_t result = PASS;
    unsigned line = 0;
    unsigned col = 0;
    config_t config = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    DEBUG_PRINT("%s\n", test_data->str);

    config_create(&config);

    ret = config_parse(&config, test_data->str, &line, &col);
    if ((ret != test_data->parse_ret) || (line != test_data->parse_line) || (col != test_data->parse_col))
    {
        result = FAIL;
    }
    DEBUG_PRINT("config_parse returned: %d, '%s', line: %d, col: %d\n", ret, config_strerr(ret), line, col);

    config_destroy(&config);

    return result;
}

int main(void)
{
    test_t tests[] = {{test_set_get_func,  &test1_data},
                      {test_set_get_func,  &test2_data},
                      {test_set_get_func,  &test3_data},
                      {test_set_get_func,  &test4_data},
                      {test_parse_func,    &test5_data},
                      {test_parse_func,    &test6_data},
                      {test_parse_func,    &test7_data},
                      {test_parse_func,    &test8_data},
                      {test_parse_func,    &test9_data},
                      {test_parse_func,    &test10_data},
                      {test_parse_func,    &test11_data},
                      {test_parse_invalid, &test12_data},
                      {test_parse_invalid, &test13_data},
                      {test_parse_invalid, &test14_data},
                      {test_parse_invalid, &test15_data},
                      {test_parse_invalid, &test16_data},
                      {test_parse_invalid, &test17_data},
                      {test_parse_invalid, &test18_data},
                      {test_parse_invalid, &test19_data},
                      {test_parse_invalid, &test20_data},
                      {test_parse_invalid, &test21_data},
                      {test_parse_invalid, &test22_data},
                      {test_parse_invalid, &test23_data},
                      {test_parse_invalid, &test24_data},
                      {test_parse_invalid, &test25_data},
                      {test_parse_invalid, &test26_data},
                      {test_parse_invalid, &test27_data},
                      {test_parse_invalid, &test28_data},
                      {test_parse_invalid, &test29_data},
                      {test_parse_invalid, &test30_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
