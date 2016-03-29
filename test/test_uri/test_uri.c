/*
 * Copyright (c) 2010 Keith Cullen.
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
 *  @file test_uri.c
 *
 *  @brief Source file for the FreeCoAP URI unit tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "uri.h"
#include "test.h"

#define DIM(x) (sizeof(x) / sizeof(x[0]))                                       /**< Calculate the size of an array */

/*  #undef DEBUG_PRINT
 *  #define DEBUG_PRINT(fmt, ...)
 */

 /**
  *  @brief Print the contents of a URI structure
  *
  *  @param[in] uri Pointer to a URI structure
  */
static void print_uri(uri_t *uri)
{
    DEBUG_PRINT("uri->scheme    : '%s'\n", uri->scheme);
    DEBUG_PRINT("uri->userinfo  : '%s'\n", uri->userinfo);
    DEBUG_PRINT("uri->host      : '%s'\n", uri->host);
    DEBUG_PRINT("uri->port      : '%s'\n", uri->port);
    DEBUG_PRINT("uri->path      : '%s'\n", uri->path);
    DEBUG_PRINT("uri->query     : '%s'\n", uri->query);
    DEBUG_PRINT("uri->fragment  : '%s'\n", uri->fragment);
}

/**
 *  @brief URI test data structure
 */
typedef struct
{
    const char *desc;                                                           /**< Test description */
    const char *uri;                                                            /**< Pointer to a URI structure */
    const char *exp_scheme;                                                     /**< Expected URI scheme value */
    const char *exp_userinfo;                                                   /**< Expected URI userinfo value */
    const char *exp_host;                                                       /**< Expected URI host value */
    const char *exp_port;                                                       /**< Expected URI port value */
    const char *exp_path;                                                       /**< Expected URI path value */
    const char *exp_query;                                                      /**< Expected URI query value */
    const char *exp_fragment;                                                   /**< Expected URI fragment value */
    const char *set_scheme;                                                     /**< Scheme value to be set in a URI structure */
    const char *set_userinfo;                                                   /**< User-info value to be set in a URI structure */
    const char *set_host;                                                       /**< Host value to be set in a URI structure */
    const char *set_port;                                                       /**< Port value to be set in a URI structure */
    const char *set_path;                                                       /**< Path value to be set in a URI structure */
    const char *set_query;                                                      /**< Query value to be set in a URI structure */
    const char *set_fragment;                                                   /**< Fragment value to be set in a URI structure */
    int ret_parse;                                                              /**< Expected return value for the parse operation */
    int ret_copy;                                                               /**< Expected return value for the copy operation */
    int ret_set_scheme;                                                         /**< Expected return value for the set-scheme operation */
    int ret_set_userinfo;                                                       /**< Expected return value for the set-userinfo operation */
    int ret_set_host;                                                           /**< Expected return value for the set-host operation */
    int ret_set_port;                                                           /**< Expected return value for the set-port operation */
    int ret_set_path;                                                           /**< Expected return value for the set-path operation */
    int ret_set_query;                                                          /**< Expected return value for the set-query operation */
    int ret_set_fragment;                                                       /**< Expected return value for the set-fragment operation */
    int ret_generate;                                                           /**< Expected return value for the generate operation */
    size_t buf_len;                                                             /**< Buffer length */
}
test_uri_data_t;

test_uri_data_t test1_data =
{
    .desc             = "test1 : parse complete URI",
    .uri              = "http://user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test2_data =
{
    .desc             = "test2 : parse URI with no userinfo",
    .uri              = "http://www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = NULL,
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test3_data =
{
    .desc             = "test3 : parse URI with no port",
    .uri              = "http://user@www.web.com/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = NULL,
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test4_data =
{
    .desc             = "test4 : parse URI with no path",
    .uri              = "http://user@www.web.com:8080?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = NULL,
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test5_data =
{
    .desc             = "test5 : parse URI with no query",
    .uri              = "http://user@www.web.com:8080/path#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = NULL,
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test6_data =
{
    .desc             = "test6 : parse URI with no fragment",
    .uri              = "http://user@www.web.com:8080/path?name=value",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test7_data =
{
    .desc             = "test7 : parse URI with no userinfo and no host",
    .uri              = "http://:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test8_data =
{
    .desc             = "test8 : parse URI with no query and no fragment",
    .uri              = "http://user@www.web.com:8080/path",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test9_data =
{
    .desc             = "test9 : parse complete URI with percent encoding",
    .uri              = "my%20scheme://the%20user@www.my%20web.com:%38%30%38%30/my%20path?name%20=%20value#my%20fragment",
    .exp_scheme       = "my scheme",
    .exp_userinfo     = "the user",
    .exp_host         = "www.my web.com",
    .exp_port         = "8080",
    .exp_path         = "/my path",
    .exp_query        = "name = value",
    .exp_fragment     = "my fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test10_data =
{
    .desc             = "test10: parse example URI from RFC3986",
    .uri              = "mailto:fred@example.com",
    .exp_scheme       = "mailto",
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = "fred@example.com",
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test11_data =
{
    .desc             = "test11: parse example URI from RFC3986",
    .uri              = "foo://info.example.com?fred",
    .exp_scheme       = "foo",
    .exp_userinfo     = NULL,
    .exp_host         = "info.example.com",
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = "fred",
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test12_data =
{
    .desc             = "test12: parse network path reference URI",
    .uri              = "//user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test13_data =
{
    .desc             = "test13: parse absolute path reference URI",
    .uri              = "/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test14_data =
{
    .desc             = "test14: parse empty string",
    .uri              = "",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test15_data =
{
    .desc             = "test15: parse null pointer",
    .uri              = NULL,
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EINVAL,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test16_data =
{
    .desc             = "test16: parse URI with invalid percent encoding in the scheme field",
    .uri              = "ht%2tp://user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test17_data =
{
    .desc             = "test17: parse URI with invalid percent encoding in the userinfo field",
    .uri              = "http://%7ser@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test18_data =
{
    .desc             = "test18: parse URI with invalid percent encoding in the host field",
    .uri              = "http://user@w%3ww.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test19_data =
{
    .desc             = "test19: parse URI with invalid percent encoding in the port field",
    .uri              = "http://user@www.web.com:8080%9/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test20_data =
{
    .desc             = "test20: parse URI with invalid percent encoding in the path field",
    .uri              = "http://user@www.web.com:8080/path%4?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test21_data =
{
    .desc             = "test20: parse URI with invalid percent encoding in the query field",
    .uri              = "http://user@www.web.com:8080/path?name%3=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test22_data =
{
    .desc             = "test17: parse URI with invalid percent encoding in the fragment field",
    .uri              = "http://user@www.web.com:8080/path?name=value#my-fragmen%7",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = -EBADMSG,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256,
};

test_uri_data_t test23_data =
{
    .desc             = "test23 : set and generate complete URI",
    .uri              = "http://user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 56,
    .buf_len          = 256,
};

test_uri_data_t test24_data =
{
    .desc             = "test24: set and generate with no userinfo",
    .uri              = "http://www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = NULL,
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = NULL,
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = -EINVAL,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256
};

test_uri_data_t test25_data =
{
    .desc             = "test25: set and generate with no port",
    .uri              = "http://user@www.web.com/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = NULL,
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = NULL,
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = -EINVAL,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256
};

test_uri_data_t test26_data =
{
    .desc             = "test26: set and generate with no path",
    .uri              = "http://user@www.web.com:8080?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = NULL,
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = NULL,
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = -EINVAL,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256
};

test_uri_data_t test27_data =
{
    .desc             = "test27: set and generate with no query",
    .uri              = "http://user@www.web.com:8080/path#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = NULL,
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = NULL,
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = -EINVAL,
    .ret_set_fragment = 0,
    .ret_generate     = 45,
    .buf_len          = 256
};

test_uri_data_t test28_data =
{
    .desc             = "test28: set and generate with no fragment",
    .uri              = "http://user@www.web.com:8080/path?name=value",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = NULL,
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = -EINVAL,
    .ret_generate     = 44,
    .buf_len          = 256
};

test_uri_data_t test29_data =
{
    .desc             = "test29: set and generate with no userinfo and no host",
    .uri              = "http://:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = -EINVAL,
    .ret_set_host     = -EINVAL,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 40,
    .buf_len          = 256
};

test_uri_data_t test30_data =
{
    .desc             = "test30: set and generate with no query and no fragment",
    .uri              = "http://user@www.web.com:8080/path",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = -EINVAL,
    .ret_set_fragment = -EINVAL,
    .ret_generate     = 33,
    .buf_len          = 256
};

test_uri_data_t test31_data =
{
    .desc             = "test31: set and generate complete URI with percent encoding",
    .uri              = "my%20scheme://the%20user@www.my%20web.com:8080/my%20path?name%20=%20value#my%20fragment",
    .exp_scheme       = "my scheme",
    .exp_userinfo     = "the user",
    .exp_host         = "www.my web.com",
    .exp_port         = "8080",
    .exp_path         = "/my path",
    .exp_query        = "name = value",
    .exp_fragment     = "my fragment",
    .set_scheme       = "my%20scheme",
    .set_userinfo     = "the%20user",
    .set_host         = "www.my%20web.com",
    .set_port         = "%38%30%38%30",
    .set_path         = "/my%20path",
    .set_query        = "name%20=%20value",
    .set_fragment     = "my%20fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 87,
    .buf_len          = 256
};

test_uri_data_t test32_data =
{
    .desc             = "test32: set and generate example URI from RFC3986",
    .uri              = "mailto:/fred@example.com",
    .exp_scheme       = "mailto",
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = "/fred@example.com",
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = "mailto",
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = "fred@example.com",
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = -EINVAL,
    .ret_set_host     = -EINVAL,
    .ret_set_port     = -EINVAL,
    .ret_set_path     = 0,
    .ret_set_query    = -EINVAL,
    .ret_set_fragment = -EINVAL,
    .ret_generate     = 24,
    .buf_len          = 256
};

test_uri_data_t test33_data =
{
    .desc             = "test33: set and generate example URI from RFC3986",
    .uri              = "foo://info.example.com?fred",
    .exp_scheme       = "foo",
    .exp_userinfo     = NULL,
    .exp_host         = "info.example.com",
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = "fred",
    .exp_fragment     = NULL,
    .set_scheme       = "foo",
    .set_userinfo     = NULL,
    .set_host         = "info.example.com",
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = "fred",
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = -EINVAL,
    .ret_set_host     = 0,
    .ret_set_port     = -EINVAL,
    .ret_set_path     = -EINVAL,
    .ret_set_query    = 0,
    .ret_set_fragment = -EINVAL,
    .ret_generate     = 27,
    .buf_len          = 256
};

test_uri_data_t test34_data =
{
    .desc             = "test34: set and generate network path reference URI",
    .uri              = "//user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = -EINVAL,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256
};

test_uri_data_t test35_data =
{
    .desc             = "test35: set and generate absolute path reference URI",
    .uri              = "/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = -EINVAL,
    .ret_set_userinfo = -EINVAL,
    .ret_set_host     = -EINVAL,
    .ret_set_port     = -EINVAL,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 28,
    .buf_len          = 256
};

test_uri_data_t test36_data =
{
    .desc             = "test36: generate empty URI",
    .uri              = "",
    .exp_scheme       = NULL,
    .exp_userinfo     = NULL,
    .exp_host         = NULL,
    .exp_port         = NULL,
    .exp_path         = NULL,
    .exp_query        = NULL,
    .exp_fragment     = NULL,
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = -EINVAL,
    .ret_set_userinfo = -EINVAL,
    .ret_set_host     = -EINVAL,
    .ret_set_port     = -EINVAL,
    .ret_set_path     = -EINVAL,
    .ret_set_query    = -EINVAL,
    .ret_set_fragment = -EINVAL,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test37_data =
{
    .desc             = "test37: set and generate URI to buffer of insufficient size",
    .uri              = "http://u",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 56,
    .buf_len          = 9
};

test_uri_data_t test38_data =
{
    .desc             = "test38: set and generate with invalid percent encoding in the scheme field",
    .uri              = "//user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = NULL,
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "ht%2tp",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = -EBADMSG,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256,
};

test_uri_data_t test39_data =
{
    .desc             = "test39: set and generate with invalid percent encoding in the userinfo field",
    .uri              = "http://www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = NULL,
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "%7ser",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = -EBADMSG,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256,
};

test_uri_data_t test40_data =
{
    .desc             = "test40: set and generate with invalid percent encoding in the host field",
    .uri              = "http://user@:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = NULL,
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "w%3ww.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = -EBADMSG,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 45,
    .buf_len          = 256,
};

test_uri_data_t test41_data =
{
    .desc             = "test41: set and generate with invalid percent encoding in the port field",
    .uri              = "http://user@www.web.com/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = NULL,
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080%9",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = -EBADMSG,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256,
};

test_uri_data_t test42_data =
{
    .desc             = "test42: set and generate with invalid percent encoding in the path field",
    .uri              = "http://user@www.web.com:8080?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = NULL,
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path%4",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = -EBADMSG,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 51,
    .buf_len          = 256,
};

test_uri_data_t test43_data =
{
    .desc             = "test43: set and generate with invalid percent encoding in the query field",
    .uri              = "http://user@www.web.com:8080/path#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = NULL,
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name%3=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = -EBADMSG,
    .ret_set_fragment = 0,
    .ret_generate     = 45,
    .buf_len          = 256,
};

test_uri_data_t test44_data =
{
    .desc             = "test44: set and generate with invalid percent encoding in the fragment field",
    .uri              = "http://user@www.web.com:8080/path?name=value",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = NULL,
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "www.web.com",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragmen%7",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = -EBADMSG,
    .ret_generate     = 44,
    .buf_len          = 256,
};

test_uri_data_t test45_data =
{
    .desc             = "test45: copy URI",
    .uri              = "http://user@www.web.com:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "www.web.com",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test46_data =
{
    .desc             = "test46: parse complete URI with IPv4 address",
    .uri              = "http://user@10.10.10.10:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "10.10.10.10",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test47_data =
{
    .desc             = "test47: parse complete URI with IPv6 address",
    .uri              = "http://user@[::1]:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "::1",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = NULL,
    .set_userinfo     = NULL,
    .set_host         = NULL,
    .set_port         = NULL,
    .set_path         = NULL,
    .set_query        = NULL,
    .set_fragment     = NULL,
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 0,
    .buf_len          = 256
};

test_uri_data_t test48_data =
{
    .desc             = "test48: set and generate complete URI with IPv4 address",
    .uri              = "http://user@10.10.10.10:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "10.10.10.10",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "10.10.10.10",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 56,
    .buf_len          = 256,
};

test_uri_data_t test49_data =
{
    .desc             = "test49: set and generate complete URI with IPv6 address",
    .uri              = "http://user@[::1]:8080/path?name=value#my-fragment",
    .exp_scheme       = "http",
    .exp_userinfo     = "user",
    .exp_host         = "::1",
    .exp_port         = "8080",
    .exp_path         = "/path",
    .exp_query        = "name=value",
    .exp_fragment     = "my-fragment",
    .set_scheme       = "http",
    .set_userinfo     = "user",
    .set_host         = "::1",
    .set_port         = "8080",
    .set_path         = "/path",
    .set_query        = "name=value",
    .set_fragment     = "my-fragment",
    .ret_parse        = 0,
    .ret_copy         = 0,
    .ret_set_scheme   = 0,
    .ret_set_userinfo = 0,
    .ret_set_host     = 0,
    .ret_set_port     = 0,
    .ret_set_path     = 0,
    .ret_set_query    = 0,
    .ret_set_fragment = 0,
    .ret_generate     = 50,
    .buf_len          = 256,
};

/**
 *  @brief Check a field in a URI structure
 *
 *  @param[out] result Pointer to a result object
 *  @param[in] field Pointer to the field value
 *  @param[in] exp Pointer to the expected field value
 */
static void test_field(test_result_t *result, const char *field, const char *exp)
{
    if (exp != NULL)
    {
        if ((field == NULL) || (strcmp(field, exp) != 0))
        {
            *result = FAIL;
        }
    }
    else  /* (exp == NULL) */
    {
        if (field != NULL)
        {
            *result = FAIL;
        }
    }
}

/**
 *  @brief Test the fields in a URI structure
 *
 *  @param[out] result Pointer to a result object
 *  @param[in] uri Pointer to a URI structure
 *  @param[in] test_data Pointer to a URI test data structure
 */
static void test_uri_struct(test_result_t *result, const uri_t *uri, const test_uri_data_t *test_data)
{
    test_field(result, uri_get_scheme(uri), test_data->exp_scheme);
    test_field(result, uri_get_userinfo(uri), test_data->exp_userinfo);
    test_field(result, uri_get_host(uri), test_data->exp_host);
    test_field(result, uri_get_port(uri), test_data->exp_port);
    test_field(result, uri_get_path(uri), test_data->exp_path);
    test_field(result, uri_get_query(uri), test_data->exp_query);
    test_field(result, uri_get_fragment(uri), test_data->exp_fragment);
}

/**
 *  @brief Assign values to the fields in a URI structure and check the return values of the set operations
 *
 *  @param[out] result Pointer to a result object
 *  @param[in] uri Pointer to a URI structure
 *  @param[in] test_data Pointer to a URI test data structure
 */
static void test_set_uri_struct(test_result_t *result, uri_t *uri, const test_uri_data_t *test_data)
{
    int ret = 0;

    ret = uri_set_scheme(uri, test_data->set_scheme);
    if (ret != test_data->ret_set_scheme)
        *result = FAIL;
    ret = uri_set_userinfo(uri, test_data->set_userinfo);
    if (ret != test_data->ret_set_userinfo)
        *result = FAIL;
    ret = uri_set_host(uri, test_data->set_host);
    if (ret != test_data->ret_set_host)
        *result = FAIL;
    ret = uri_set_port(uri, test_data->set_port);
    if (ret != test_data->ret_set_port)
        *result = FAIL;
    ret = uri_set_path(uri, test_data->set_path);
    if (ret != test_data->ret_set_path)
        *result = FAIL;
    ret = uri_set_query(uri, test_data->set_query);
    if (ret != test_data->ret_set_query)
        *result = FAIL;
    ret = uri_set_fragment(uri, test_data->set_fragment);
    if (ret != test_data->ret_set_fragment)
        *result = FAIL;
}

/**
 *  @brief Parse a URI and check the fields in the resulting URI structure
 *
 *  @param[in] test_data Pointer to a URI test data structure
 *
 *  @returns Test result
 */
test_result_t test_parse_func(test_data_t data)
{
    test_uri_data_t *test_data = (test_uri_data_t *)data;
    test_result_t result = PASS;
    uri_t uri = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    DEBUG_PRINT("URI: '%s'\n", test_data->uri);

    uri_create(&uri);
    ret = uri_parse(&uri, test_data->uri);
    if (ret != test_data->ret_parse)
    {
        result = FAIL;
    }
    print_uri(&uri);
    test_uri_struct(&result, &uri, test_data);
    uri_destroy(&uri);
    return result;
}

/**
 *  @brief Set the fields in a URI structure and generate the URI
 *
 *  @param[in] data Pointer to a URI test data structure
 *
 *  @returns Test result
 */
test_result_t test_set_gen_func(test_data_t data)
{
    test_uri_data_t *test_data = (test_uri_data_t *)data;
    test_result_t result = PASS;
    size_t num = 0;
    uri_t uri = {0};
    char buf[test_data->buf_len];

    printf("%s\n", test_data->desc);

    uri_create(&uri);

    test_set_uri_struct(&result, &uri, test_data);
    print_uri(&uri);
    test_uri_struct(&result, &uri, test_data);

    num = uri_generate(&uri, buf, sizeof(buf));
    if (num != test_data->ret_generate)
        result = FAIL;
    if (strcmp(buf, test_data->uri) != 0)
        result = FAIL;
    DEBUG_PRINT("buf: '%s'\n", buf);

    uri_destroy(&uri);

    return result;
}

/**
 *  @brief Copy a URI structure and check the fields in the destination URI structure
 *
 *  @param[in] data Pointer to a URI test data structure
 *
 *  @returns Test result
 */
test_result_t test_copy_func(test_data_t data)
{
    test_uri_data_t *test_data = (test_uri_data_t *)data;
    test_result_t result = PASS;
    uri_t uri_dest = {0};
    uri_t uri_src = {0};
    int ret = 0;

    printf("%s\n", test_data->desc);

    DEBUG_PRINT("URI: '%s'\n", test_data->uri);

    uri_create(&uri_src);
    uri_create(&uri_dest);
    ret = uri_parse(&uri_src, test_data->uri);
    if (ret != test_data->ret_parse)
    {
        result = FAIL;
    }
    ret = uri_copy(&uri_dest, &uri_src);
    if (ret != test_data->ret_copy)
    {
        result = FAIL;
    }
    print_uri(&uri_dest);
    test_uri_struct(&result, &uri_dest, test_data);
    uri_destroy(&uri_dest);
    uri_destroy(&uri_src);
    return result;
}

/**
 *  @brief Main function for the FreeCoAP URI unit tests
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main()
{
    test_t tests[] = {{test_parse_func, &test1_data},
                      {test_parse_func, &test2_data},
                      {test_parse_func, &test3_data},
                      {test_parse_func, &test4_data},
                      {test_parse_func, &test5_data},
                      {test_parse_func, &test6_data},
                      {test_parse_func, &test7_data},
                      {test_parse_func, &test8_data},
                      {test_parse_func, &test9_data},
                      {test_parse_func, &test10_data},
                      {test_parse_func, &test11_data},
                      {test_parse_func, &test12_data},
                      {test_parse_func, &test13_data},
                      {test_parse_func, &test14_data},
                      {test_parse_func, &test15_data},
                      {test_parse_func, &test16_data},
                      {test_parse_func, &test17_data},
                      {test_parse_func, &test18_data},
                      {test_parse_func, &test19_data},
                      {test_parse_func, &test20_data},
                      {test_parse_func, &test21_data},
                      {test_parse_func, &test22_data},
                      {test_set_gen_func, &test23_data},
                      {test_set_gen_func, &test24_data},
                      {test_set_gen_func, &test25_data},
                      {test_set_gen_func, &test26_data},
                      {test_set_gen_func, &test27_data},
                      {test_set_gen_func, &test28_data},
                      {test_set_gen_func, &test29_data},
                      {test_set_gen_func, &test30_data},
                      {test_set_gen_func, &test31_data},
                      {test_set_gen_func, &test32_data},
                      {test_set_gen_func, &test33_data},
                      {test_set_gen_func, &test34_data},
                      {test_set_gen_func, &test35_data},
                      {test_set_gen_func, &test36_data},
                      {test_set_gen_func, &test37_data},
                      {test_set_gen_func, &test38_data},
                      {test_set_gen_func, &test39_data},
                      {test_set_gen_func, &test40_data},
                      {test_set_gen_func, &test41_data},
                      {test_set_gen_func, &test42_data},
                      {test_set_gen_func, &test43_data},
                      {test_set_gen_func, &test44_data},
                      {test_copy_func, &test45_data},
                      {test_parse_func, &test46_data},
                      {test_parse_func, &test47_data},
                      {test_set_gen_func, &test48_data},
                      {test_set_gen_func, &test49_data}};
    unsigned num_tests = DIM(tests);
    unsigned num_pass = 0;

    num_pass = test_run(tests, num_tests);

    return num_pass == num_tests ? EXIT_SUCCESS : EXIT_FAILURE;
}
