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
 *  @file param.c
 *
 *  @brief Source file for the FreeCoAP HTTP/CoAP proxy parameter module
 */

#include <stdlib.h>
#include <string.h>
#include "param.h"
#include "config.h"
#include "util.h"

#define PARAM_BUF_SIZE  1024

#define param_report_start(file_name)                   {coap_log_notice("reading config file: '%s'", file_name);}
#define param_report_file_error(file_name)              {coap_log_error("unable to load config file: '%s'", file_name);}
#define param_report_mem_error()                        {coap_log_error("out of memory");}
#define param_report_parse_error(file_name, line, col)  {coap_log_error("parse error in config file: '%s', line: %d, col: %d", file_name, line, col);}
#define param_report_success(key, val)                  {coap_log_notice("config parameter: '%s'='%s'", key, val);}
#define param_report_unknown(key, val)                  {coap_log_error("config parameter: '%s' defined with unsupported value: '%s'", key, val);}
#define param_report_fail(file_name)                    {coap_log_error("failed to read config file: '%s'", file_name);}
#define param_report_end(file_name)                     {coap_log_notice("finished reading config file: '%s'", file_name);}

static int param_parse_key_val(config_t *config, const char *section, const char *key, const char *def_val, char **val)
{
    const char *str = NULL;

    str = config_get(config, section, key);
    if (str == NULL)
    {
        str = def_val;
    }
    *val = strdup(str);
    if (*val == NULL)
    {
        param_report_mem_error();
        return -1;
    }
    param_report_success(key, *val);
    return 0;
}

static int param_parse_log_level(param_t *param, config_t *config)
{
    const char *key = NULL;
    const char *val = NULL;

    key = "log_level";
    val = config_get(config, "", key);
    if (val == NULL)
    {
        val = PARAM_DEF_MAX_LOG_LEVEL;
    }
    if (strcmp(val, "error") == 0)
    {
        param->max_log_level = COAP_LOG_ERROR;
    }
    else if (strcmp(val, "warning") == 0)
    {
        param->max_log_level = COAP_LOG_WARN;
    }
    else if (strcmp(val, "notice") == 0)
    {
        param->max_log_level = COAP_LOG_NOTICE;
    }
    else if (strcmp(val, "info") == 0)
    {
        param->max_log_level = COAP_LOG_INFO;
    }
    else if (strcmp(val, "debug") == 0)
    {
        param->max_log_level = COAP_LOG_DEBUG;
    }
    else
    {
        param_report_unknown(key, val);
        return -1;
    }
    param_report_success(key, val);
    return 0;
}

static int param_parse(param_t *param, const char *file_name, config_t *config, const char *buf)
{
    unsigned line = 0;
    unsigned col = 0;
    int ret = 0;

    ret = config_parse(config, buf, &line, &col);
    if (ret != 0)
    {
        param_report_parse_error(file_name, line, col);
        return -1;
    }

    ret = param_parse_key_val(config,
                              "",
                              "port",
                              PARAM_DEF_PORT,
                              &param->port);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_log_level(param, config);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_key_val(config,
                              "http_server",
                              "key_file",
                              PARAM_DEF_HTTP_SERVER_KEY_FILE_NAME,
                              &param->http_server_key_file_name);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_key_val(config,
                              "http_server",
                              "cert_file",
                              PARAM_DEF_HTTP_SERVER_CERT_FILE_NAME,
                              &param->http_server_cert_file_name);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_key_val(config,
                              "http_server",
                              "trust_file",
                              PARAM_DEF_HTTP_SERVER_TRUST_FILE_NAME,
                              &param->http_server_trust_file_name);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_key_val(config,
                              "coap_client",
                              "key_file",
                              PARAM_DEF_COAP_CLIENT_KEY_FILE_NAME,
                              &param->coap_client_key_file_name);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_key_val(config,
                              "coap_client",
                              "cert_file",
                              PARAM_DEF_COAP_CLIENT_CERT_FILE_NAME,
                              &param->coap_client_cert_file_name);
    if (ret != 0)
    {
        return ret;
    }

    ret = param_parse_key_val(config,
                              "coap_client",
                              "trust_file",
                              PARAM_DEF_COAP_CLIENT_TRUST_FILE_NAME,
                              &param->coap_client_trust_file_name);
    if (ret != 0)
    {
        return ret;
    }

    return ret;
}

int param_create(param_t *param, const char *file_name)
{
    config_t config = {0};
    char *buf = NULL;
    long num = 0;
    int status = 0;

    param_report_start(file_name);
    memset(param, 0, sizeof(param_t));
    config_create(&config);
    num = util_load_txt_file(file_name, &buf);
    if (num == UTIL_FILE_ERROR)
    {
        param_report_file_error(file_name);
        status = -1;
    }
    else if (num == UTIL_NOMEM_ERROR)
    {
        param_report_mem_error();
        status = -1;
    }
    else
    {
        status = param_parse(param, file_name, &config, buf);
        free(buf);
    }
    config_destroy(&config);
    if (status != 0)
    {
        param_report_fail(file_name);
        param_destroy(param);
    }
    else
    {
        param_report_end(file_name);
    }
    return status;
}

void param_destroy(param_t *param)
{
    if (param->coap_client_trust_file_name != NULL)
    {
        free(param->coap_client_trust_file_name);
    }
    if (param->coap_client_cert_file_name != NULL)
    {
        free(param->coap_client_cert_file_name);
    }
    if (param->coap_client_key_file_name != NULL)
    {
        free(param->coap_client_key_file_name);
    }
    if (param->http_server_trust_file_name != NULL)
    {
        free(param->http_server_trust_file_name);
    }
    if (param->http_server_cert_file_name != NULL)
    {
        free(param->http_server_cert_file_name);
    }
    if (param->http_server_key_file_name != NULL)
    {
        free(param->http_server_key_file_name);
    }
    if (param->port != NULL)
    {
        free(param->port);
    }
    memset(param, 0, sizeof(param_t));
}
