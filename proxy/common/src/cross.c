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
 *  @file cross.c
 *
 *  @brief Source file for the FreeCoAP HTTP/COAP message/URI cross library
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "cross.h"
#include "uri.h"

#define CROSS_NUM_HTTP_RESP  5                                                  /**< Number of HTTP response codes */
#define CROSS_COAP_SCHEME    "coaps"                                            /**< CoAP scheme */
#define CROSS_TMP_BUF_LEN    256                                                /**< Length of temporary buffer */

/**
 *  @brief Array of HTTP response strings
 */
static const char *cross_http_resp_str[CROSS_NUM_HTTP_RESP + 1] =
{
    "Bad Request",                                                              /**< 400 Bad Request HTTP response description */
    "Not Acceptable",                                                           /**< 406 Not Acceptable HTTP response description  */
    "Internal Server Error",                                                    /**< 500 Internal Server Error HTTP response description */
    "Not Implemented",                                                          /**< 501 Not Implemented HTTP response description */
    "Bad Gateway",                                                              /**< 502 Bad Gateway HTTP response description */
    "(Unknown)"                                                                 /**< Unknown HTTP response description */
};

const char *cross_http_resp_code_to_str(unsigned code)
{
    switch (code)
    {
    case 400:
        return cross_http_resp_str[0];
    case 406:
        return cross_http_resp_str[1];
    case 500:
        return cross_http_resp_str[2];
    case 501:
        return cross_http_resp_str[3];
    case 502:
        return cross_http_resp_str[4];
    }
    return cross_http_resp_str[CROSS_NUM_HTTP_RESP];
}

/**
 *  @brief Convert a HTTP request method to a CoAP request method
 *
 *  @param[out] coap_msg Pointer to a CoAP message structure
 *  @param[in] http_msg Pointer to a HTTP message structure
 *  @param[out] code HTTP response code
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int cross_method_http_to_coap(coap_msg_t *coap_msg, http_msg_t *http_msg, unsigned *code)
{
    const char *str = NULL;

    str = http_msg_get_start(http_msg, 0);
    if (str == NULL)
    {
        *code = 400;
        return -EBADMSG;
    }
    if (strcmp(str, "GET") == 0)
    {
        coap_msg_set_code(coap_msg, COAP_MSG_REQ, COAP_MSG_GET);
    }
    else if (strcmp(str, "POST") == 0)
    {
        coap_msg_set_code(coap_msg, COAP_MSG_REQ, COAP_MSG_POST);
    }
    else if (strcmp(str, "PUT") == 0)
    {
        coap_msg_set_code(coap_msg, COAP_MSG_REQ, COAP_MSG_PUT);
    }
    else if (strcmp(str, "DELETE") == 0)
    {
        coap_msg_set_code(coap_msg, COAP_MSG_REQ, COAP_MSG_DELETE);
    }
    else
    {
        *code = 501;
        return -EBADMSG;
    }
    return 0;
}

/**
 *  @brief Convert a CoAP response status to a HTTP response status
 *
 *  @param[out] coap_msg Pointer to a CoAP message structure
 *  @param[in] http_msg Pointer to a HTTP message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int cross_status_coap_to_http(http_msg_t *http_msg, coap_msg_t *coap_msg)
{
    switch (coap_msg_get_code_class(coap_msg))
    {
    case COAP_MSG_SUCCESS:
        switch (coap_msg_get_code_detail(coap_msg))
        {
        case COAP_MSG_CREATED:
            return http_msg_set_start(http_msg, "HTTP/1.1", "200", "OK");
        case COAP_MSG_DELETED:
            return http_msg_set_start(http_msg, "HTTP/1.1", "200", "OK");
        case COAP_MSG_VALID:
            return http_msg_set_start(http_msg, "HTTP/1.1", "304", "Not Modified");
        case COAP_MSG_CHANGED:
            return http_msg_set_start(http_msg, "HTTP/1.1", "200", "OK");
        case COAP_MSG_CONTENT:
            return http_msg_set_start(http_msg, "HTTP/1.1", "200", "OK");
        }
    case COAP_MSG_CLIENT_ERR:
        switch (coap_msg_get_code_detail(coap_msg))
        {
        case COAP_MSG_BAD_REQ:
            return http_msg_set_start(http_msg, "HTTP/1.1", "400", "Bad Request");
        case COAP_MSG_UNAUTHORIZED:
            return http_msg_set_start(http_msg, "HTTP/1.1", "401", "Unauthorized");
        case COAP_MSG_BAD_OPTION:
            /* closest match */
            return http_msg_set_start(http_msg, "HTTP/1.1", "400", "Bad Request");
        case COAP_MSG_FORBIDDEN:
            return http_msg_set_start(http_msg, "HTTP/1.1", "403", "Forbidden");
        case COAP_MSG_NOT_FOUND:
            return http_msg_set_start(http_msg, "HTTP/1.1", "404", "Not Found");
        case COAP_MSG_METHOD_NOT_ALLOWED:
            return http_msg_set_start(http_msg, "HTTP/1.1", "405", "Method Not Allowed");
        case COAP_MSG_NOT_ACCEPTABLE:
            return http_msg_set_start(http_msg, "HTTP/1.1", "406", "Not Acceptable");
        case COAP_MSG_PRECOND_FAILED:
            return http_msg_set_start(http_msg, "HTTP/1.1", "412", "Precondition Failed");
        case COAP_MSG_REQ_ENT_TOO_LARGE:
            return http_msg_set_start(http_msg, "HTTP/1.1", "413", "Request Entity Too Large");
        case COAP_MSG_UNSUP_CONT_FMT:
            return http_msg_set_start(http_msg, "HTTP/1.1", "415", "Unsupported Media Type");
        }
    case COAP_MSG_SERVER_ERR:
        switch (coap_msg_get_code_detail(coap_msg))
        {
        case COAP_MSG_INT_SERVER_ERR:
            return http_msg_set_start(http_msg, "HTTP/1.1", "500", "Internal Server Error");
        case COAP_MSG_NOT_IMPL:
            return http_msg_set_start(http_msg, "HTTP/1.1", "501", "Not Implemented");
        case COAP_MSG_BAD_GATEWAY:
            return http_msg_set_start(http_msg, "HTTP/1.1", "502", "Bad Gateway");
        case COAP_MSG_SERV_UNAVAIL:
            return http_msg_set_start(http_msg, "HTTP/1.1", "503", "Service Unavailable");
        case COAP_MSG_GATEWAY_TIMEOUT:
            return http_msg_set_start(http_msg, "HTTP/1.1", "504", "Gateway Timeout");
        case COAP_MSG_PROXY_NOT_SUP:
            /* closest match */
            /* could use 502 Bad Gateway */
            return http_msg_set_start(http_msg, "HTTP/1.1", "501", "Not Implemented");
        }
    }
    return -EBADMSG;
}

int cross_uri_http_to_coap(coap_msg_t *coap_msg, const char *http_uri)
{
    const char *str = NULL;
    const char *end = NULL;
    unsigned len = 0;
    uri_t uri = {0};
    int ret = 0;

    uri_create(&uri);
    ret = uri_parse(&uri, http_uri);
    if (ret < 0)
    {
        uri_destroy(&uri);
        return ret;
    }

    /* fragment */
    str = uri_get_fragment(&uri);
    if (str != NULL)
    {
        uri_destroy(&uri);
        return -EBADMSG;
    }

    /* scheme */
    str = uri_get_scheme(&uri);
    if (str == NULL)
    {
        uri_destroy(&uri);
        return -EBADMSG;
    }
    if ((strcasecmp(str, "coap") != 0)
     && (strcasecmp(str, "coaps") != 0))
    {
        uri_destroy(&uri);
        return -EBADMSG;
    }

    /* host */
    str = uri_get_host(&uri);
    if (str != NULL)
    {
        /* to do: check if the host is a literal IP address */
        /* to do: convert the host name to ASCII lowercase */
        len = strlen(str);
        ret = coap_msg_add_op(coap_msg, COAP_MSG_URI_HOST, len, str);
        if (ret < 0)
        {
            uri_destroy(&uri);
            return ret;
        }
    }

    /* port */
    str = uri_get_port(&uri);
    if (str != NULL)
    {
        len = strlen(str);
        ret = coap_msg_add_op(coap_msg, COAP_MSG_URI_PORT, len, str);
        if (ret < 0)
        {
            uri_destroy(&uri);
            return ret;
        }
    }

    /* path */
    str = uri_get_path(&uri);
    if (str != NULL)
    {
        /*  /          */
        /*  /abc       */
        /*  /abc/      */
        /*  /abc/def   */
        /*  /abc/def/  */
        /*  /abc//def  */
        if (*str != '/')
        {
            uri_destroy(&uri);
            return -EBADMSG;
        }
        str++;
        while (1)
        {
            end = strchr(str, '/');
            if (end == NULL)
            {
                len = strlen(str);
                if (len > 0)
                {
                    ret = coap_msg_add_op(coap_msg, COAP_MSG_URI_PATH, len, str);
                    if (ret < 0)
                    {
                        uri_destroy(&uri);
                        return ret;
                    }
                }
                break;
            }
            else
            {
                len = end - str;
                if (len > 0)
                {
                    ret = coap_msg_add_op(coap_msg, COAP_MSG_URI_PATH, len, str);
                    if (ret < 0)
                    {
                        uri_destroy(&uri);
                        return ret;
                    }
                }
                end++;
                str = end;
            }
        }
    }

    /* query */
    str = uri_get_query(&uri);
    if (str != NULL)
    {
        /*  abc       */
        /*  abc&      */
        /*  abc&def   */
        /*  abc&def&  */
        /*  abc&&def  */
        while (1)
        {
            end = strchr(str, '&');
            if (end == NULL)
            {
                len = strlen(str);
                if (len > 0)
                {
                    ret = coap_msg_add_op(coap_msg, COAP_MSG_URI_QUERY, len, str);
                    if (ret < 0)
                    {
                        uri_destroy(&uri);
                        return ret;
                    }
                }
                break;
            }
            else
            {
                len = end - str;
                if (len > 0)
                {
                    ret = coap_msg_add_op(coap_msg, COAP_MSG_URI_QUERY, len, str);
                    if (ret < 0)
                    {
                        uri_destroy(&uri);
                        return ret;
                    }
                }
                end++;
                str = end;
            }
        }
    }

    uri_destroy(&uri);
    return 0;
}

int cross_uri_coap_to_http(char *buf, size_t len, coap_msg_t *coap_msg)
{
    coap_msg_op_t *op = NULL;
    size_t num = 0;
    uri_t uri = {0};
    char tmp[CROSS_TMP_BUF_LEN] = {0};
    int ret = 0;

    uri_create(&uri);

    /* todo: figure out which scheme to use */
    ret = uri_set_scheme(&uri, CROSS_COAP_SCHEME);
    if (ret < 0)
    {
        uri_destroy(&uri);
        return ret;
    }

    /* host */
    op = coap_msg_get_first_op(coap_msg);
    while (op != NULL)
    {
        if (coap_msg_op_get_num(op) == COAP_MSG_URI_HOST)
        {
            if (coap_msg_op_get_len(op) >= sizeof(tmp))
            {
                uri_destroy(&uri);
                return -ENOSPC;
            }
            memcpy(tmp, coap_msg_op_get_val(op), coap_msg_op_get_len(op));
            tmp[coap_msg_op_get_len(op)] = '\0';
            ret = uri_set_host(&uri, tmp);
            if (ret < 0)
            {
                uri_destroy(&uri);
                return ret;
            }
            break;
        }
        op = coap_msg_op_get_next(op);
    }

    /* port */
    op = coap_msg_get_first_op(coap_msg);
    while (op != NULL)
    {
        if (coap_msg_op_get_num(op) == COAP_MSG_URI_PORT)
        {
            if (coap_msg_op_get_len(op) > sizeof(tmp) - 1)  /* -1 for the terminating '\0' */
            {
                uri_destroy(&uri);
                return -ENOSPC;
            }
            memcpy(tmp, coap_msg_op_get_val(op), coap_msg_op_get_len(op));
            tmp[coap_msg_op_get_len(op)] = '\0';
            ret = uri_set_port(&uri, tmp);
            if (ret < 0)
            {
                uri_destroy(&uri);
                return ret;
            }
            break;
        }
        op = coap_msg_op_get_next(op);
    }

    /* path */
    num = 0;
    op = coap_msg_get_first_op(coap_msg);
    while (op != NULL)
    {
        if (coap_msg_op_get_num(op) == COAP_MSG_URI_PATH)
        {
            if (coap_msg_op_get_len(op) + 1 > sizeof(tmp) - 1 - num)  /* +1 for the leading '/' */
            {
                uri_destroy(&uri);
                return -ENOSPC;
            }
            tmp[num++] = '/';
            memcpy(tmp + num, coap_msg_op_get_val(op), coap_msg_op_get_len(op));
            num += coap_msg_op_get_len(op);
            tmp[num] = '\0';
        }
        op = coap_msg_op_get_next(op);
    }
    if (num == 0)
    {
        tmp[0] = '/';
        tmp[1] = '\0';
    }
    ret = uri_set_path(&uri, tmp);
    if (ret < 0)
    {
        uri_destroy(&uri);
        return ret;
    }

    /* query */
    num = 0;
    op = coap_msg_get_first_op(coap_msg);
    while (op != NULL)
    {
        if (coap_msg_op_get_num(op) == COAP_MSG_URI_QUERY)
        {
            if (coap_msg_op_get_len(op) + 1 > sizeof(tmp) - 1 - num)  /* +1 for the leading '&' */
            {
                uri_destroy(&uri);
                return -ENOSPC;
            }
            if (num > 0)
            {
                tmp[num++] = '&';
            }
            memcpy(tmp + num, coap_msg_op_get_val(op), coap_msg_op_get_len(op));
            num += coap_msg_op_get_len(op);
            tmp[num] = '\0';
        }
        op = coap_msg_op_get_next(op);
    }
    if (num > 0)
    {
        ret = uri_set_query(&uri, tmp);
        if (ret < 0)
        {
            uri_destroy(&uri);
            return ret;
        }
    }

    /* generate URI */
    num = uri_generate(&uri, buf, len);
    uri_destroy(&uri);
    if (num > len - 1)
    {
        return -ENOSPC;
    }
    return 0;
}

/**
 *  @brief Convert HTTP headers to CoAP options
 *
 *  @param[out] coap_msg Pointer to a CoAP message structure
 *  @param[in] http_msg Pointer to a HTTP message structure
 *  @param[out] code HTTP response code
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int cross_headers_http_to_coap(coap_msg_t *coap_msg, http_msg_t *http_msg, unsigned *code)
{
    http_msg_header_t *http_header = NULL;
    const char *str = NULL;
    unsigned val = 0;
    char tmp[CROSS_TMP_BUF_LEN] = {0};
    int ret = 0;

    /*  todo:
     *  COAP_MSG_IF_MATCH               not done
     *  COAP_MSG_URI_HOST               done
     *  COAP_MSG_ETAG                   done
     *  COAP_MSG_IF_NONE_MATCH          not done
     *  COAP_MSG_URI_PORT               done
     *  COAP_MSG_LOCATION_PATH          not done
     *  COAP_MSG_URI_PATH               done
     *  COAP_MSG_CONTENT_FORMAT         not done
     *  COAP_MSG_MAX_AGE                done
     *  COAP_MSG_URI_QUERY              done
     *  COAP_MSG_ACCEPT                 done
     *  COAP_MSG_LOCATION_QUERY         not done
     *  COAP_MSG_PROXY_URI              not done
     *  COAP_MSG_PROXY_SCHEME           not done
     *  COAP_MSG_SIZE1                  not done
     */

    http_header = http_msg_get_first_header(http_msg);
    while (http_header != NULL)
    {
        if (strcasecmp(http_msg_header_get_name(http_header), "Etag") == 0)
        {
            str = http_msg_header_get_value(http_header);
            ret = coap_msg_add_op(coap_msg, COAP_MSG_ETAG, strlen(str), str);
            if (ret < 0)
            {
                *code = 502;
                return ret;
            }
        }
        else if (strcasecmp(http_msg_header_get_name(http_header), "Cache-Control") == 0)
        {
            str = http_msg_header_get_value(http_header);
            str = strstr(str, "max-age=");
            if (str != NULL)
            {
                ret = sscanf(str, "max-age=%u", &val);
                if (ret == 1)
                {
                    ret = snprintf(tmp, sizeof(tmp), "%u", val);
                    if (ret >= sizeof(tmp))
                    {
                        *code = 502;
                        return -ENOSPC;
                    }
                    ret = coap_msg_add_op(coap_msg, COAP_MSG_MAX_AGE, strlen(tmp), tmp);
                    if (ret < 0)
                    {
                        *code = 502;
                        return ret;
                    }
                }
            }
        }
        else if (strcasecmp(http_msg_header_get_name(http_header), "Accept") == 0)
        {
            str = http_msg_header_get_value(http_header);
            if (strncasecmp(str, "text/plain", 10) == 0)
            {
                tmp[0] = '0';
                tmp[1] = '\0';
            }
            else
            {
                *code = 406;
                return -EBADMSG;
            }
            ret = coap_msg_add_op(coap_msg, COAP_MSG_ACCEPT, strlen(tmp), tmp);
            if (ret < 0)
            {
                *code = 502;
                return ret;
            }
        }
        http_header = http_msg_header_get_next(http_header);
    }
    return 0;
}

/**
 *  @brief Convert CoAP options to HTTP headers
 *
 *  @param[out] http_msg Pointer to a HTTP message structure
 *  @param[in] coap_msg Pointer to a CoAP message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int cross_headers_coap_to_http(coap_msg_t *coap_msg, http_msg_t *http_msg)
{
    coap_msg_op_t *op = NULL;
    unsigned val = 0;
    char tmp[CROSS_TMP_BUF_LEN] = {0};
    int ret = 0;

    /*  todo:
     *  COAP_MSG_IF_MATCH               not done
     *  COAP_MSG_URI_HOST               not done
     *  COAP_MSG_ETAG                   done
     *  COAP_MSG_IF_NONE_MATCH          not done
     *  COAP_MSG_URI_PORT               not done
     *  COAP_MSG_LOCATION_PATH          not done
     *  COAP_MSG_URI_PATH               not done
     *  COAP_MSG_CONTENT_FORMAT         not done
     *  COAP_MSG_MAX_AGE                done
     *  COAP_MSG_URI_QUERY              not done
     *  COAP_MSG_ACCEPT                 done
     *  COAP_MSG_LOCATION_QUERY         not done
     *  COAP_MSG_PROXY_URI              not done
     *  COAP_MSG_PROXY_SCHEME           not done
     *  COAP_MSG_SIZE1                  not done
     */

    op = coap_msg_get_first_op(coap_msg);
    while (op != NULL)
    {
        if (coap_msg_op_get_val(op) != NULL)
        {
            if (coap_msg_op_get_len(op) >= sizeof(tmp))
            {
                return -ENOSPC;
            }
            memcpy(tmp, coap_msg_op_get_val(op), coap_msg_op_get_len(op));
            tmp[coap_msg_op_get_len(op)] = '\0';

            switch (coap_msg_op_get_num(op))
            {
            case COAP_MSG_ETAG:
                ret = http_msg_set_header(http_msg, "Etag", tmp);
                if (ret < 0)
                {
                    return ret;
                }
                break;
            case COAP_MSG_MAX_AGE:
                ret = sscanf(tmp, "%u", &val);
                if (ret == 1)
                {
                    ret = snprintf(tmp, sizeof(tmp), "max-age=%u", val);
                    if (ret >= sizeof(tmp))
                    {
                        return -ENOSPC;
                    }
                    ret = http_msg_set_header(http_msg, "Cache-Control", tmp);
                    if (ret < 0)
                    {
                        return ret;
                    }
                }
                break;
            case COAP_MSG_ACCEPT:
                if ((coap_msg_op_get_len(op) == 1)
                 && (memcmp(coap_msg_op_get_val(op), "0", 1) == 0))
                {
                    ret = http_msg_set_header(http_msg, "Accept", "text/plain");
                    if (ret < 0)
                    {
                        return ret;
                    }
                }
                break;
            }
        }
        op = coap_msg_op_get_next(op);
    }
    return 0;
}

/**
 *  @brief Convert HTTP body to CoAP payload
 *
 *  @param[out] coap_msg Pointer to a CoAP message structure
 *  @param[in] http_msg Pointer to a HTTP message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int cross_body_http_to_coap(coap_msg_t *coap_msg, http_msg_t *http_msg)
{
    int ret = 0;

    if (http_msg_get_body_len(http_msg))
    {
        ret = coap_msg_set_payload(coap_msg, http_msg_get_body(http_msg), http_msg_get_body_len(http_msg));
        if (ret < 0)
        {
            return ret;
        }
    }
    return 0;
}

/**
 *  @brief Convert a CoAP body to a HTTP body
 *
 *  @param[out] http_msg Pointer to a HTTP message structure
 *  @param[in] buf Buffer to hold the body of a CoAP message
 *  @param[in] len Length of the buffer to hold the body of a CoAP message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int cross_body_coap_to_http(http_msg_t *http_msg, const char *buf, size_t len)
{
    char tmp[CROSS_TMP_BUF_LEN] = {0};
    int ret = 0;

    ret = http_msg_set_body(http_msg, buf, len);
    if (ret < 0)
    {
        return ret;
    }
    ret = snprintf(tmp, sizeof(tmp), "%zu", len);
    if (ret >= sizeof(tmp))
    {
        return -ENOSPC;
    }
    return http_msg_set_header(http_msg, "Content-Length", tmp);
}

int cross_req_http_to_coap(coap_msg_t *coap_msg, char *coap_body, size_t coap_body_len, size_t *coap_body_end, http_msg_t *http_msg, unsigned *code)
{
    int ret = 0;

    coap_msg_reset(coap_msg);
    coap_msg_set_type(coap_msg, CROSS_COAP_REQ_TYPE);

    ret = cross_method_http_to_coap(coap_msg, http_msg, code);
    if (ret < 0)
    {
        return ret;
    }

    ret = cross_uri_http_to_coap(coap_msg, http_msg_get_start(http_msg, 1));
    if (ret < 0)
    {
        *code = 400;
        return ret;
    }

    ret = cross_headers_http_to_coap(coap_msg, http_msg, code);
    if (ret < 0)
    {
        return ret;
    }

    if (http_msg_get_body_len(http_msg) > COAP_MSG_MAX_PAYLOAD_LEN)
    {
        if (http_msg_get_body_len(http_msg) > coap_body_len)
        {
            *code = 502;
            return -ENOSPC;
        }
        memcpy(coap_body, http_msg_get_body(http_msg), http_msg_get_body_len(http_msg));
        *coap_body_end = http_msg_get_body_len(http_msg);
    }
    else
    {
        ret = coap_msg_set_payload(coap_msg, http_msg_get_body(http_msg), http_msg_get_body_len(http_msg));
        if (ret < 0)
        {
            *code = 502;
            return ret;
        }
    }
    *code = 0;
    return 0;
}

int cross_resp_coap_to_http(http_msg_t *http_msg, coap_msg_t *coap_msg, const char *coap_body, size_t coap_body_len, unsigned *code)
{
    int ret = 0;

    http_msg_reset(http_msg);

    ret = cross_status_coap_to_http(http_msg, coap_msg);
    if (ret < 0)
    {
        *code = 502;
        return ret;
    }

    ret = cross_headers_coap_to_http(coap_msg, http_msg);
    if (ret < 0)
    {
        *code = 502;
        return ret;
    }

    if (coap_body_len > 0)
    {
        ret = cross_body_coap_to_http(http_msg, coap_body, coap_body_len);
        if (ret < 0)
        {
            *code = 502;
            return ret;
        }
    }
    else if (coap_msg_get_payload_len(coap_msg) > 0)
    {
        ret = cross_body_coap_to_http(http_msg,
                                      coap_msg_get_payload(coap_msg),
                                      coap_msg_get_payload_len(coap_msg));
        if (ret < 0)
        {
            *code = 502;
            return ret;
        }
    }
    *code = 0;
    return 0;
}
