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
 *  @file http_msg.c
 *
 *  @brief Source file for the FreeCoAP HTTP message parser/formatter library
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "http_msg.h"
#include "util.h"

#define HTTP_MSG_NUM_ERROR_STR  4                                               /**< Number of error strings */

/**
 *  @brief Array of string representations of error codes
 */
static const char *http_msg_error_str[HTTP_MSG_NUM_ERROR_STR + 1] = {
    "ok",                                                                       /**< OK error code description */
    "incomplete",                                                               /**< Incomplete-Message error code description */
    "no memory",                                                                /**< No-Memory error code description */
    "format error",                                                             /**< Format error code description */
    "(unknown)",                                                                /**< Unknown error code description */
};

const char *http_msg_strerror(int error)
{
    switch (error)
    {
    case 0:
        return http_msg_error_str[0];
    case -EAGAIN:
        return http_msg_error_str[1];
    case -ENOMEM:
        return http_msg_error_str[2];
    case -EBADMSG:
        return http_msg_error_str[3];
    }
    return http_msg_error_str[HTTP_MSG_NUM_ERROR_STR];
}

/**
 *  @brief Allocate memory and initialise a message header
 *
 *  @parain[in] name String containing the message header name
 *  @parain[in] value String containing the message header value
 *
 *  @returns Pointer to a message header structure or NULL
 *  @retval Pointer to a message header structure, Success
 *  @retval NULL, Out-of-memory
 */
static http_msg_header_t *http_msg_header_new(const char *name, const char *value)
{
    http_msg_header_t *header = NULL;

    header = (http_msg_header_t *)malloc(sizeof(http_msg_header_t));
    if (header == NULL)
    {
        return NULL;
    }
    header->name = strdup(name);
    if (header->name == NULL)
    {
        free(header);
        return NULL;
    }
    header->value = strdup(value);
    if (header->value == NULL)
    {
        free(header->name);
        free(header);
        return NULL;
    }
    header->next = NULL;
    return header;
}

/**
 *  @brief Free the memory that holds a message header structure
 */
static void http_msg_header_delete(http_msg_header_t *header)
{
    free(header->name);
    free(header->value);
    free(header);
}

/**
 *  @brief Initialise a message header linked-list structure
 *
 *  @param[out] list Pointer to a message header linked-list structure
 */
static void http_msg_list_create(http_msg_list_t *list)
{
    memset(list, 0, sizeof(http_msg_list_t));
}

/**
 *  @brief Deinitialise a message header linked-list structure
 *
 *  @param[out] list Pointer to a message header linked-list structure
 */
static void http_msg_list_destroy(http_msg_list_t *list)
{
    http_msg_header_t *header = list->first;
    http_msg_header_t *prev = NULL;

    while (header != NULL)
    {
        prev = header;
        header = header->next;
        http_msg_header_delete(prev);
    }
    memset(list, 0, sizeof(http_msg_list_t));
}

/**
 *  @brief Add a message header to a message header linked-list structure
 *
 *  @param[in,out] list Pointer to a message header linked-list structure
 *  @param[in] name String containing the message header name
 *  @param[in] value String containing the message header value
 *
 *  @returns Error code
 */
static int http_msg_list_add(http_msg_list_t *list, const char *name, const char *value)
{
    http_msg_header_t *header = NULL;

    header = http_msg_header_new(name, value);
    if (header == NULL)
        return -ENOMEM;
    if (list->first == NULL)
        list->first = header;
    else
        list->last->next = header;
    list->last = header;
    return 0;
}

/**
 *  @brief Remove redundant whitespace from a message field
 *
 *  Remove leading and trailing whitespace and replace each
 *  contiguous sequence of whitespace with a single space.
 *
 *  @param[in,out] str String containing the message field
 *
 *  @returns String containing the trimmed message field
 */
static char *http_msg_trim_ws(char *str)
{
    char *s = NULL;
    char *d = NULL;
    int sp = 0;

    while (isspace(*str))
    {
        *str++ = '\0';
    }
    s = str;
    d = str;
    while (*s != '\0')
    {
        if (isspace(*s))
        {
            sp = 1;
            s++;
        }
        else if (sp)
        {
            *d++ = ' ';
            sp = 0;
        }
        else
        {
            *d++ = *s++;
        }
    }
    while (d < s)
    {
        *d++ = '\0';
    }
    return str;
}

void http_msg_create(http_msg_t *msg)
{
    memset(msg, 0, sizeof(http_msg_t));
    http_msg_list_create(&msg->header);
}

void http_msg_destroy(http_msg_t *msg)
{
    int i = 0;

    if (msg->body != NULL)
    {
        free(msg->body);
    }
    http_msg_list_destroy(&msg->header);
    for (i = 0; i < HTTP_MSG_NUM_START; i++)
    {
        if (msg->start[i] != NULL)
        {
            free(msg->start[i]);
        }
    }
    memset(msg, 0, sizeof(http_msg_t));
}

void http_msg_reset(http_msg_t *msg)
{
    http_msg_destroy(msg);
    http_msg_create(msg);
}

/**
 *  @brief Parse the start line in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in,out] str String containing the message
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error code
 */
static ssize_t http_msg_parse_start(http_msg_t *msg, char *str)
{
    size_t len = 0;
    char *start = NULL;
    char *next = str;
    char *end = NULL;
    int i = 0;

    end = strstr(str, "\r\n");
    if (end == NULL)
    {
        return -EAGAIN;
    }
    *end++ = '\0';
    *end++ = '\0';

    for (i = 0; i < HTTP_MSG_NUM_START; i++)
    {
        start = next;
        if (i < HTTP_MSG_NUM_START - 1)
        {
            next = strchr(start, ' ');
            if (next == NULL)
            {
                return -EBADMSG;
            }
            *next++ = '\0';
        }
        len = strlen(start);
        if (len == 0)
        {
            return -EBADMSG;
        }
        msg->start[i] = malloc(len + 1);
        if (msg->start[i] == NULL)
        {
            return -ENOMEM;
        }
        strncpy(msg->start[i], start, len);
        msg->start[i][len] = '\0';
    }
    return end - str;
}

/**
 *  @brief Parse the headers in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in,out] str String representation of the message
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error code
 */
static ssize_t http_msg_parse_headers(http_msg_t *msg, char *str)
{
    char *value = NULL;
    char *name = NULL;
    char *next = str;
    int ret = 0;

    while (1)
    {
        name = next;
        while (1)
        {
            next = strstr(next, "\r\n");
            if (next == NULL)
            {
                return -EAGAIN;
            }
            else if (next == name)
            {
                /* blank line */
                return (next + 2) - str;
            }
            else if ((*(next + 2) == ' ') || (*(next + 2) == '\t'))
            {
                next += 3;
            }
            else
            {
                *next++ = '\0';
                *next++ = '\0';
                break;
            }
        }
        value = strchr(name, ':');
        if (value == NULL)
        {
            return -EBADMSG;
        }
        *value++ = '\0';
        ret = http_msg_list_add(&msg->header, http_msg_trim_ws(name), http_msg_trim_ws(value));
        if (ret < 0)
        {
            return ret;
        }
    }
    return 0;  /* should never arrive here */
}

/**
 *  @brief Parse the body in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] str String representation of the message body
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >=0 Number of bytes parsed
 *  @retval <0 Error code
 */
static ssize_t http_msg_parse_body(http_msg_t *msg, char *str)
{
    http_msg_header_t *header = NULL;
    ssize_t num = 0;
    size_t content_len = 0;
    size_t str_len = 0;
    char *chunk_size = NULL;
    char *chunk_data = NULL;
    char *param = NULL;
    char *next = NULL;
    char *dest = NULL;
    int total_len = 0;
    int chunk_len = 0;
    int chunked = 0;
    int ret = 0;
    int i = 0;

    str_len = strlen(str);

    header = http_msg_get_first_header(msg);
    while (header != NULL)
    {
        if ((strcasecmp(header->name, "Transfer-Encoding") == 0)
         && (strcasecmp(header->value, "chunked") == 0))
        {
            chunked = 1;
        }
        if (strcasecmp(header->name, "Content-Length") == 0)
        {
            content_len = atoi(header->value);
        }
        header = header->next;
    }
    if (chunked)
    {
        /* 1: "06\r\nchunk1\r\n06\r\nchunk2\r\n0\r\n\r\n"                */
        /* 2: "06\r\nchunk1\r\n06\r\nchunk2\r\n0\r\nname: value\r\n\r\n" */
        /* 3: "06\r\nchunk1\r\n06; param=value\r\nchunk2\r\n0\r\n\r\n"   */

        /* make 2 passes */
        /* the first pass determines the total size of all chunks */
        /* the second pass copies data */
        for (i = 0; i < 2; i++)
        {
            next = str;
            while (1)
            {
                chunk_size = next;

                /* find the end of the chunk-size field */
                next = strstr(next, "\r\n");
                if (next == NULL)
                {
                    return -EAGAIN;
                }
                next += 2;

                /* ignore unrecognised parameters in the chunk-size field */
                param = strchr(chunk_size, ';');
                if ((param != NULL) && (param < next))
                {
                    *param = ' ';
                }

                /* parse chunk length */
                ret = sscanf(chunk_size, "%x", &chunk_len);
                if (ret != 1)
                {
                    return -EBADMSG;
                }
                if (chunk_len == 0)
                {
                    break;
                }
                if (i == 0)
                {
                    total_len += chunk_len;
                }

                chunk_data = next;
                next += chunk_len;

                /* parse the end of chunk-data */
                if (next + 2 > str + str_len)
                {
                    return -EAGAIN;
                }
                if ((*next != '\r')
                 || (*(next + 1) != '\n'))
                {
                    return -EBADMSG;
                }
                next += 2;

                /* copy data on the second pass */
                if (i == 1)
                {
                    memcpy(dest, chunk_data, chunk_len);
                    dest += chunk_len;
                }
            }

            /* allocate memory after the first pass */
            if (i == 0)
            {
                msg->body = malloc(total_len + 1);
                if (msg->body == NULL)
                {
                    return -ENOMEM;
                }
                msg->body[total_len] = '\0';
                msg->body_len = total_len;
                dest = msg->body;
            }
        }

        /* 1: "\r\n"                */
        /* 2: "name: value\r\n\r\n" */
        /* 3: "\r\n"                */

        /* process trailers */
        num = http_msg_parse_headers(msg, next);
        if (num < 0)
        {
            return num;
        }
        return (next + num) - str;
    }
    else if (content_len)
    {
        if (content_len > str_len)
        {
            return -EAGAIN;
        }
        msg->body = malloc(content_len + 1);
        if (msg->body == NULL)
        {
            return -ENOMEM;
        }
        memcpy(msg->body, str, content_len);
        msg->body[content_len] = '\0';
        msg->body_len = content_len;
        return content_len;
    }
    return 0;
}

/**
 *  @brief Parse a message
 *
 *  This function expects the message body to be contained
 *  in a mutable string with a terminating null character.
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in,out] str String containing the message
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes
 *  @retval <0 Error code
 */static ssize_t __http_msg_parse(http_msg_t *msg, char *str)
{
    ssize_t num = 0;
    char *next = str;

    num = http_msg_parse_start(msg, next);
    if (num < 0)
    {
        return num;
    }
    next += num;

    num = http_msg_parse_headers(msg, next);
    if (num < 0 )
    {
        return num;
    }
    next += num;

    num = http_msg_parse_body(msg, next);
    if (num < 0)
    {
        return num;
    }
    next += num;

    return next - str;
}

ssize_t http_msg_parse(http_msg_t *msg, const char *buf, size_t len)
{
    ssize_t num = 0;
    char *str = NULL;

    http_msg_reset(msg);
    str = malloc(len + 1);
    if (str == NULL)
    {
        return -ENOMEM;
    }
    memcpy(str, buf, len);
    str[len] = '\0';
    num = __http_msg_parse(msg, str);
    free(str);
    return num;
}

int http_msg_set_start(http_msg_t *msg, const char *start1, const char *start2, const char *start3)
{
    msg->start[0] = strdup(start1);
    if (msg->start[0] == NULL)
    {
        return -ENOMEM;
    }
    msg->start[1] = strdup(start2);
    if (msg->start[1] == NULL)
    {
        return -ENOMEM;
    }
    msg->start[2] = strdup(start3);
    if (msg->start[2] == NULL)
    {
        return -ENOMEM;
    }
    return 0;
}

int http_msg_set_header(http_msg_t *msg, const char *name, const char *value)
{
    return http_msg_list_add(&msg->header, name, value);
}

int http_msg_set_body(http_msg_t *msg, const char *buf, size_t len)
{
    msg->body = calloc(len + 1, 1);  /* allocate space for a terminating null character */
    if (msg->body == NULL)           /* even if the body carries binary data */
    {
        return -ENOMEM;
    }
    memcpy(msg->body, buf, len);
    msg->body_len = len;
    return 0;
}

size_t http_msg_generate(http_msg_t *msg, char *buf, size_t len)
{
    http_msg_header_t *header = NULL;
    size_t str_len = 0;

    memset(buf, 0, len);
    str_len = util_strncat(buf, msg->start[0], str_len, len);
    str_len = util_strncat(buf, " ", str_len, len);
    str_len = util_strncat(buf, msg->start[1], str_len, len);
    str_len = util_strncat(buf, " ", str_len, len);
    str_len = util_strncat(buf, msg->start[2], str_len, len);
    str_len = util_strncat(buf, "\r\n", str_len, len);

    header = msg->header.first;
    while (header != NULL)
    {
        str_len = util_strncat(buf, header->name, str_len, len);
        str_len = util_strncat(buf, ": ", str_len, len);
        str_len = util_strncat(buf, header->value, str_len, len);
        str_len = util_strncat(buf, "\r\n", str_len, len);
        header = header->next;
    }
    str_len = util_strncat(buf, "\r\n", str_len, len);

    /* special handling for (binary) message body which could */
    /* contain null byte that would fool util_strncat */
    if (msg->body != NULL)
    {
        if (str_len + msg->body_len < len)
        {
            memcpy(buf + str_len, msg->body, msg->body_len);  /* full copy */
        }
        else if (str_len < (len - 1))  /* if there is space for one byte not including the '\0' */
        {
            memcpy(buf + str_len, msg->body, (len - 1) - str_len);  /* partial copy */
        }
        str_len += msg->body_len;
    }
    return str_len;
}

size_t http_msg_generate_chunk(char *out, size_t out_len, const char *in, size_t in_len)
{
    size_t target = 0;
    size_t actual = 0;
    size_t num = 0;

    memset(out, 0, out_len);

    target = snprintf(out, out_len, "%zx\r\n", in_len);
    actual = (target <= out_len) ? target : out_len;
    out += actual;
    out_len -= actual;
    num += target;

    target = in_len;
    actual = (target <= (out_len - 1)) ? target : (out_len - 1);
    memcpy(out, in, actual);
    out += actual;
    out_len -= actual;
    num += target;

    target = snprintf(out, out_len, "\r\n");
    actual = (target <= out_len) ? target : out_len;
    out += actual;
    out_len -= actual;
    num += target;

    return num;
}

size_t http_msg_generate_last_chunk(char *buf, size_t len)
{
    return snprintf(buf, len, "0\r\n");
}

size_t http_msg_generate_trailer(char *buf, size_t len, const char *name, const char *value)
{
    return snprintf(buf, len, "%s: %s\r\n", name, value);
}

size_t http_msg_generate_blank_line(char *buf, size_t len)
{
    return snprintf(buf, len, "\r\n");
}
