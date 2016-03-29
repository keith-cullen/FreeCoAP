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
 *  @file uri.c
 *
 *  @brief Source file for the FreeCoAP URI library
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include "uri.h"

/*  RFC3986
 *
 *  URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 *
 *  hier-part   = "//" authority path
 *                / path
 *
 *  authority   = [ userinfo "@" ] host [ ":" port ]
 */

/*
 *  This implementation does not support suffix references (e.g. www.w3.org/Addressing/)
 */

#define NUM_LEN  2                                                              /**< Length of an octet in hexadecimal ASCII characters */

#define URI_SUB_DELIMS  "!$&'()*+,;="                                           /**< List of sub-delimiters */

/**
 *  @biref Array of hexadecimal ASCII characters
 */
static char uri_hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

/**
 *  @brief Determine if an ASCII character is unreserved
 *
 *  @param[in] c ASCII character
 *
 *  @returns Operation status
 *  @retval 1 ASCII character is unreserved
 *  @retval 0 ASCII character is reserved
 */
static inline int uri_is_unreserved(char c)
{
    return (isalpha(c) || isdigit(c) || (c == '-') || (c == '.') || (c == '_') || (c == '~'));
}

/**
 *  @brief Determine if an ASCII character is allowed
 *
 *  @param[in] c ASCII character
 *
 *  @returns Operation status
 *  @retval 1 ASCII character is allowed
 *  @retval 0 ASCII character is not allowed
 */
static inline int uri_is_allowed(char c)
{
    return uri_is_unreserved(c) || (strchr(URI_SUB_DELIMS, c) != NULL);
}

/**
 *  @brief Convert a hexadecimal ASCII character to an integer value
 *
 *  @param[in] c ASCII character
 *
 *  @returns Integer value or error code
 *  @retval >=0 Integer value
 *  @retval -1 Error
 */
static inline int uri_hex_to_int(char h)
{
    int c = toupper(h);
    if ((c >= 'A') && (c <= 'F'))
        return c - 'A' + 10;
    else if ((c >= '0') && (c <= '9'))
        return c - '0';
    return -1;
}

/**
 *  @brief Convert two hexadecimal ASCII characters to an integer value
 *
 *  @param[in] str String containing two ASCII characters
 *
 *  @returns Integer value or error code
 *  @retval >=0 Integer value
 *  @retval -1 Error
 */
static inline int uri_2_hex_to_int(const char *str)
{
    int i0 = 0;
    int i1 = 0;

    i0 = uri_hex_to_int(str[0]);
    if (i0 == -1)
    {
        return -1;
    }
    i1 = uri_hex_to_int(str[1]);
    if (i1 == -1)
    {
        return -1;
    }
    return (i0 << 4) | i1;
}

/**
 *  @brief Percent-encode an octet
 *
 *  param[out] str String to hold the result (must contain space for 3 characters, e.g. "%20")
 *  param[in] val Octet
 */
static void uri_encode_octet(char *str, char val)
{
    unsigned h1 = (val >> 4) & 0x0f;
    unsigned h0 = val & 0x0f;

    str[0] = '%';
    str[1] = uri_hex[h1];
    str[2] = uri_hex[h0];
}

/**
 *  @brief Percent-decode an octet
 *
 *  param[in,out] str Double pointer to a string
 *
 *  @returns Octet
 */
static int uri_decode_octet(const char **str)
{
    char num[NUM_LEN + 1] = {0};
    char *p = num;
    int c = 0;

    if (**str == '\0')
    {
        c = '\0';
    }
    else if (**str == '%')
    {
        (*str)++;
        while ((**str != '\0') && (p - num < NUM_LEN))
        {
            *p++ = *(*str)++;
        }
        *p = '\0';
        c = uri_2_hex_to_int(num);
    }
    else
    {
        c = *(*str)++;
    }
    return c;
}

/**
 *  @brief Append a source string to a destination string, percent-encoding characters as necessary
 *
 *  @param[out] dest Destination string
 *  @param[in] src Source string
 *  @param[in] dest_str_len Currently used length of the destination string not including the terminating '\0'
 *  @param[in] dest_len Total length of the destination string including space for the terminating '\0'
 *  @param[in] except List of normally dis-allowed characters that are acceptable here
 *
 *  @returns Length of the destination string if it was large enough to hold the result
 */
static size_t uri_encode_str(char *dest, const char *src, size_t dest_str_len, size_t dest_len, char *except)
{
    size_t i = 0;

    while (src[i] != '\0')
    {
        if ((uri_is_allowed(src[i])) || (strchr(except, src[i]) != NULL))
        {
            if (dest_str_len + 1 < dest_len)
            {
                dest[dest_str_len] = src[i];
            }
            dest_str_len++;
        }
        else
        {
            if (dest_str_len + 3 < dest_len)
            {
                uri_encode_octet(&dest[dest_str_len], src[i]);
            }
            dest_str_len += 3;
        }
        i++;
    }
    return dest_str_len;
}

/**
 *  @brief Append a source string to a destination string
 *
 *  @param[out] dest Destination string
 *  @param[in] src Source string
 *  @param[in] dest_str_len Currently used length of the destination string not including the terminating '\0'
 *  @param[in] dest_len Total length of the destination string including space for the terminating '\0'
 *
 *  @returns Length of the destination string if it was large enough to hold the result
 */
static size_t uri_copy_str(char *dest, const char *src, size_t dest_str_len, size_t dest_len)
{
    size_t i = 0;

    while (src[i] != '\0')
    {
        if (dest_str_len + 1 < dest_len)
        {
            dest[dest_str_len] = src[i];
        }
        dest_str_len++;
        i++;
    }
    return dest_str_len;
}

/**
 *  @brief Append a source string to a destination string, percent-decoding characters as necessary
 *
 *  @param[out] dest Destination string
 *  @param[in] src Source string
 *  @param[in] dest_str_len Currently used length of the destination string not including the terminating '\0'
 *  @param[in] dest_len Total length of the destination string including space for the terminating '\0'
 *
 *  @returns Length of the destination string if it was large enough to hold the result
 */
static ssize_t uri_decode_str(char *dest, const char *src, size_t dest_str_len, size_t dest_len)
{
    int c = 0;

    while (*src != '\0')
    {
        c = uri_decode_octet(&src);
        if (c == -1)
        {
            return -1;
        }
        if (dest_str_len + 1 < dest_len)
        {
            dest[dest_str_len] = c;
        }
        dest_str_len++;
    }
    return dest_str_len;
}

/**
 *  @brief Locate the port field in a URI
 *
 *  IPv6 addresses contain ':' characters. The ':' character
 *  is also used to mark the start of the port field. So for
 *  this reason, IPv6 addresses are enclosed within '[' and ']'.
 *  This function finds the first occurrence of the ':' character,
 *  in the string, str, that is not enclosed within '[' and ']'.
 *  This marks the start of the port field.
 *
 *  @param[in] str Source string
 *
 *  @returns Pointer to the location of the port field or NULL
 */
static char *uri_find_port(char *str)
{
    char *p = str;
    int in = 0;

    while (*p != '\0')
    {
        if (!in)
        {
            if (*p == '[')
            {
                in = 1;
            }
        }
        else
        {
            if (*p == ']')
            {
                in = 0;
            }
        }
        if ((!in) && (*p == ':'))
        {
            return p;
        }
        p++;
    }
    return NULL;
}

void uri_create(uri_t *uri)
{
    memset(uri, 0, sizeof(uri_t));
}

void uri_destroy(uri_t *uri)
{
    if (uri->scheme != NULL)
        free(uri->scheme);
    if (uri->userinfo != NULL)
        free(uri->userinfo);
    if (uri->host != NULL)
        free(uri->host);
    if (uri->port != NULL)
        free(uri->port);
    if (uri->path != NULL)
        free(uri->path);
    if (uri->query != NULL)
        free(uri->query);
    if (uri->fragment != NULL)
        free(uri->fragment);
    memset(uri, 0, sizeof(uri_t));
}

/**
 *  @brief Parse the scheme component of a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in,out] q Double pointer to a string containing the URI
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int uri_parse_scheme(uri_t *uri, char **q)
{
    ssize_t num = 0;
    size_t len = 0;
    char *p = NULL;
    char *r = NULL;

    if (uri->scheme != NULL)
    {
        return -EBADMSG;
    }
    p = *q;
    r = strchr(p, ':');
    if (r != NULL)
    {
        *r = '\0';
        len = strlen(p) + 1;
        if (len > 1)
        {
            uri->scheme = calloc(len, 1);
            if (uri->scheme == NULL)
            {
                uri_destroy(uri);
                return -ENOMEM;
            }
            num = uri_decode_str(uri->scheme, p, 0, len);
            if ((num == -1) || (num >= len))
            {
                uri_destroy(uri);
                return -EBADMSG;
            }
        }
        *q = r + 1;
    }
    return 0;
}

/**
 *  @brief Parse the hierarchy part of a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in,out] q Double pointer to a string containing the URI
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int uri_parse_hier_part(uri_t *uri, char **q)
{
    ssize_t num = 0;
    size_t len = 0;
    char *port = NULL;
    char *path = NULL;
    char *p = NULL;
    char *r = NULL;

    if ((uri->userinfo != NULL)
     || (uri->host != NULL)
     || (uri->port != NULL)
     || (uri->path != NULL))
    {
        return -EBADMSG;
    }
    p = strsep(q, "?#");
    if (p == NULL)
    {
        uri_destroy(uri);
        return -EBADMSG;
    }
    len = strlen(p);
    if ((len >= 2) && (p[0] == '/') && (p[1] == '/'))
    {
        /* parse authority and path */

        p += 2;
        r = strchr(p, '@');
        if (r != NULL)
        {
            /* parse userinfo */

            *r = '\0';
            len = strlen(p) + 1;
            uri->userinfo = calloc(len, 1);
            if (uri->userinfo == NULL)
            {
                uri_destroy(uri);
                return -ENOMEM;
            }
            num = uri_decode_str(uri->userinfo, p, 0, len);
            if ((num == -1) || (num >= len))
            {
                uri_destroy(uri);
                return -EBADMSG;
            }
            p = r + 1;
        }

        /* check for port and path */
        port = uri_find_port(p);
        if (port != NULL)
        {
            *port++ = '\0';
            path = strchr(port, '/');
        }
        else
        {
            path = strchr(p, '/');
        }
        if (path != NULL)
        {
            *path++ = '\0';
        }

        /* parse host */
        len = strlen(p) + 1;
        r = p + len - 2;
        if ((len > 2) && (*p == '[') && (*r == ']'))
        {
            /* strip enclosing '[' and ']' from IPv6 address */
            p++;
            *r = '\0';
            len -= 2;
        }
        if (len > 1)
        {
            uri->host = calloc(len, 1);
            if (uri->host == NULL)
            {
                uri_destroy(uri);
                return -ENOMEM;
            }
            num = uri_decode_str(uri->host, p, 0, len);
            if ((num == -1) || (num >= len))
            {
                uri_destroy(uri);
                return -EBADMSG;
            }
        }

        if (port != NULL)
        {
            /* parse port */
            len = strlen(port) + 1;
            uri->port = calloc(len, 1);
            if (uri->port == NULL)
            {
                uri_destroy(uri);
                return -ENOMEM;
            }
            num = uri_decode_str(uri->port, port, 0, len);
            if ((num == -1) || (num >= len))
            {
                uri_destroy(uri);
                return -EBADMSG;
            }
        }

        if (path != NULL)
        {
            /* parse path */
            len = strlen(path) + 1;
            uri->path = calloc(len + 1, 1);  /* + 1 for the leading forward slash */
            if (uri->path == NULL)
            {
                uri_destroy(uri);
                return -ENOMEM;
            }
            /* reintroduce stripped forward slash */
            uri->path[0] = '/';
            num = uri_decode_str(uri->path + 1, path, 0, len);
            if ((num == -1) || (num >= len))
            {
                uri_destroy(uri);
                return -EBADMSG;
            }
        }
    }
    else if (len > 0)
    {
        /* parse path only */

        len = strlen(p) + 1;
        uri->path = calloc(len, 1);
        if (uri->path == NULL)
        {
            uri_destroy(uri);
            return -ENOMEM;
        }
        num = uri_decode_str(uri->path, p, 0, len);
        if ((num == -1) || (num >= len))
        {
            uri_destroy(uri);
            return -EBADMSG;
        }
    }
    return 0;
}

/**
 *  @brief Parse the query component of a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in,out] q Double pointer to a string containing the URI
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int uri_parse_query(uri_t *uri, char **q)
{
    ssize_t num = 0;
    size_t len = 0;
    char *p = NULL;

    if (uri->query != NULL)
    {
        return -EBADMSG;
    }
    p = strsep(q, "#");
    if (p == NULL)
    {
        uri_destroy(uri);
        return -EBADMSG;
    }
    len = strlen(p) + 1;
    uri->query = calloc(len, 1);
    if (uri->query == NULL)
    {
        uri_destroy(uri);
        return -ENOMEM;
    }
    num = uri_decode_str(uri->query, p, 0, len);
    if ((num == -1) || (num >= len))
    {
        uri_destroy(uri);
        return -EBADMSG;
    }
    return 0;
}

/**
 *  @brief Parse the fragment component of a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in,out] q Double pointer to a string containing the URI
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int uri_parse_fragment(uri_t *uri, char **q)
{
    ssize_t num = 0;
    size_t len = 0;
    char *p = NULL;

    if (uri->fragment != NULL)
    {
        return -EBADMSG;
    }
    p = strsep(q, "");
    if (p == NULL)
    {
        uri_destroy(uri);
        return -EBADMSG;
    }
    len = strlen(p) + 1;
    uri->fragment = calloc(len, 1);
    if (uri->fragment == NULL)
    {
        uri_destroy(uri);
        return -ENOMEM;
    }
    num = uri_decode_str(uri->fragment, p, 0, len);
    if ((num == -1) || (num >= len))
    {
        uri_destroy(uri);
        return -EBADMSG;
    }
    return 0;
}

int uri_parse(uri_t *uri, const char *str)
{
    char *s = NULL;
    char *q = NULL;
    char c = '\0';
    int ret = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }

    uri_destroy(uri);

    s = strdup(str);
    if (s == NULL)
    {
        return -ENOMEM;
    }
    q = s;

    if (*s != '/')
    {
        /* read scheme */
        ret = uri_parse_scheme(uri, &q);
        if (ret != 0)
        {
            free(s);
            return ret;
        }
    }

    /* read hier-part */
    ret = uri_parse_hier_part(uri, &q);
    if (ret != 0)
    {
        free(s);
        return ret;
    }

    if (q != NULL)
    {
        /* check with the original input string */
        /* to see what character was overwritten */
        c = str[(q - 1) - s];
        if (c == '?')
        {
            ret = uri_parse_query(uri, &q);
            if (ret != 0)
            {
                free(s);
                return ret;
            }
        }
    }
    if (q != NULL)
    {
        /* check with the original input string */
        /* to see what character was overwritten */
        c = str[(q - 1) - s];
        if (c == '#')
        {
            ret = uri_parse_fragment(uri, &q);
            if (ret != 0)
            {
                free(s);
                return ret;
            }
        }
    }

    free(s);
    if (q != NULL)
    {
        return -EBADMSG;
    }
    return 0;
}

int uri_copy(uri_t *dest, uri_t *src)
{
    if ((dest == NULL) || (src == NULL))
    {
        return -EINVAL;
    }

    uri_destroy(dest);

    if (src->scheme != NULL)
    {
        dest->scheme = strdup(src->scheme);
        if (dest->scheme == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    if (src->userinfo != NULL)
    {
        dest->userinfo = strdup(src->userinfo);
        if (dest->userinfo == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    if (src->host != NULL)
    {
        dest->host = strdup(src->host);
        if (dest->scheme == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    if (src->port != NULL)
    {
        dest->port = strdup(src->port);
        if (dest->scheme == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    if (src->path != NULL)
    {
        dest->path = strdup(src->path);
        if (dest->path == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    if (src->query != NULL)
    {
        dest->query = strdup(src->query);
        if (dest->query == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    if (src->fragment != NULL)
    {
        dest->fragment = strdup(src->fragment);
        if (dest->fragment == NULL)
        {
            uri_destroy(dest);
            return -ENOMEM;
        }
    }
    return 0;
}

int uri_set_scheme(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->scheme != NULL)
    {
        free(uri->scheme);
    }
    len = strlen(str) + 1;
    uri->scheme = (char *)calloc(1, len);
    if (uri->scheme == NULL)
    {
        return -ENOMEM;
    }
    num = uri_decode_str(uri->scheme, str, num, len);
    if ((num == -1) || (num >= len))
    {
        free(uri->scheme);
        uri->scheme = NULL;
        return -EBADMSG;
    }
    return 0;
}

int uri_set_userinfo(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->userinfo != NULL)
    {
        free(uri->userinfo);
    }
    len = strlen(str) + 1;
    uri->userinfo = (char *)calloc(1, len);
    if (uri->userinfo == NULL)
    {
        return -ENOMEM;
    }
    num = uri_decode_str(uri->userinfo, str, num, len);
    if ((num == -1) || (num >= len))
    {
        free(uri->userinfo);
        uri->userinfo = NULL;
        return -EBADMSG;
    }
    return 0;
}

int uri_set_host(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->host != NULL)
    {
        free(uri->host);
    }
    len = strlen(str) + 1;
    uri->host = (char *)calloc(1, len);
    if (uri->host == NULL)
    {
        return -ENOMEM;
    }
    num = uri_decode_str(uri->host, str, num, len);
    if ((num == -1) || (num >= len))
    {
        free(uri->host);
        uri->host = NULL;
        return -EBADMSG;
    }
    return 0;
}

int uri_set_port(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->port != NULL)
    {
        free(uri->port);
    }
    len = strlen(str) + 1;
    uri->port = (char *)calloc(1, len);
    if (uri->port == NULL)
    {
        return -ENOMEM;
    }
    num = uri_decode_str(uri->port, str, num, len);
    if ((num == -1) || (num >= len))
    {
        free(uri->port);
        uri->port = NULL;
        return -EBADMSG;
    }
    return 0;
}

int uri_set_path(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->path != NULL)
    {
        free(uri->path);
    }
    len = strlen(str) + 1;
    if (str[0] != '/')
    {
        len++;
    }
    uri->path = (char *)calloc(1, len);
    if (uri->path == NULL)
    {
        return -ENOMEM;
    }
    if (str[0] != '/')
    {
        num = uri_decode_str(uri->path, "/", num, len);
    }
    num = uri_decode_str(uri->path, str, num, len);
    if ((num == -1) || (num >= len))
    {
        free(uri->path);
        uri->path = NULL;
        return -EBADMSG;
    }
    return 0;
}

int uri_set_query(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->query != NULL)
    {
        free(uri->query);
    }
    len = strlen(str) + 1;
    uri->query = (char *)calloc(1, len);
    if (uri->query == NULL)
    {
        return -ENOMEM;
    }
    num = uri_decode_str(uri->query, str, num, len);
    if ((num == -1) || (num > len))
    {
        free(uri->query);
        uri->query = NULL;
        return -EBADMSG;
    }
    return 0;
}

int uri_set_fragment(uri_t *uri, const char *str)
{
    ssize_t num = 0;
    size_t len = 0;

    if ((uri == NULL) || (str == NULL))
    {
        return -EINVAL;
    }
    if (uri->fragment != NULL)
    {
        free(uri->fragment);
    }
    len = strlen(str) + 1;
    uri->fragment = (char *)calloc(1, len);
    if (uri->fragment == NULL)
    {
        return -ENOMEM;
    }
    num = uri_decode_str(uri->fragment, str, num, len);
    if ((num == -1) || (num >= len))
    {
        free(uri->fragment);
        uri->fragment = NULL;
        return -EBADMSG;
    }
    return 0;
}

size_t uri_generate(uri_t *uri, char *buf, size_t len)
{
    size_t num = 0;

    if ((uri == NULL) || (buf == NULL))
    {
        return -EINVAL;
    }
    memset(buf, 0, len);
    if (uri->scheme != NULL)
    {
        num = uri_encode_str(buf, uri->scheme, num, len, "");
        num = uri_copy_str(buf, ":", num, len);
    }
    if ((uri->userinfo != NULL) || (uri->host != NULL) || (uri->port != NULL))
    {
        num = uri_copy_str(buf, "//", num, len);
    }
    if (uri->userinfo != NULL)
    {
        num = uri_encode_str(buf, uri->userinfo, num, len, ":");
        num = uri_copy_str(buf, "@", num, len);
    }
    if (uri->host != NULL)
    {
        if (strchr(uri->host, ':') != NULL)
        {
            /* enclose IPv6 address in '[' and ']' */
            num = uri_copy_str(buf, "[", num, len);
            num = uri_encode_str(buf, uri->host, num, len, ":");
            num = uri_copy_str(buf, "]", num, len);
        }
        else
        {
            num = uri_encode_str(buf, uri->host, num, len, "");
        }
    }
    if (uri->port != NULL)
    {
        num = uri_copy_str(buf, ":", num, len);
        num = uri_encode_str(buf, uri->port, num, len, "");
    }
    if (uri->path != NULL)
    {
        num = uri_encode_str(buf, uri->path, num, len, "/:@");
    }
    if (uri->query != NULL)
    {
        num = uri_copy_str(buf, "?", num, len);
        num = uri_encode_str(buf, uri->query, num, len, "?/:@");
    }
    if (uri->fragment != NULL)
    {
        num = uri_copy_str(buf, "#", num, len);
        num = uri_encode_str(buf, uri->fragment, num, len, "?/:@");
    }
    return num;
}
