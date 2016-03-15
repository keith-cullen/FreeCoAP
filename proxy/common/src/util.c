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
 *  @file util.c
 *
 *  @brief Source file for the FreeCoAP utility library
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "util.h"

/*  always writes a terminating null character if dst_len > 0
 *  returns the number of chars that dst would contain, not including
 *  the terminating null char, if dst_len was large enough
 */
size_t util_strncpy(char *dst, const char *src, size_t dst_len)
{
    size_t i = 0;
    size_t j = 0;

    if (dst_len == 0)
    {
        return 0;
    }
    while (src[j] != '\0')
    {
        if (i < (dst_len - 1))
        {
            dst[i] = src[j];
            i++;
        }
        j++;
    }
    dst[i] = '\0';
    return j;
}

/*  always writes a terminating null character if any chars are written
 *  returns the number of chars that dst would contain, not including
 *  the terminating null character, if dst_len was large enough
 */
size_t util_strncat(char *dst, const char *src, size_t dst_str_len, size_t dst_len)
{
    size_t i = dst_str_len;
    size_t j = 0;

    if (dst_len == 0)
    {
        return 0;
    }
    while (src[j] != '\0')
    {
        if (i < (dst_len - 1))
        {
            dst[i] = src[j];
            i++;
        }
        j++;
    }
    if (i < dst_len)
    {
        dst[i] = '\0';
    }
    else
    {
        dst[dst_len - 1] = '\0';
    }
    return dst_str_len + j;
}

/*  always writes a terminating null character if any chars are written
 *  returns the number of chars that dst would contain, not including
 *  the terminating null character, if dst_len was large enough
 */
size_t util_snprintf_tail(char *dst, size_t dst_len, size_t dst_str_len, const char *str, ...)
{
    va_list arg_list;
    size_t dst_next_len = 0;
    char *dst_next = NULL;
    char *dst_end = NULL;
    int num = 0;

    va_start(arg_list, str);
    dst_next = dst + dst_str_len;
    dst_end = dst + dst_len;
    if (dst_next < dst_end)
    {
        dst_next_len = dst_end - dst_next;
        num = vsnprintf(dst_next, dst_next_len, str, arg_list);
        if (num < 0)
        {
            num = 0;
        }
    }
    va_end(arg_list);
    return dst_str_len + num;
}

/*  returns: {UTIL_OK, success
 *           {UTIL_NOMEM_ERROR, no memory
 *           {UTIL_INVAL_ERROR, new buffer size is invalid
 */
int util_create_buf(char **buf, size_t buf_len, size_t max_buf_len)
{
    if ((buf_len == 0) || (buf_len > max_buf_len))
    {
        return UTIL_INVAL_ERROR;
    }
    *buf = (char *)calloc(buf_len + 1, 1);
    if (*buf == NULL)
    {
        return UTIL_NOMEM_ERROR;
    }
    return UTIL_OK;
}

/*  returns: {UTIL_OK, success
 *           {UTIL_NOMEM_ERROR, no memory
 *           {UTIL_INVAL_ERROR, new buffer size is invalid
 */
int util_inc_buf(char **buf, size_t *buf_len, size_t max_buf_len)
{
    size_t new_buf_len = 0;
    char *new_buf = NULL;

    new_buf_len = *buf_len * 2;
    if ((new_buf_len == 0) || (new_buf_len > max_buf_len))
    {
        return UTIL_INVAL_ERROR;
    }
    new_buf = (char *)calloc(new_buf_len + 1, 1);
    if (new_buf == NULL)
    {
        return UTIL_NOMEM_ERROR;
    }
    memcpy(new_buf, *buf, *buf_len);
    free(*buf);
    *buf = new_buf;
    *buf_len = new_buf_len;
    return UTIL_OK;
}

/*  returns: {>=0, file size in bytes
 *           {UTIL_FILE_ERROR, file not readable
 */
static inline long util_file_len(FILE *file)
{
    long file_len = 0;

    if ((fseek(file, 0, SEEK_END) == 0)
     && ((file_len = ftell(file)) >= 0)
     && (fseek(file, 0, SEEK_SET) == 0))
    {
        return file_len;
    }
    return UTIL_FILE_ERROR;
}

/*  returns: {>=0, num bytes read
 *           {UTIL_FILE_ERROR, file not found or unreadable
 *           {UTIL_NOMEM_ERROR, no memory
 */
static long util_load_file(const char *file_name, char **buf, int term)
{
    long file_len = 0;
    long num = 0;
    FILE *file = NULL;

    *buf = NULL;

    file = fopen(file_name, "r");
    if (file == NULL)
    {
        return UTIL_FILE_ERROR;
    }
    file_len = util_file_len(file);
    if (file_len == -1)
    {
        fclose(file);
        return UTIL_FILE_ERROR;
    }
    *buf = (char *)calloc(file_len + term, 1);
    if (*buf == NULL)
    {
        fclose(file);
        return UTIL_NOMEM_ERROR;
    }
    num = fread(*buf, 1, file_len, file);
    fclose(file);
    if (num != file_len)
    {
        free(*buf);
        *buf = NULL;
        return UTIL_FILE_ERROR;
    }
    return num;
}

/*  returns: {>=0, num bytes read
 *           {UTIL_FILE_ERROR, file not found or unreadable
 *           {UTIL_NOMEM_ERROR, no memory
 */
long util_load_bin_file(const char *file_name, char **buf)
{
    return util_load_file(file_name, buf, 0);
}

/*  returns: {>=0, num bytes read
 *           {UTIL_FILE_ERROR, file not found or unreadable
 *           {UTIL_NOMEM_ERROR, no memory
 */
long util_load_txt_file(const char *file_name, char **buf)
{
    return util_load_file(file_name, buf, 1);
}

/*  returns: {>=0, num bytes read
 *           {UTIL_FILE_ERROR, file not found or unreadable
 *           {UTIL_INVAL_ERROR, insufficient buffer
 */
static long util_read_file(const char *file_name, char *buf, size_t len, int term)
{
    FILE *file = NULL;
    long file_len = 0;
    long num = 0;
    long ret = 0;

    if (len == 0)
    {
        return 0;
    }
    memset(buf, 0, len);
    file = fopen(file_name, "r");
    if (file == NULL)
    {
        return UTIL_FILE_ERROR;
    }
    file_len = util_file_len(file);
    if (file_len <= 0)
    {
        fclose(file);
        return UTIL_FILE_ERROR;
    }
    if (file_len + term > (long)len)
    {
        fclose(file);
        return UTIL_INVAL_ERROR;
    }
    num = fread(buf, 1, file_len, file);
    if (num == file_len)
    {
        ret = num;  /* success */
    }
    else
    {
        ret = UTIL_FILE_ERROR;
    }
    fclose(file);
    return ret;
}

/*  returns: {>=0, num bytes read
 *           {UTIL_FILE_ERROR, file not found or unreadable
 *           {UTIL_INVAL_ERROR, insufficient buffer
 */
long util_read_bin_file(const char *file_name, char *buf, size_t len)
{
    return util_read_file(file_name, buf, len, 0);
}

/*  returns: {>=0, num bytes read
 *           {UTIL_FILE_ERROR, file not found or unreadable
 *           {UTIL_INVAL_ERROR, insufficient buffer
 */
long util_read_txt_file(const char *file_name, char *buf, size_t len)
{
    return util_read_file(file_name, buf, len, 1);
}

/*  returns: {UTIL_OK, success
 *           {UTIL_FILE_ERROR, file error
 */
int util_save_file(const char *file_name, const char *buf, size_t len)
{
    size_t num = 0;
    FILE *file = NULL;

    if (len == 0)
    {
        return UTIL_OK;
    }
    file = fopen(file_name, "w");
    if (file == NULL)
    {
        return UTIL_FILE_ERROR;
    }
    num = fwrite(buf, 1, len, file);
    fclose(file);
    if (num != len)
    {
        return UTIL_FILE_ERROR;
    }
    return UTIL_OK;
}
