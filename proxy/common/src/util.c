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
long util_load_txt_file(const char *file_name, char **buf)
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
    *buf = (char *)calloc(file_len + 1, 1);
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
