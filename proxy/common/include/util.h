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
 *  @file util.h
 *
 *  @brief Include file for the FreeCoAP utility library
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <string.h>

#define UTIL_OK            0
#define UTIL_FILE_ERROR   -1
#define UTIL_NOMEM_ERROR  -2
#define UTIL_INVAL_ERROR  -3

size_t util_strncpy(char *dst, const char *src, size_t n);
size_t util_strncat(char *dst, const char *src, size_t dst_str_len, size_t dst_len);
size_t util_snprintf_tail(char *dst, size_t dst_len, size_t dst_str_len, const char *str, ...);
int util_create_buf(char **buf, size_t buf_len, size_t max_buf_len);
int util_inc_buf(char **buf, size_t *buf_len, size_t max_buf_len);
long util_load_bin_file(const char *file_name, char **buf);
long util_load_txt_file(const char *file_name, char **buf);
long util_read_bin_file(const char *file_name, char *buf, size_t len);
long util_read_txt_file(const char *file_name, char *buf, size_t len);
int util_save_file(const char *file_name, const char *buf, size_t len);

#endif
