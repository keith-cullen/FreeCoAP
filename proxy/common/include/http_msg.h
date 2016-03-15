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
 *  @file http_msg.h
 *
 *  @brief Include file for the FreeCoAP HTTP message parser/formatter library
 */

#ifndef HTTP_MSG_H
#define HTTP_MSG_H

#include <stddef.h>
#include <sys/types.h>

#define HTTP_MSG_NUM_START  3                                                   /**< Number of fields in the start line */

#define http_msg_header_get_name(header)   ((header)->name)                     /**< Get the name of a message header */
#define http_msg_header_get_value(header)  ((header)->value)                    /**< Get the value of a message header */
#define http_msg_header_get_next(header)   ((header)->next)                     /**< Get the next message header */

#define http_msg_get_start(msg, i)         ((msg)->start[i])                    /**< Get a start field from a message */
#define http_msg_get_first_header(msg)     ((msg)->header.first)                /**< Get the first header in a message */
#define http_msg_get_body(msg)             ((msg)->body)                        /**< Get the body of a message */
#define http_msg_get_body_len(msg)         ((msg)->body_len)                    /**< Get the body length for a message */

/**
 *  @brief Message header structure
 */
typedef struct http_msg_header_t
{
    char *name;                                                                 /**< Name of a message header */
    char *value;                                                                /**< Value of a message header */
    struct http_msg_header_t *next;                                             /**< Next message header */
}
http_msg_header_t;

/**
 *  @brief Message header linked-list structure
 */
typedef struct
{
    http_msg_header_t *first;                                                   /**< First message header */
    http_msg_header_t *last;                                                    /**< Last message header */
}
http_msg_list_t;

/**
 *  @brief Message structure
 */
typedef struct
{
    char *start[HTTP_MSG_NUM_START];                                            /**< Array of start line fields */
    http_msg_list_t header;                                                     /**< Linked-list of message headers */
    char *body;                                                                 /**< Message body */
    size_t body_len;                                                            /**< Length of the message body */
}
http_msg_t;

/**
 *  @brief Convert an error code to a string representation
 *
 *  @param[in] error Error code
 *
 *  @returns String representation
 */
const char *http_msg_strerror(int error);

/**
 *  @brief Initialise a message structure
 *
 *  @param[out] msg Pointer to a message structure
 */
void http_msg_create(http_msg_t *msg);

/**
 *  @brief Deinitialise a message structure
 *
 *  @param[out] msg Pointer to a message structure
 */
void http_msg_destroy(http_msg_t *msg);

/**
 *  @brief Deinitialise then initialise a message structure
 *
 *  @param[out] msg Pointer to a message structure
 */
void http_msg_reset(http_msg_t *msg);

/**
 *  @brief Parse a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer containing the message
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes
 *  @retval <0 Error code
 */
ssize_t http_msg_parse(http_msg_t *msg, const char *buf, size_t len);

/**
 *  @brief Set the start line in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] start1 String containing the first start field
 *  @param[in] start2 String containing the second start field
 *  @param[in] start3 String containing the third start field
 *
 *  @returns Error code
 */
int http_msg_set_start(http_msg_t *msg, const char *start1, const char *start2, const char *start3);

/**
 *  @brief Set a header in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] name String containing the header name
 *  @param[in] name String containing the header value
 *
 *  @returns Error code
 */
int http_msg_set_header(http_msg_t *msg, const char *name, const char *value);

/**
 *  @brief Set the body in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] buf Buffer containing the message body
 *  @param[in] len Length of the buffer containing the message body
 *
 *  @returns Error code
 */
int http_msg_set_body(http_msg_t *msg, const char *buf, size_t len);

/**
 *  @brief Write a message to a buffer
 *
 *  Always writes a terminating null character if
 *  the length of the buffer is greater than zero.
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Buffer to hold the message
 *  @param[in] len Length of the buffer to hold the message
 *
 *  @returns Number of bytes or error code
 *  @retval >0 Number of bytes that would have been written if the buffer was large enough
 *  @retval <0 Error code
 */
size_t http_msg_generate(http_msg_t *msg, char *buf, size_t len);

/**
 *  @brief Write a message body chunk to a buffer
 *
 *  Always writes a terminating null character if
 *  the length of the buffer is greater than zero.
 *
 *  @param[out] out Buffer to contain the message body chunk
 *  @param[in] out_len Length of the buffer to contain the message body chunk
 *  @param[in] in Buffer that contains the message body chunk
 *  @param[in] in_len Length of the buffer that contains the message body chunk
 *
 *  @returns Number of bytes that would have been written if the buffer was large enough
 */
size_t http_msg_generate_chunk(char *out, size_t out_len, const char *in, size_t in_len);

/**
 *  @brief Write the marker for the last message body chunk to a buffer
 *
 *  Always writes a terminating null character if
 *  the length of the buffer is greater than zero.
 *
 *  @param[out] buf Buffer to contain the marker
 *  @param[in] len Length of the buffer to contain the marker
 *
 *  @returns Number of bytes that would have been written if the buffer was large enough
 */
size_t http_msg_generate_last_chunk(char *buf, size_t len);

/**
 *  @brief Write a message trailer to a buffer
 *
 *  Always writes a terminating null character if
 *  the length of the buffer is greater than zero.
 *
 *  @param[out] buf Buffer to contain the trailer
 *  @param[in] len Length of the buffer to contain the trailer
 *  @param[in] name String containing the trailer name
 *  @param[in] value String containing the trailer value
 *
 *  @returns Number of bytes that would have been written if the buffer was large enough
 */
size_t http_msg_generate_trailer(char *buf, size_t len, const char *name, const char *value);

/**
 *  @brief Write a blank line to a buffer
 *
 *  Always writes a terminating null character if
 *  the length of the buffer is greater than zero.
 *
 *  @param[out] buf Buffer to contain the blank line
 *  @param[in] len Length of the buffer to contain the blank line
 *
 *  @returns Number of bytes that would have been written if the buffer was large enough
 */
size_t http_msg_generate_blank_line(char *buf, size_t len);

#endif
