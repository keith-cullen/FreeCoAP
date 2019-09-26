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
 *  @file coap_msg.h
 *
 *  @brief Include file for the FreeCoAP message parser/formatter library
 */

#ifndef COAP_MSG_H
#define COAP_MSG_H

#include <stddef.h>
#include <sys/types.h>

#define COAP_MSG_VER                                0x01                        /**< CoAP version */
#define COAP_MSG_MAX_TOKEN_LEN                      8                           /**< Maximum token length */
#define COAP_MSG_MAX_CODE_CLASS                     7                           /**< Maximum code class */
#define COAP_MSG_MAX_CODE_DETAIL                    31                          /**< Maximum code detail */
#define COAP_MSG_MAX_MSG_ID                         ((1 << 16) - 1)             /**< Maximum message ID */

#define COAP_MSG_OP_URI_PATH_MAX_LEN                256                         /**< Maximum buffer length for a reconstructed URI path */
#define COAP_MSG_OP_MAX_BLOCK_VAL_LEN               3                           /**< Maximum buffer length for a Block1 or Block2 option value */
#define COAP_MSG_OP_MAX_BLOCK_SIZE                  (1 << 10)                   /**< Maximum block size for a Block1 or Block2 option */
#define COAP_MSG_MAX_BUF_LEN                        1152                        /**< Maximum buffer length for header and payload */
#define COAP_MSG_MAX_PAYLOAD_LEN                    1024                        /**< Maximum buffer length for payload */

#define coap_msg_block_szx_to_size(szx)             (1 << ((szx) + 4)))         /**< Convert a block size exponent value to a size value */
#define coap_msg_block_start_to_num(start, szx)     ((start) >> ((szx) + 4))    /**< Convert a start byte value to a block num value */

#define coap_msg_op_num_is_critical(num)            ((num) & 1)                 /**< Indicate if an option is critical */
#define coap_msg_op_num_is_unsafe(num)              ((num) & 2)                 /**< Indicate if an option is unsafe to forward */
#define coap_msg_op_num_no_cache_key(num)           ((num & 0x1e) == 0x1c)      /**< Indicate if an option is not part of the cache key */

#define coap_msg_op_get_num(op)                     ((op)->num)                 /**< Get the option number from an option */
#define coap_msg_op_set_num(op, num)                ((op)->num = (num))         /**< Set the option number in an option */
#define coap_msg_op_get_len(op)                     ((op)->len)                 /**< Get the option length from an option */
#define coap_msg_op_set_len(op, len)                ((op)->len = (len))         /**< Set the option length in an option */
#define coap_msg_op_get_val(op)                     ((op)->val)                 /**< Get the option value from an option */
#define coap_msg_op_set_val(op, val)                ((op)->val = (val))         /**< Set the option value in an option */
#define coap_msg_op_get_next(op)                    ((op)->next)                /**< Get the next pointer from an option */
#define coap_msg_op_set_next(op, next_op)           ((op)->next = (next_op))    /**< Set the next pointer in an option */

#define coap_msg_get_ver(msg)                       ((msg)->ver)                /**< Get the version from a message */
#define coap_msg_get_type(msg)                      ((msg)->type)               /**< Get the type from a message */
#define coap_msg_get_token_len(msg)                 ((msg)->token_len)          /**< Get the token length from a message */
#define coap_msg_get_code_class(msg)                ((msg)->code_class)         /**< Get the code class from a message */
#define coap_msg_get_code_detail(msg)               ((msg)->code_detail)        /**< Get the code detail from a message */
#define coap_msg_get_msg_id(msg)                    ((msg)->msg_id)             /**< Get the message ID from message */
#define coap_msg_get_token(msg)                     ((msg)->token)              /**< Get the token from a message */
#define coap_msg_get_first_op(msg)                  ((msg)->op_list.first)      /**< Get the first option from a message */
#define coap_msg_get_payload(msg)                   ((msg)->payload)            /**< Get the payload from a message */
#define coap_msg_get_payload_len(msg)               ((msg)->payload_len)        /**< Get the payload length from a message */
#define coap_msg_is_empty(msg)                      (((msg)->code_class == 0) && ((msg)->code_detail == 0))
                                                                                /**< Indicate if a message is empty */

/**
 *  @brief Message type enumeration
 */
typedef enum
{
    COAP_MSG_CON = 0x0,                                                         /**< Confirmable message */
    COAP_MSG_NON = 0x1,                                                         /**< Non-confirmable message */
    COAP_MSG_ACK = 0x2,                                                         /**< Acknowledgement message */
    COAP_MSG_RST = 0x3                                                          /**< Reset message */
}
coap_msg_type_t;

/**
 *  @brief Code class enumeration
 */
typedef enum
{
    COAP_MSG_REQ = 0,                                                           /**< Request */
    COAP_MSG_SUCCESS = 2,                                                       /**< Success response */
    COAP_MSG_CLIENT_ERR = 4,                                                    /**< Client error response */
    COAP_MSG_SERVER_ERR = 5,                                                    /**< Server error response */
}
coap_msg_class_t;

/**
 *  @brief Request code detail enumeration
 */
typedef enum
{
    COAP_MSG_GET = 1,                                                           /**< Get request method */
    COAP_MSG_POST = 2,                                                          /**< Post request method */
    COAP_MSG_PUT = 3,                                                           /**< Put request method */
    COAP_MSG_DELETE = 4                                                         /**< Delete request method */
}
coap_msg_method_t;

/**
 *  @brief Success response code detail enumeration
 */
typedef enum
{
    COAP_MSG_CREATED = 1,                                                       /**< Created success response */
    COAP_MSG_DELETED = 2,                                                       /**< Deleted success response */
    COAP_MSG_VALID = 3,                                                         /**< Valid success response */
    COAP_MSG_CHANGED = 4,                                                       /**< Changed success response */
    COAP_MSG_CONTENT = 5,                                                       /**< Content success response */
    COAP_MSG_CONTINUE = 31                                                      /**< Continue success response */
}
coap_msg_success_t;

/**
 *  @brief Client error response code detail enumeration
 */
typedef enum
{
    COAP_MSG_BAD_REQ = 0,                                                       /**< Bad request client error */
    COAP_MSG_UNAUTHORIZED = 1,                                                  /**< Unauthorized client error */
    COAP_MSG_BAD_OPTION = 2,                                                    /**< Bad option client error */
    COAP_MSG_FORBIDDEN = 3,                                                     /**< Forbidden client error */
    COAP_MSG_NOT_FOUND = 4,                                                     /**< Not found client error */
    COAP_MSG_METHOD_NOT_ALLOWED = 5,                                            /**< Method not allowed client error */
    COAP_MSG_NOT_ACCEPTABLE = 6,                                                /**< Not acceptable client error */
    COAP_MSG_INCOMPLETE = 8,                                                    /**< Request entity incomplete client error */
    COAP_MSG_PRECOND_FAILED = 12,                                               /**< Precondition failed client error */
    COAP_MSG_REQ_ENT_TOO_LARGE = 13,                                            /**< Request entity too large client error */
    COAP_MSG_UNSUP_CONT_FMT = 15                                                /**< Unsupported content-format client error */
}
coap_msg_client_err_t;

/**
 *  @brief Server error response code detail enumeration
 */
typedef enum
{
    COAP_MSG_INT_SERVER_ERR = 0,                                                /**< Internal server error */
    COAP_MSG_NOT_IMPL = 1,                                                      /**< Not implemented server error */
    COAP_MSG_BAD_GATEWAY = 2,                                                   /**< Bad gateway server error */
    COAP_MSG_SERV_UNAVAIL = 3,                                                  /**< Service unavailable server error */
    COAP_MSG_GATEWAY_TIMEOUT = 4,                                               /**< Gateway timeout server error */
    COAP_MSG_PROXY_NOT_SUP = 5                                                  /**< Proxying not supported server error */
}
coap_msg_server_err_t;

/**
 *  @brief Option number enumeration
 */
typedef enum
{
    COAP_MSG_IF_MATCH = 1,                                                      /**< If-Match option number */
    COAP_MSG_URI_HOST = 3,                                                      /**< URI-Host option number */
    COAP_MSG_ETAG = 4,                                                          /**< Entity-Tag option number */
    COAP_MSG_IF_NONE_MATCH = 5,                                                 /**< If-None-Match option number */
    COAP_MSG_URI_PORT = 7,                                                      /**< URI-Port option number */
    COAP_MSG_LOCATION_PATH = 8,                                                 /**< Location-Path option number */
    COAP_MSG_URI_PATH = 11,                                                     /**< URI-Path option number */
    COAP_MSG_CONTENT_FORMAT = 12,                                               /**< Content-Format option number */
    COAP_MSG_MAX_AGE = 14,                                                      /**< Max-Age option number */
    COAP_MSG_URI_QUERY = 15,                                                    /**< URI-Query option number */
    COAP_MSG_ACCEPT = 17,                                                       /**< Accept option number */
    COAP_MSG_LOCATION_QUERY = 20,                                               /**< Location-Query option number */
    COAP_MSG_BLOCK2 = 23,                                                       /**< Block2 option number */
    COAP_MSG_BLOCK1 = 27,                                                       /**< Block1 option number */
    COAP_MSG_SIZE2 = 28,                                                        /**< Size2 option number */
    COAP_MSG_PROXY_URI = 35,                                                    /**< Proxy-URI option number */
    COAP_MSG_PROXY_SCHEME = 39,                                                 /**< Proxy-Scheme option number */
    COAP_MSG_SIZE1 = 60                                                         /**< Size1 option number */
}
coap_msg_op_num_t;

/**
 *  @brief Option structure
 */
typedef struct coap_msg_op
{
    unsigned num;                                                               /**< Option number */
    unsigned len;                                                               /**< Option length */
    char *val;                                                                  /**< Pointer to a buffer containing the option value */
    struct coap_msg_op *next;                                                   /**< Pointer to the next option structure in the list */
}
coap_msg_op_t;

/**
 *  @brief Option linked-list structure
 */
typedef struct
{
    coap_msg_op_t *first;                                                       /**< Pointer to the first option structure in the list */
    coap_msg_op_t *last;                                                        /**< Pointer to the last option structure in the list */
}
coap_msg_op_list_t;

/**
 *  @brief Message structure
 */
typedef struct
{
    unsigned ver;                                                               /**< CoAP version */
    coap_msg_type_t type;                                                       /**< Message type */
    unsigned token_len;                                                         /**< Token length */
    unsigned code_class;                                                        /**< Code class */
    unsigned code_detail;                                                       /**< Code detail */
    unsigned msg_id;                                                            /**< Message ID */
    char token[COAP_MSG_MAX_TOKEN_LEN];                                         /**< Token value */
    coap_msg_op_list_t op_list;                                                 /**< Option list */
    char *payload;                                                              /**< Pointer to a buffer containing the payload */
    size_t payload_len;                                                         /**< Length of the payload */
}
coap_msg_t;

/**
 *  @brief Check if option is recognized
 *
 *  @param[in] num Option number
 *
 *  @returns Operation status
 *  @retval 1 Option is recognized
 *  @retval 0 Option is not recognized
 */
int coap_msg_op_num_is_recognized(unsigned num);

/**
 *  @brief Calculate block size exponent from block size
 *
 *  @param[in] size Block size
 *
 *  @returns Block size exponent or error code
 *  @retval >=0 Block size exponent
 *  @retval <0 Error
 */
int coap_msg_op_calc_block_szx(unsigned size);

/**
 *  @brief Parse Block1 or Block2 option value
 *
 *  @param[out] num Pointer to Block number
 *  @param[out] more Pointer to More value
 *  @param[out] size Pointer to Block size
 *  @param[in] val Pointer to the option value
 *  @param[in] len Option length
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_op_parse_block_val(unsigned *num, unsigned *more, unsigned *size, const char *val, unsigned len);

/**
 *  @brief Format Block1 or Block2 option value
 *
 *  @param[out] val Pointer to a buffer to store the option value
 *  @param[in] len Length of the buffer
 *  @param[in] num Block number
 *  @param[in] more More value
 *  @param[in] size Block size
 *
 *  @returns Length of the formatted option value or error code
 *  @retval >0 Length of the formatted option value
 *  @retval <0 Error
 */
int coap_msg_op_format_block_val(char *val, unsigned len, unsigned num, unsigned more, unsigned size);

/**
 *  @brief Generate a random string of bytes
 *
 *  @param[out] buf Pointer to a buffer to store the random string
 *  @param[in] len Length of the buffer
 */
void coap_msg_gen_rand_str(char *buf, size_t len);

/**
 *  @brief Initialise a message structure
 *
 *  @param[out] msg Pointer to a message structure
 */
void coap_msg_create(coap_msg_t *msg);

/**
 *  @brief Deinitialise a message structure
 *
 *  @param[in,out] msg Pointer to a message structure
 */
void coap_msg_destroy(coap_msg_t *msg);

/**
 *  @brief Deinitialise and initialise a message structure
 *
 *  @param[in,out] msg Pointer to a message structure
 */
void coap_msg_reset(coap_msg_t *msg);

/**
 *  @brief Check that all of the critical options in a message are recognized
 *
 *  @param[in] msg Pointer to message structure
 *
 *  @returns Operation status or bad option number
 *  @retval 0 Success
 *  @retval >0 Bad option number
 */
unsigned coap_msg_check_critical_ops(coap_msg_t *msg);

/**
 *  @brief Check that all of the unsafe options in a message are recognized
 *
 *  @param[in] msg Pointer to message structure
 *
 *  @returns Operation status or bad option number
 *  @retval 0 Success
 *  @retval >0 Bad option number
 */
unsigned coap_msg_check_unsafe_ops(coap_msg_t *msg);

/**
 *  @brief Extract the type and message ID values from a message
 *
 *  If a message contains a format error, this function
 *  will attempt to extract the type and message ID so
 *  that a reset message can be returned to the sender.
 *
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *  @param[out] type Pointer to field to store the type value
 *  @param[out] msg_id Pointer to a field to store the message ID value
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_parse_type_msg_id(char *buf, size_t len, unsigned *type, unsigned *msg_id);

/**
 *  @brief Find and parse a Block1 or Block2 option in a message
 *
 *  @param[out] num Pointer to Block number
 *  @param[out] more Pointer to More value
 *  @param[out] size Pointer to Block size (in bytes)
 *  @param[in] msg Pointer to a message
 *  @param[in] type Block option type: COAP_MSG_BLOCK1 or COAP_MSG_BLOCK2
 *
 *  @returns Operation status
 *  @retval 1 Block option not found
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_parse_block_op(unsigned *num, unsigned *more, unsigned *size, coap_msg_t *msg, int type);

/**
 *  @brief Parse a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
ssize_t coap_msg_parse(coap_msg_t *msg, char *buf, size_t len);

/**
 *  @brief Set the type in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] type Message type
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_set_type(coap_msg_t *msg, unsigned type);

/**
 *  @brief Set the code in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] code_class Code class
 *  @param[in] code_detail Code detail
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_set_code(coap_msg_t *msg, unsigned code_class, unsigned code_detail);

/**
 *  @brief Set the message ID in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] msg_id Message ID
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_set_msg_id(coap_msg_t *msg, unsigned msg_id);

/**
 *  @brief Set the token in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the token
 *  @param[in] len Length of the buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_set_token(coap_msg_t *msg, char *buf, size_t len);

/**
 *  @brief Add an option to a message structure
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] num Option number
 *  @param[in] len Option length
 *  @param[in] val Pointer to a buffer containing the option value
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_add_op(coap_msg_t *msg, unsigned num, unsigned len, const char *val);

/**
 *  @brief Set the payload in a message
 *
 *  Free the buffer in the message structure containing
 *  the current payload if there is one, allocate a buffer
 *  to contain the new payload and copy the buffer argument
 *  into the new payload buffer.
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the payload
 *  @param[in] len Length of the buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_set_payload(coap_msg_t *msg, char *buf, size_t len);

/**
 *  @brief Clear the payload in a message
 *
 *  Free the buffer in the message structure containing
 *  the current payload if there is one.
 *
 *  @param[in,out] msg Pointer to a message structure
 */
void coap_msg_clear_payload(coap_msg_t *msg);

/**
 *  @brief Format a message
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the formatted message or error code
 *  @retval >0 Length of the formatted message
 *  @retval <0 Error
 */
ssize_t coap_msg_format(coap_msg_t *msg, char *buf, size_t len);

/**
 *  @brief Copy a message
 *
 *  @param[in,out] dst Pointer to the destination message structure
 *  @param[in] src Pointer to the source message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_msg_copy(coap_msg_t *dst, coap_msg_t *src);

/**
 *  @brief Convert the URI path in a message to a string representation
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to hold the string
 *  @param[in] len Length of the buffer
 *
 *  @returns The number of bytes that would be written to the buffer it was large enough
 */
size_t coap_msg_uri_path_to_str(coap_msg_t *msg, char *buf, size_t len);

#endif
