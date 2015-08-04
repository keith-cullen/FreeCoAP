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

#define COAP_MSG_VER                           0x01                             /**< CoAP version */
#define COAP_MSG_MAX_TOKEN_LEN                 8                                /**< Maximum token length */
#define COAP_MSG_MAX_CODE_CLASS                7                                /**< Maximum code class */
#define COAP_MSG_MAX_CODE_DETAIL               31                               /**< Maximum code detail */
#define COAP_MSG_MAX_MSG_ID                    ((1 << 16) - 1)                  /**< Maximum message ID */

#define COAP_MSG_OP_URI_PATH_NUM               11                               /**< Uri-path option number */
#define COAP_MSG_OP_URI_PATH_MAX_LEN           256                              /**< Maximum buffer length for a reconstructed URI path */

#define COAP_MSG_MAX_BUF_LEN                   1152                             /**< Maximum buffer length for header and payload */

#define coap_msg_op_num_is_critical(num)       ((num) & 1)                      /**< Indicate if an option is critical */
#define coap_msg_op_num_is_unsafe(num)         ((num) & 2)                      /**< Indicate if an option is unsafe to forward */
#define coap_msg_op_num_no_cache_key(num)      ((num & 0x1e) == 0x1c)           /**< Indicate if an option is not part of the cache key */

#define coap_msg_op_get_num(op)                ((op)->num)                      /**< Get the option number from an option */
#define coap_msg_op_set_num(op, num)           ((op)->num = (num))              /**< Set the option number in an option */
#define coap_msg_op_get_len(op)                ((op)->len)                      /**< Get the option length from an option */
#define coap_msg_op_set_len(op, len)           ((op)->len = (len))              /**< Set the option length in an option */
#define coap_msg_op_get_val(op)                ((op)->val)                      /**< Get the option value from an option */
#define coap_msg_op_set_val(op, val)           ((op)->val = (val))              /**< Set the option value in an option */
#define coap_msg_op_get_next(op)               ((op)->next)                     /**< Get the next pointer from an option */
#define coap_msg_op_set_next(op, next_op)      ((op)->next = (next_op))         /**< Set the next pointer in an option */

#define coap_msg_get_ver(msg)                  ((msg)->ver)                     /**< Get the version from a message */
#define coap_msg_get_type(msg)                 ((msg)->type)                    /**< Get the type from a message */
#define coap_msg_get_token_len(msg)            ((msg)->token_len)               /**< Get the token length from a message */
#define coap_msg_get_code_class(msg)           ((msg)->code_class)              /**< Get the code class from a message */
#define coap_msg_get_code_detail(msg)          ((msg)->code_detail)             /**< Get the code detail from a message */
#define coap_msg_get_msg_id(msg)               ((msg)->msg_id)                  /**< Get the message ID from message */
#define coap_msg_get_token(msg)                ((msg)->token)                   /**< Get the token from a message */
#define coap_msg_get_first_op(msg)             ((msg)->op_list.first)           /**< Get the first option from a message */
#define coap_msg_get_payload(msg)              ((msg)->payload)                 /**< Get the payload from a message */
#define coap_msg_get_payload_len(msg)          ((msg)->payload_len)             /**< Get the payload length from a message */
#define coap_msg_is_empty(msg)                 (((msg)->code_class == 0) && ((msg)->code_detail == 0))
                                                                                /**< Indicate if a message is empty */

/**
 *  @brief Message type enumeration
 */
typedef enum
{
    COAP_MSG_CON = 0x0,
    COAP_MSG_NON = 0x1,
    COAP_MSG_ACK = 0x2,
    COAP_MSG_RST = 0x3
}
coap_msg_type_t;

/**
 *  @brief Code class enumeration
 */
typedef enum
{
    COAP_MSG_REQ = 0,
    COAP_MSG_SUCCESS = 2,
    COAP_MSG_CLIENT_ERR = 4,
    COAP_MSG_SERVER_ERR = 5,
}
coap_msg_class_t;

/**
 *  @brief Code detail enumeration
 */
typedef enum
{
    COAP_MSG_GET = 1,
    COAP_MSG_POST = 2,
    COAP_MSG_PUT = 3,
    COAP_MSG_DELETE =4
}
coap_msg_method_t;

/**
 *  @brief Success response code detail enumeration
 */
typedef enum
{
    COAP_MSG_CREATED = 1,
    COAP_MSG_DELETED = 2,
    COAP_MSG_VALID = 3,
    COAP_MSG_CHANGED = 4,
    COAP_MSG_CONTENT = 5
}
coap_msg_success_t;

/**
 *  @brief Client error response code detail enumeration
 */
typedef enum
{
    COAP_MSG_BAD_REQ = 0,
    COAP_MSG_UNAUTHORIZED = 1,
    COAP_MSG_BAD_OPTION = 2,
    COAP_MSG_FORBIDDEN = 3,
    COAP_MSG_NOT_FOUND = 4,
    COAP_MSG_METHOD_NOT_ALLOWED = 5,
    COAP_MSG_NOT_ACCEPTABLE = 6,
    COAP_MSG_PRECOND_FAILED = 12,
    COAP_MSG_REQ_ENT_TOO_LARGE = 13,
    COAP_MSG_UNSUP_CONT_FMT = 15
}
coap_msg_client_err_t;

/**
 *  @brief Server error response code detail enumeration
 */
typedef enum
{
    COAP_MSG_INT_SERVER_ERR = 0,
    COAP_MSG_NOT_IMPL = 1,
    COAP_MSG_BAD_GATEWAY = 2,
    COAP_MSG_SERV_UNAVAIL = 3,
    COAP_MSG_GATEWAY_TIMEOUT = 4,
    COAP_MSG_PROXY_NOT_SUP = 5
}
coap_msg_server_err_t;

/**
 *  @brief Option structure
 */
typedef struct coap_msg_op
{
    unsigned num;
    unsigned len;
    char *val;
    struct coap_msg_op *next;
}
coap_msg_op_t;

/**
 *  @brief Option linked-list structure
 */
typedef struct
{
    coap_msg_op_t *first;
    coap_msg_op_t *last;
}
coap_msg_op_list_t;

/**
 *  @brief Message structure
 */
typedef struct
{
    unsigned ver;
    coap_msg_type_t type;
    unsigned token_len;
    unsigned code_class;
    unsigned code_detail;
    unsigned msg_id;
    char token[COAP_MSG_MAX_TOKEN_LEN];
    coap_msg_op_list_t op_list;
    char *payload;
    unsigned payload_len;
}
coap_msg_t;

/**
 *  @brief Generate a random string of bytes
 *
 *  @param[out] buf Pointer to the buffer to store the random string
 *  @param[in] len Length of the buffer
 */
void coap_msg_gen_rand_str(char *buf, unsigned len);

/**
 *  @brief Initialise a message structure
 *
 *  @param[out] msg Pointer to a message structure
 */
void coap_msg_create(coap_msg_t *msg);

/**
 *  @brief Deinitialise a message structure
 *
 *  @param[in] msg Pointer to a message structure
 */
void coap_msg_destroy(coap_msg_t *msg);

/**
 *  @brief Deinitialise and initialise a message structure
 *
 *  @param[out] msg Pointer to a message structure
 */
void coap_msg_reset(coap_msg_t *msg);

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
 *  @retval -EBADMSG The message is corrupt
 */
int coap_msg_parse_type_msg_id(char *buf, unsigned len, unsigned *type, unsigned *msg_id);

/**
 *  @brief Parse a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -EINVAL Invalid argument
 *  @retval -ENOMEM Out-of-memory
 *  @retval -EBADMSG The message is corrupt
 */
int coap_msg_parse(coap_msg_t *msg, char *buf, unsigned len);

/**
 *  @brief Set the type in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] type Message type
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -EINVAL Invalid argument
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
 *  @retval -EINVAL Invalid argument
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
 *  @retval -EINVAL Invalid argument
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
 *  @retval -EINVAL Invalid argument
 */
int coap_msg_set_token(coap_msg_t *msg, char *buf, unsigned len);

/**
 *  @brief Add a token to a message structure
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] num Option number
 *  @param[in] len Option length
 *  @param[in] val Pointer to a buffer containing the option value
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -ENOMEM Out-of-memory
 */
int coap_msg_add_op(coap_msg_t *msg, unsigned num, unsigned len, char *val);

/**
 *  @brief Set the payload in a message
 *
 *  Free the buffer in the message structure containing
 *  the current payload if there is one, allocate a buffer
 *  to contain the new payload and copy the buffer argument
 *  into the new payload buffer.
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the payload
 *  @param[in] len Length of the buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -ENOMEM Out-of-memory
 */
int coap_msg_set_payload(coap_msg_t *msg, char *buf, unsigned len);

/**
 *  @brief Format a message
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Operation status
 *  @retval >0 Length of the formatted message
 *  @retval -ENOSPC Insufficient buffer length
 *  @retval -EBADMSG Message is corrupt
 */
int coap_msg_format(coap_msg_t *msg, char *buf, unsigned len);

/**
 *  @brief Copy a message
 *
 *  @param[out] dst Pointer to the destination message structure
 *  @param[in] src Pointer to the source message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -EINVAL Invalid argument
 *  @retval -ENOMEM Out-of-memory
 */
int coap_msg_copy(coap_msg_t *dst, coap_msg_t *src);

#endif
