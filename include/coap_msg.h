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

#ifndef COAP_MSG_H
#define COAP_MSG_H

#define COAP_MSG_VER                           0x01
#define COAP_MSG_MAX_TOKEN_LEN                 8
#define COAP_MSG_MAX_CODE_CLASS                7
#define COAP_MSG_MAX_CODE_DETAIL               31
#define COAP_MSG_MAX_MSG_ID                    ((1 << 16) - 1)

#define COAP_MSG_MAX_BUF_LEN                   1152

#define coap_msg_op_num_is_critical(num)       ((num) & 1)
#define coap_msg_op_num_is_unsafe(num)         ((num) & 2)
#define coap_msg_op_num_no_cache_key(num)      ((num & 0x1e) == 0x1c)

#define coap_msg_op_get_num(op)                ((op)->num)
#define coap_msg_op_set_num(op, num)           ((op)->num = (num))
#define coap_msg_op_get_len(op)                ((op)->len)
#define coap_msg_op_set_len(op, len)           ((op)->len = (len))
#define coap_msg_op_get_val(op)                ((op)->val)
#define coap_msg_op_set_val(op, val)           ((op)->val = (val))
#define coap_msg_op_get_next(op)               ((op)->next)
#define coap_msg_op_set_next(op, next_op)      ((op)->next = (next_op))

#define coap_msg_op_list_get_first(list)       ((list)->first)
#define coap_msg_op_list_get_last(list)        ((list)->last)
#define coap_msg_op_list_is_empty(list)        ((list)->first == NULL)

#define coap_msg_get_ver(msg)                  ((msg)->ver)
#define coap_msg_get_type(msg)                 ((msg)->type)
#define coap_msg_get_token_len(msg)            ((msg)->token_len)
#define coap_msg_get_code_class(msg)           ((msg)->code_class)
#define coap_msg_get_code_detail(msg)          ((msg)->code_detail)
#define coap_msg_get_msg_id(msg)               ((msg)->msg_id)
#define coap_msg_get_token(msg)                ((msg)->token)
#define coap_msg_get_first_op(msg)             ((msg)->op_list.first)
#define coap_msg_get_payload(msg)              ((msg)->payload)
#define coap_msg_get_payload_len(msg)          ((msg)->payload_len)
#define coap_msg_is_empty(msg)                 (((msg)->code_class == 0) && ((msg)->code_detail == 0))

typedef enum
{
    COAP_MSG_CON = 0x0,
    COAP_MSG_NON = 0x1,
    COAP_MSG_ACK = 0x2,
    COAP_MSG_RST = 0x3
}
coap_msg_type_t;

/* code class values */
typedef enum
{
    COAP_MSG_REQ = 0,
    COAP_MSG_SUCCESS = 2,
    COAP_MSG_CLIENT_ERR = 4,
    COAP_MSG_SERVER_ERR = 5,
}
coap_msg_class_t;

/* 0.xx code detail values */
typedef enum
{
    COAP_MSG_GET = 1,
    COAP_MSG_POST = 2,
    COAP_MSG_PUT = 3,
    COAP_MSG_DELETE =4
}
coap_msg_method_t;

/* 2.xx code detail values */
typedef enum
{
    COAP_MSG_CREATED = 1,
    COAP_MSG_DELETED = 2,
    COAP_MSG_VALID = 3,
    COAP_MSG_CHANGED = 4,
    COAP_MSG_CONTENT = 5
}
coap_msg_success_t;

/* 4.xx code detail values */
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

/* 5.xx code detail values */
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

typedef struct coap_msg_op
{
    unsigned num;
    unsigned len;
    char *val;
    struct coap_msg_op *next;
}
coap_msg_op_t;

typedef struct
{
    coap_msg_op_t *first;
    coap_msg_op_t *last;
}
coap_msg_op_list_t;

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

void coap_msg_gen_rand_str(char *buf, unsigned len);

coap_msg_op_t *coap_msg_op_new(unsigned num, unsigned len, char *val);
void coap_msg_op_delete(coap_msg_op_t *op);
unsigned coap_msg_op_calc_len(coap_msg_op_t *op);

void coap_msg_op_list_create(coap_msg_op_list_t *list);
void coap_msg_op_list_destroy(coap_msg_op_list_t *list);
int coap_msg_op_list_add(coap_msg_op_list_t *list, unsigned num, unsigned len, char *val);

void coap_msg_create(coap_msg_t *msg);
void coap_msg_destroy(coap_msg_t *msg);
void coap_msg_reset(coap_msg_t *msg);
int coap_msg_parse_type_msg_id(char *buf, unsigned len, unsigned *type, unsigned *msg_id);
int coap_msg_parse(coap_msg_t *msg, char *buf, unsigned len);

int coap_msg_set_hdr(coap_msg_t *msg, unsigned type, unsigned token_len, unsigned code_class, unsigned code_detail, unsigned msg_id);
int coap_msg_set_token(coap_msg_t *msg, char *buf, unsigned len);
int coap_msg_add_op(coap_msg_t *msg, unsigned num, unsigned len, char *val);
int coap_msg_set_payload(coap_msg_t *msg, char *buf, unsigned len);
int coap_msg_format(coap_msg_t *msg, char *buf, unsigned len);

#endif
