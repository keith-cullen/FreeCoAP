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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "coap_server.h"

#define HOST  "127.0.0.1"
#define PORT  12436

static void print_coap_msg(coap_msg_t *msg)
{
    coap_msg_op_t *op = NULL;
    unsigned num = 0;
    unsigned len = 0;
    unsigned i = 0;
    unsigned j = 0;
    char *payload = NULL;
    char *token = NULL;
    char *val = NULL;

    printf("ver:         0x%02x\n", coap_msg_get_ver(msg));
    printf("type:        0x%02x\n", coap_msg_get_type(msg));
    printf("token_len:   %d\n", coap_msg_get_token_len(msg));
    printf("code_class:  %d\n", coap_msg_get_code_class(msg));
    printf("code_detail: %d\n", coap_msg_get_code_detail(msg));
    printf("msg_id:      0x%04x\n", coap_msg_get_msg_id(msg));
    printf("token:      ");
    token = coap_msg_get_token(msg);
    for (i = 0; i < coap_msg_get_token_len(msg); i++)
    {
        printf(" 0x%02x", (unsigned char)token[i]);
    }
    printf("\n");
    op = coap_msg_op_list_get_first(&msg->op_list);
    while (op != NULL)
    {
        num = coap_msg_op_get_num(op);
        len = coap_msg_op_get_len(op);
        val = coap_msg_op_get_val(op);
        printf("op[%u].num:   %u\n", j, num);
        printf("op[%u].len:   %u\n", j, len);
        printf("op[%u].val:  ", j);
        for (i = 0; i < len; i++)
        {
            printf(" 0x%02x", (unsigned char)val[i]);
        }
        printf("\n");
        op = coap_msg_op_get_next(op);
        j++;
    }
    printf("payload:     ");
    payload = coap_msg_get_payload(msg);
    for (i = 0; i < coap_msg_get_payload_len(msg); i++)
    {
        printf("%c", payload[i]);
    }
    printf("\n");
    printf("payload_len: %d\n", coap_msg_get_payload_len(msg));
}

/* the handler function is called to service a request
 * and produce a response, this function should only set
 * the code and payload fields in the response message,
 * the other fields are set by the server library when
 * this function returns
 */
int handle(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    char *payload = "Hello, Client!";
    int ret = 0;

    ret = coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
    if (ret < 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        return ret;
    }
    ret = coap_msg_set_payload(resp, payload, strlen(payload));
    if (ret < 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        return ret;
    }
    printf("Received:\n");
    print_coap_msg(req);
    printf("\nSent: (Note: the type, message ID and token fields have not been set by the server library yet)\n");
    print_coap_msg(resp);
    return 0;
}

int main()
{
    coap_server_t server = {0};
    int ret = 0;

    ret = coap_server_create(&server, HOST, PORT, handle);
    if (ret < 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        return -1;
    }
    ret = coap_server_run(&server);
    if (ret < 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        return -1;
    }
    coap_server_destroy(&server);
    return 0;
}
