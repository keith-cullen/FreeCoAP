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
#include "coap_client.h"
#include "coap_log.h"

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

int test_con(void)
{
    coap_client_t client = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    char *payload = "Hello, Server!";
    int pass = 1;
    int ret = 0;

    printf("==================================================\n");
    printf("Confirmable request test\n");
    printf("==================================================\n");

    ret = coap_client_create(&client, HOST, PORT);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        return -1;
    }
    coap_msg_create(&req);
    ret = coap_msg_set_type(&req, COAP_MSG_CON);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }
    ret = coap_msg_set_code(&req, COAP_MSG_REQ, COAP_MSG_GET);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }
    ret = coap_msg_set_payload(&req, payload, strlen(payload));
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }
    coap_msg_create(&resp);
    ret = coap_client_exchange(&client, &req, &resp);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }

    printf("Sent:\n");
    print_coap_msg(&req);
    printf("\nReceived:\n");
    print_coap_msg(&resp);

    if (coap_msg_get_ver(&req) != coap_msg_get_ver(&resp))
    {
        pass = 0;
    }
    if (coap_msg_get_token_len(&req) != coap_msg_get_token_len(&resp))
    {
        pass = 0;
    }
    else
    {
        if (memcmp(coap_msg_get_token(&req), coap_msg_get_token(&resp), coap_msg_get_token_len(&req)) != 0)
        {
            pass = 0;
        }
    }
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    coap_client_destroy(&client);
    return pass;
}

int test_non(void)
{
    coap_client_t client = {0};
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    char *payload = "Hello, Server!";
    int pass = 1;
    int ret = 0;

    printf("==================================================\n");
    printf("Non-confirmable request test\n");
    printf("==================================================\n");

    ret = coap_client_create(&client, HOST, PORT);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        return -1;
    }
    coap_msg_create(&req);
    ret = coap_msg_set_type(&req, COAP_MSG_NON);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }
    ret = coap_msg_set_code(&req, COAP_MSG_REQ, COAP_MSG_GET);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }
    ret = coap_msg_set_payload(&req, payload, strlen(payload));
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }
    coap_msg_create(&resp);
    ret = coap_client_exchange(&client, &req, &resp);
    if (ret != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(-ret));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        coap_client_destroy(&client);
        return -1;
    }

    printf("Sent:\n");
    print_coap_msg(&req);
    printf("Received:\n");
    print_coap_msg(&resp);

    if (coap_msg_get_ver(&req) != coap_msg_get_ver(&resp))
    {
        pass = 0;
    }
    if (coap_msg_get_token_len(&req) != coap_msg_get_token_len(&resp))
    {
        pass = 0;
    }
    else
    {
        if (memcmp(coap_msg_get_token(&req), coap_msg_get_token(&resp), coap_msg_get_token_len(&req)) != 0)
        {
            pass = 0;
        }
    }
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    coap_client_destroy(&client);
    return pass;
}

int main(void)
{
    int con_result = 0;
    int non_result = 0;

    coap_log_set_level(COAP_LOG_INFO);

    con_result = test_con();
    non_result = test_non();

    printf("==================================================\n");
    printf("Confirmable request test result: %s\n", (con_result == 1) ? "pass" : "fail");
    printf("==================================================\n");

    printf("==================================================\n");
    printf("Non-confirmable request test result: %s\n", (non_result == 1) ? "pass" : "fail");
    printf("==================================================\n");

    return 0;
}
