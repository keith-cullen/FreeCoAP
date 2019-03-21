/*
 * Copyright (c) 2017 Keith Cullen.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "reg_client.h"

#define KEY_FILE_NAME    "../../certs/client_privkey.pem"
#define CERT_FILE_NAME   "../../certs/client_cert.pem"
#define TRUST_FILE_NAME  "../../certs/root_server_cert.pem"
#define CRL_FILE_NAME    ""
#define COMMON_NAME      "dummy/server"
#define BUF_LEN          32

int main(int argc, char **argv)
{
    reg_client_t client = {0};
    size_t len = 0;
    char buf[BUF_LEN] = {0};
    int ret = 0;

    if (argc != 4)
    {
        fprintf(stderr, "usage: reg_client host port client id\n");
        fprintf(stderr, "    host: IP address or host name to connect to\n");
        fprintf(stderr, "    port: port number to connect to\n");
        fprintf(stderr, "    id: any opaque identifier to be sent to the server\n");
        return EXIT_FAILURE;
    }
    len = strlen(argv[3]);
    if ((len + 1) > sizeof(buf))
    {
        fprintf(stderr, "error: id value too long (max %zd)\n", sizeof(buf) - 1);
        return EXIT_FAILURE;
    }
    ret = reg_client_init();
    if (ret < 0)
    {
        return EXIT_FAILURE;
    }
    ret = reg_client_create(&client,
                            argv[1],
                            argv[2],
                            KEY_FILE_NAME,
                            CERT_FILE_NAME,
                            TRUST_FILE_NAME,
                            CRL_FILE_NAME,
                            COMMON_NAME);
    if (ret < 0)
    {
        reg_client_deinit();
        return EXIT_FAILURE;
    }
    memcpy(buf, argv[3], len);
    buf[len] = '\0';
    ret = reg_client_register(&client, buf, sizeof(buf));
    if (ret < 0)
    {
        reg_client_destroy(&client);
        reg_client_deinit();
        return EXIT_FAILURE;
    }
    reg_client_destroy(&client);
    reg_client_deinit();
    return EXIT_SUCCESS;
}
