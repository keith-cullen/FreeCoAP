/*
 * Copyright (c) 2019 Keith Cullen.
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
#include "transfer_server.h"

#define KEY_FILE_NAME    "../../certs/server_privkey.pem"
#define CERT_FILE_NAME   "../../certs/server_cert.pem"
#define TRUST_FILE_NAME  "../../certs/root_client_cert.pem"
#define CRL_FILE_NAME    ""

int main(int argc, char **argv)
{
    transfer_server_t server = {0};
    int ret = 0;

    if (argc != 3)
    {
        fprintf(stderr, "usage: transfer_server host port\n");
        fprintf(stderr, "    host: IP address or host name to listen on (0.0.0.0 to listen on all interfaces)\n");
        fprintf(stderr, "    port: port number to listen on\n");
        return EXIT_FAILURE;
    }
    ret = transfer_server_init();
    if (ret < 0)
    {
        return EXIT_FAILURE;
    }
    ret = transfer_server_create(&server,
                            argv[1],
                            argv[2],
                            KEY_FILE_NAME,
                            CERT_FILE_NAME,
                            TRUST_FILE_NAME,
                            CRL_FILE_NAME);
    if (ret < 0)
    {
        transfer_server_deinit();
        return EXIT_FAILURE;
    }
    ret = transfer_server_run(&server);
    transfer_server_destroy(&server);
    transfer_server_deinit();
    if (ret < 0)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
