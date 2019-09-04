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
 *  @file param.h
 *
 *  @brief Include file for the FreeCoAP HTTP/CoAP proxy parameter module
 */

#ifndef PARAM_H
#define PARAM_H

#include "coap_log.h"

#define PARAM_DEF_PORT                                "4430"
#define PARAM_DEF_MAX_LOG_LEVEL                       "info"
#define PARAM_DEF_HTTP_SERVER_TRUST_FILE_NAME         "http_server_trust.pem"   /**< TLS trust file name */
#define PARAM_DEF_HTTP_SERVER_CERT_FILE_NAME          "http_server_cert.pem"    /**< TLS certificate file name*/
#define PARAM_DEF_HTTP_SERVER_KEY_FILE_NAME           "http_server_privkey.pem" /**< TLS key file name */
#define PARAM_DEF_COAP_CLIENT_TRUST_FILE_NAME         "coap_client_trust.pem"   /**< DTLS trust file name */
#define PARAM_DEF_COAP_CLIENT_CERT_FILE_NAME          "coap_client_cert.pem"    /**< DTLS certificate file name */
#define PARAM_DEF_COAP_CLIENT_KEY_FILE_NAME           "coap_client_privkey.pem" /**< DTLS key file name */

#define param_get_port(param)                         ((param)->port)
#define param_get_max_log_level(param)                ((param)->max_log_level)
#define param_get_http_server_key_file_name(param)    ((param)->http_server_key_file_name)
#define param_get_http_server_cert_file_name(param)   ((param)->http_server_cert_file_name)
#define param_get_http_server_trust_file_name(param)  ((param)->http_server_trust_file_name)
#define param_get_coap_client_key_file_name(param)    ((param)->coap_client_key_file_name)
#define param_get_coap_client_cert_file_name(param)   ((param)->coap_client_cert_file_name)
#define param_get_coap_client_trust_file_name(param)  ((param)->coap_client_trust_file_name)

typedef struct
{
    char *port;
    coap_log_level_t max_log_level;
    char *http_server_key_file_name;
    char *http_server_cert_file_name;
    char *http_server_trust_file_name;
    char *coap_client_key_file_name;
    char *coap_client_cert_file_name;
    char *coap_client_trust_file_name;
}
param_t;

int param_create(param_t *param, const char *file_name);
void param_destroy(param_t *param);

#endif
