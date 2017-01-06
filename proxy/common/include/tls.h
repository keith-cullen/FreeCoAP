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
 *  @file tls.h
 *
 *  @brief Include file for the FreeCoAP TLS library
 */

#ifndef TLS_H
#define TLS_H

#include <stddef.h>         /* size_t */
#include <gnutls/gnutls.h>
#include "sock.h"           /* error codes */
#include "lock.h"           /* lock_t */

#define TLS_CLIENT_MAX_SESSION_DATA_SIZE  2048
#define TLS_CLIENT_CACHE_SIZE               50
#define TLS_CLIENT_NUM_DH_BITS            1024

#define TLS_SERVER_MAX_SESSION_ID_SIZE      32
#define TLS_SERVER_MAX_SESSION_DATA_SIZE  2048
#define TLS_SERVER_CACHE_SIZE               50
#define TLS_SERVER_NUM_DH_BITS            1024

#define tls_client_get_cred(client)  ((client)->cred)
#define tls_server_get_cred(server)  ((server)->cred)

typedef struct
{
    char addr[SOCK_INET_ADDRSTRLEN];
    unsigned char session_data[TLS_CLIENT_MAX_SESSION_DATA_SIZE];
    size_t session_data_size;
}
tls_client_cache_element_t;

typedef struct
{
    tls_client_cache_element_t *element;
    size_t size;
    unsigned index;
}
tls_client_cache_t;

typedef struct
{
    gnutls_certificate_credentials_t cred;
#ifdef TLS_CLIENT_AUTH
    gnutls_dh_params_t dh_params;
#endif
    tls_client_cache_t cache;
    lock_t lock;
}
tls_client_t;

typedef struct
{
    unsigned char session_id[TLS_SERVER_MAX_SESSION_ID_SIZE];
    unsigned char session_data[TLS_SERVER_MAX_SESSION_DATA_SIZE];
    size_t session_id_size;
    size_t session_data_size;
}
tls_server_cache_element_t;

typedef struct
{
    tls_server_cache_element_t *element;
    size_t size;
    unsigned index;
}
tls_server_cache_t;

typedef struct
{
    gnutls_certificate_credentials_t cred;
    gnutls_dh_params_t dh_params;
    tls_server_cache_t cache;
    lock_t lock;
}
tls_server_t;

int tls_init(void);
void tls_deinit(void);
gnutls_priority_t tls_get_priority_cache(void);

int tls_client_create(tls_client_t *client, const char *trust_file_name, const char *cert_file_name, const char *key_file_name);
void tls_client_destroy(tls_client_t *client);
int tls_client_set(tls_client_t *client, char *addr, gnutls_datum_t data);
gnutls_datum_t tls_client_get(tls_client_t *client, char *addr);

int tls_server_create(tls_server_t *server, const char *trust_file_name, const char *cert_file_name, const char *key_file_name);
void tls_server_destroy(tls_server_t *server);
int tls_server_set(void *buf, gnutls_datum_t key, gnutls_datum_t data);
gnutls_datum_t tls_server_get(void *buf, gnutls_datum_t key);
int tls_server_delete(void *buf, gnutls_datum_t key);

#endif
