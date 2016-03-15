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
 *  @brief Include file for the FreeCoAP TLS client/server library
 */

#ifndef TLS_H
#define TLS_H

#include <gnutls/gnutls.h>
#include "sock.h"  /* error codes */

int tls_init();
void tls_deinit();
gnutls_priority_t tls_priority_cache();

int tls_client_init(const char *trust_file_name, const char *cert_file_name, const char *key_file_name);
void tls_client_deinit();
gnutls_certificate_credentials_t tls_client_cred();

int tls_server_init(const char *trust_file_name, const char *cert_file_name, const char *key_file_name);
void tls_server_deinit();
gnutls_certificate_credentials_t tls_server_cred();

int tls_client_cache_set(char *addr, gnutls_datum_t data);
gnutls_datum_t tls_client_cache_get(char *addr);

int tls_server_cache_set(void *buf, gnutls_datum_t key, gnutls_datum_t data);
gnutls_datum_t tls_server_cache_get(void *buf, gnutls_datum_t key);
int tls_server_cache_delete(void *buf, gnutls_datum_t key);

#endif
