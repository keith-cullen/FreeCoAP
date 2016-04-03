/*
 * Copyright (c) 2009 Keith Cullen.
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
 *  @file sock.h
 *
 *  @brief Include file for the FreeCoAP socket library
 */

#ifndef SOCK_H
#define SOCK_H

#define SOCK_OK                               0
#define SOCK_INTR                            -1
#define SOCK_TIMEOUT                         -2
#define SOCK_MEM_ALLOC_ERROR                 -3
#define SOCK_TYPE_ERROR                      -4
#define SOCK_ARG_ERROR                       -5
#define SOCK_OPEN_ERROR                      -6
#define SOCK_CONFIG_ERROR                    -7
#define SOCK_ADDR_ERROR                      -8
#define SOCK_BIND_ERROR                      -9
#define SOCK_LISTEN_ERROR                   -10
#define SOCK_ACCEPT_ERROR                   -11
#define SOCK_CONNECT_ERROR                  -12
#define SOCK_READ_ERROR                     -13
#define SOCK_WRITE_ERROR                    -14
#define SOCK_SSL_INIT_ERROR                 -15
#define SOCK_SSL_TRUST_ERROR                -16
#define SOCK_SSL_CERT_ERROR                 -17
#define SOCK_SSL_KEY_ERROR                  -18
#define SOCK_SSL_CONFIG_ERROR               -19
#define SOCK_SSL_HANDSHAKE_ERROR            -20
#define SOCK_SSL_CACHE_ERROR                -21
#define SOCK_TLS_INIT_ERROR                 -22
#define SOCK_TLS_TRUST_ERROR                -23
#define SOCK_TLS_CRED_ERROR                 -24
#define SOCK_TLS_CONFIG_ERROR               -25
#define SOCK_TLS_HANDSHAKE_ERROR            -26
#define SOCK_TLS_REHANDSHAKE_REFUSED_ERROR  -27
#define SOCK_TLS_WARNING_ALERT              -28
#define SOCK_TLS_CACHE_ERROR                -29
#define SOCK_PEER_CERT_VERIFY_ERROR         -30
#define SOCK_CLOSE_ERROR                    -31
#define SOCK_LOCK_ERROR                     -32
#define SOCK_NUM_ERRORS                      33

const char *sock_strerror(int error);

#endif
