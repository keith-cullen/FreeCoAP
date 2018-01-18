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

/**
 *  @file coap_ipv.h
 *
 *  @brief Include file for the FreeCoAP IP Version (IPv4/IPv6) abstraction layer
 */

#ifndef COAP_IPV_H
#define COAP_IPV_H

#include <netinet/in.h>

#ifdef COAP_IP6

#define COAP_IPV_AF_INET          AF_INET6
#define COAP_IPV_INET_ADDRSTRLEN  INET6_ADDRSTRLEN
#define COAP_IPV_SIN_ADDR         sin6_addr
#define COAP_IPV_SIN_PORT         sin6_port

typedef struct sockaddr_in6  coap_ipv_sockaddr_in_t;

#else  /* COAP_IP4 */

#define COAP_IPV_AF_INET          AF_INET
#define COAP_IPV_INET_ADDRSTRLEN  INET_ADDRSTRLEN
#define COAP_IPV_SIN_ADDR         sin_addr
#define COAP_IPV_SIN_PORT         sin_port

typedef struct sockaddr_in   coap_ipv_sockaddr_in_t;

#endif  /* COAP_IP6 */

#endif
