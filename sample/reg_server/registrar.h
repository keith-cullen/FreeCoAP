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

#ifndef REGISTRAR_H
#define REGISTRAR_H

#include <arpa/inet.h>
#include "coap_ipv.h"

#define REGISTRAR_ID_MAX_BUF_LEN  32

#define registrar_entry_get_id(entry)            ((entry)->id)
#define registrar_entry_get_addr(entry)          ((entry)->addr)
#define registrar_entry_get_prev(entry)          ((entry)->prev)
#define registrar_entry_set_prev(entry, pentry)  ((entry)->prev = (pentry))
#define registrar_entry_get_next(entry)          ((entry)->next)
#define registrar_entry_set_next(entry, nentry)  ((entry)->next = (nentry))

#define registrar_get_first(registrar)           ((registrar)->first)
#define registrar_get_last(registrar)            ((registrar)->last)

typedef struct registrar_entry
{
    char id[REGISTRAR_ID_MAX_BUF_LEN];    /* must contain a null terminated string */
    char addr[COAP_IPV_INET_ADDRSTRLEN];  /* must contain a null terminated string */
    struct registrar_entry *prev;
    struct registrar_entry *next;
}
registrar_entry_t;

typedef struct
{
    registrar_entry_t *first;
    registrar_entry_t *last;
}
registrar_t;

registrar_entry_t *registrar_entry_new(const char *id, const char *addr);
void registrar_entry_delete(registrar_entry_t *entry);

void registrar_create(registrar_t *registrar);
void registrar_destroy(registrar_t *registrar);
registrar_entry_t *registrar_find(registrar_t *registrar, const char *id);
int registrar_add(registrar_t *registrar, const char *id, const char *addr);
int registrar_del(registrar_t *registrar, const char *id);

#endif
