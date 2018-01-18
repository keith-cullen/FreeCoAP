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
#include <string.h>
#include <errno.h>
#include "registrar.h"

registrar_entry_t *registrar_entry_new(const char *id, const char *addr)
{
    registrar_entry_t *entry = NULL;

    entry = (registrar_entry_t *)malloc(sizeof(registrar_entry_t));
    if (entry == NULL)
    {
        return NULL;
    }
    strncpy(entry->id, id, sizeof(entry->id));
    entry->id[sizeof(entry->id) - 1] = '\0';
    strncpy(entry->addr, addr, sizeof(entry->addr));
    entry->addr[sizeof(entry->addr) - 1] = '\0';
    entry->prev = NULL;
    entry->next = NULL;
    return entry;
}

void registrar_entry_delete(registrar_entry_t *entry)
{
    free(entry);
}

void registrar_create(registrar_t *registrar)
{
    memset(registrar, 0, sizeof(registrar_t));
}

static void registrar_entry_set_addr(registrar_entry_t *entry, const char *addr)
{
    strncpy(entry->addr, addr, sizeof(entry->addr));
    entry->addr[sizeof(entry->addr) - 1] = '\0';
}

void registrar_destroy(registrar_t *registrar)
{
    registrar_entry_t *entry = NULL;
    registrar_entry_t *prev = NULL;

    entry = registrar->first;
    while (entry != NULL)
    {
        prev = entry;
        entry = registrar_entry_get_next(entry);
        registrar_entry_delete(prev);
    }
    memset(registrar, 0, sizeof(registrar_t));
}

registrar_entry_t *registrar_find(registrar_t *registrar, const char *id)
{
    registrar_entry_t *entry = NULL;

    entry = registrar->first;
    while (entry != NULL)
    {
        if (strcmp(entry->id, id) == 0)
        {
            return entry;
        }
        entry = registrar_entry_get_next(entry);
    }
    return NULL;
}

int registrar_add(registrar_t *registrar, const char *id, const char *addr)
{
    registrar_entry_t *entry = NULL;

    entry = registrar_find(registrar, id);
    if (entry != NULL)
    {
        /* already exists */
        registrar_entry_set_addr(entry, addr);
        return 1;
    }
    entry = registrar_entry_new(id, addr);
    if (entry == NULL)
    {
        return -ENOMEM;
    }
    if ((registrar->first == NULL) && (registrar->last == NULL))
    {
        registrar->first = entry;
        registrar->last = entry;
    }
    else
    {
        registrar_entry_set_prev(entry, registrar->last);
        registrar_entry_set_next(registrar->last, entry);
        registrar->last = entry;
    }
    return 0;
}

int registrar_del(registrar_t *registrar, const char *id)
{
    registrar_entry_t *entry = NULL;

    entry = registrar_find(registrar, id);
    if (entry == NULL)
    {
        return -EINVAL;
    }
    if (registrar->first == entry)
        registrar->first = registrar_entry_get_next(registrar->first);
    if (registrar->last == entry)
        registrar->last = registrar_entry_get_prev(registrar->last);
    registrar_entry_delete(entry);
    return 0;
}
