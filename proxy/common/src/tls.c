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
 *  @file tls.c
 *
 *  @brief Include file for the FreeCoAP TLS library
 */

#include <stdlib.h>
#include <string.h>
#include "tls.h"
#include "util.h"

static int _tls_init = 0;
static gnutls_priority_t _tls_priority_cache = NULL;

int tls_init(void)
{
    int ret = 0;

    if (!_tls_init)
    {
        ret = gnutls_global_init();
        if (ret != GNUTLS_E_SUCCESS)
        {
            return SOCK_TLS_INIT_ERROR;
        }
        ret = gnutls_priority_init(&_tls_priority_cache, "NORMAL", NULL);
        if (ret != GNUTLS_E_SUCCESS)
        {
            return SOCK_TLS_INIT_ERROR;
        }
        _tls_init = 1;
    }
    return SOCK_OK;
}

void tls_deinit(void)
{
    if (_tls_init)
    {
        gnutls_priority_deinit(_tls_priority_cache);
        gnutls_global_deinit();
        _tls_init = 0;
    }
}

gnutls_priority_t tls_get_priority_cache(void)
{
    if (!_tls_init)
    {
        return NULL;
    }
    return _tls_priority_cache;
}

static int tls_client_cache_create(tls_client_cache_t *cache, size_t size)
{
    memset(cache, 0, sizeof(tls_client_cache_t));
    if (size == 0)
    {
        return SOCK_ARG_ERROR;
    }
    cache->element = (tls_client_cache_element_t *)calloc(size, sizeof(tls_client_cache_element_t));
    if (cache->element == NULL)
    {
        return SOCK_MEM_ALLOC_ERROR;
    }
    cache->size = size;
    cache->index = 0;
    return SOCK_OK;
}

static void tls_client_cache_destroy(tls_client_cache_t *cache)
{
    free(cache->element);
    memset(cache, 0, sizeof(tls_client_cache_t));
}

static int tls_client_cache_set(tls_client_cache_t *cache, char *addr, gnutls_datum_t data)
{
    unsigned i = 0;
    int found = 0;

    if (data.size > TLS_CLIENT_MAX_SESSION_DATA_SIZE)
    {
        return SOCK_TLS_CACHE_ERROR;
    }

    for (i = 0; i < cache->size; i++)
    {
        if (strcmp(addr, cache->element[i].addr) == 0)
        {
            found = 1;
            break;
        }
    }
    if (!found)
    {
        i = cache->index++;
        cache->index %= cache->size;
    }

    util_strncpy(cache->element[i].addr, addr, SOCK_INET_ADDRSTRLEN);
    memcpy(cache->element[i].session_data, data.data, data.size);
    cache->element[i].session_data_size = data.size;

    return SOCK_OK;
}

static gnutls_datum_t tls_client_cache_get(tls_client_cache_t *cache, char *addr)
{
    gnutls_datum_t res = {0};
    unsigned i = 0;

    for (i = 0; i < cache->size; i++)
    {
        if (strcmp(addr, cache->element[i].addr) == 0)
        {
            res.data = cache->element[i].session_data;
            res.size = cache->element[i].session_data_size;
            break;
        }
    }
    return res;
}

int tls_client_create(tls_client_t *client, const char *trust_file_name, const char *cert_file_name, const char *key_file_name)
{
    int ret = 0;

    memset(client, 0, sizeof(tls_client_t));

    ret = gnutls_certificate_allocate_credentials(&client->cred);
    if (ret != GNUTLS_E_SUCCESS)
    {
        memset(client, 0, sizeof(tls_client_t));
        return SOCK_TLS_INIT_ERROR;
    }

    ret = gnutls_certificate_set_x509_trust_file(client->cred, trust_file_name, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
    {
        gnutls_certificate_free_credentials(client->cred);
        memset(client, 0, sizeof(tls_client_t));
        return SOCK_TLS_TRUST_ERROR;
    }

#ifdef TLS_CLIENT_AUTH
    if ((cert_file_name != NULL) && (key_file_name != NULL))
    {
        ret = gnutls_certificate_set_x509_key_file(client->cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_certificate_free_credentials(client->cred);
            memset(client, 0, sizeof(tls_client_t));
            return SOCK_TLS_CRED_ERROR;
        }

        ret = gnutls_dh_params_init(&client->dh_params);
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_certificate_free_credentials(client->cred);
            memset(client, 0, sizeof(tls_client_t));
            return SOCK_TLS_INIT_ERROR;
        }

        ret = gnutls_dh_params_generate2(client->dh_params, TLS_CLIENT_NUM_DH_BITS);
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_dh_params_deinit(client->dh_params);
            gnutls_certificate_free_credentials(client->cred);
            memset(client, 0, sizeof(tls_client_t));
            return SOCK_TLS_INIT_ERROR;
        }

        gnutls_certificate_set_dh_params(client->cred, client->dh_params);
    }
#endif

    ret = tls_client_cache_create(&client->cache, TLS_CLIENT_CACHE_SIZE);
    if (ret != SOCK_OK)
    {
#ifdef TLS_CLIENT_AUTH
        if (client->dh_params != NULL)
        {
            gnutls_dh_params_deinit(client->dh_params);
        }
#endif
        gnutls_certificate_free_credentials(client->cred);
        memset(client, 0, sizeof(tls_client_t));
        return ret;
    }

    ret = lock_create(&client->lock);
    if (ret < 0)
    {
        tls_client_cache_destroy(&client->cache);
#ifdef TLS_CLIENT_AUTH
        if (client->dh_params != NULL)
        {
            gnutls_dh_params_deinit(client->dh_params);
        }
#endif
        gnutls_certificate_free_credentials(client->cred);
        memset(client, 0, sizeof(tls_client_t));
        return SOCK_LOCK_ERROR;
    }

    return SOCK_OK;
}

void tls_client_destroy(tls_client_t *client)
{
    lock_destroy(&client->lock);
    tls_client_cache_destroy(&client->cache);
#ifdef TLS_CLIENT_AUTH
    if (client->dh_params != NULL)
    {
        gnutls_dh_params_deinit(client->dh_params);
    }
#endif
    gnutls_certificate_free_credentials(client->cred);
    memset(client, 0, sizeof(tls_client_t));
}

int tls_client_set(tls_client_t *client, char *addr, gnutls_datum_t data)
{
    int status = 0;
    int ret = 0;

    ret = lock_get(&client->lock);
    if (ret < 0)
    {
        return SOCK_LOCK_ERROR;
    }
    status = tls_client_cache_set(&client->cache, addr, data);
    ret = lock_put(&client->lock);
    if (ret < 0)
    {
        return SOCK_LOCK_ERROR;
    }
    return status;
}

gnutls_datum_t tls_client_get(tls_client_t *client, char *addr)
{
    gnutls_datum_t res = {NULL, 0};
    int ret = 0;

    ret = lock_get(&client->lock);
    if (ret < 0)
    {
        return res;
    }
    res = tls_client_cache_get(&client->cache, addr);
    ret = lock_put(&client->lock);
    if (ret < 0)
    {
        res.size = 0;
    }
    return res;
}

static int tls_server_cache_create(tls_server_cache_t *cache, size_t size)
{
    memset(cache, 0, sizeof(tls_server_cache_t));
    if (size == 0)
    {
        return SOCK_ARG_ERROR;
    }
    cache->element = (tls_server_cache_element_t *)calloc(size, sizeof(tls_server_cache_element_t));
    if (cache->element == NULL)
    {
        return SOCK_MEM_ALLOC_ERROR;
    }
    cache->size = size;
    cache->index = 0;
    return SOCK_OK;
}

static void tls_server_cache_destroy(tls_server_cache_t *cache)
{
    free(cache->element);
    memset(cache, 0, sizeof(tls_server_cache_t));
}

static int tls_server_cache_set(tls_server_cache_t *cache, gnutls_datum_t key, gnutls_datum_t data)
{
    if ((key.size > TLS_SERVER_MAX_SESSION_ID_SIZE) || (data.size > TLS_SERVER_MAX_SESSION_DATA_SIZE))
    {
        return SOCK_TLS_CACHE_ERROR;
    }

    memcpy(cache->element[cache->index].session_id, key.data, key.size);
    cache->element[cache->index].session_id_size = key.size;

    memcpy(cache->element[cache->index].session_data, data.data, data.size);
    cache->element[cache->index].session_data_size = data.size;

    cache->index++;
    cache->index %= cache->size;

    return SOCK_OK;
}

static gnutls_datum_t tls_server_cache_get(tls_server_cache_t *cache, gnutls_datum_t key)
{
    gnutls_datum_t res = {NULL, 0};
    unsigned i = 0;

    res.data = NULL;
    res.size = 0;

    for (i = 0; i < cache->size; i++)
    {
        if ((key.size == cache->element[i].session_id_size)
         && (memcmp(key.data, cache->element[i].session_id, key.size) == 0))
        {
            res.size = cache->element[i].session_data_size;
            res.data = (unsigned char *)gnutls_malloc(res.size);
            if (res.data != NULL)
            {
                memcpy(res.data, cache->element[i].session_data, res.size);
            }
            break;
        }
    }
    return res;
}

static int tls_server_cache_delete(tls_server_cache_t *cache, gnutls_datum_t key)
{
    unsigned i = 0;

    for (i = 0; i < cache->size; i++)
    {
        if ((key.size == cache->element[i].session_id_size)
         && (memcmp(key.data, cache->element[i].session_id, key.size) == 0))
        {
            memset(&cache->element[i], 0, sizeof(tls_server_cache_element_t));
            return SOCK_OK;
        }
    }
    return SOCK_ARG_ERROR;
}

int tls_server_create(tls_server_t *server, const char *trust_file_name, const char *cert_file_name, const char *key_file_name)
{
    int ret = 0;

    memset(server, 0, sizeof(tls_server_t));

    ret = gnutls_certificate_allocate_credentials(&server->cred);
    if (ret != GNUTLS_E_SUCCESS)
    {
        memset(server, 0, sizeof(tls_server_t));
        return SOCK_TLS_INIT_ERROR;
    }

#ifdef TLS_CLIENT_AUTH
    if (trust_file_name != NULL)
    {
        ret = gnutls_certificate_set_x509_trust_file(server->cred, trust_file_name, GNUTLS_X509_FMT_PEM);
        if (ret < 0)
        {
            gnutls_certificate_free_credentials(server->cred);
            memset(server, 0, sizeof(tls_server_t));
            return SOCK_TLS_TRUST_ERROR;
        }
    }
#endif

#if 0
    /* set certificate revocation list */
    ret = gnutls_certificate_set_x509_crl_file(server->cred, trust_file_name, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
    {
        gnutls_certificate_free_credentials(server->cred);
        memset(server, 0, sizeof(tls_server_t));
        return SOCK_TLS_CRED_ERROR;
    }
#endif

    ret = gnutls_certificate_set_x509_key_file(server->cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_certificate_free_credentials(server->cred);
        memset(server, 0, sizeof(tls_server_t));
        return SOCK_TLS_CRED_ERROR;
    }

    ret = gnutls_dh_params_init(&server->dh_params);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_certificate_free_credentials(server->cred);
        memset(server, 0, sizeof(tls_server_t));
        return SOCK_TLS_INIT_ERROR;
    }

    ret = gnutls_dh_params_generate2(server->dh_params, TLS_SERVER_NUM_DH_BITS);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_dh_params_deinit(server->dh_params);
        gnutls_certificate_free_credentials(server->cred);
        memset(server, 0, sizeof(tls_server_t));
        return SOCK_TLS_INIT_ERROR;
    }

    gnutls_certificate_set_dh_params(server->cred, server->dh_params);

    ret = tls_server_cache_create(&server->cache, TLS_SERVER_CACHE_SIZE);
    if (ret != SOCK_OK)
    {
        gnutls_dh_params_deinit(server->dh_params);
        gnutls_certificate_free_credentials(server->cred);
        memset(server, 0, sizeof(tls_server_t));
        return ret;
    }

    ret = lock_create(&server->lock);
    if (ret < 0)
    {
        tls_server_cache_destroy(&server->cache);
        gnutls_dh_params_deinit(server->dh_params);
        gnutls_certificate_free_credentials(server->cred);
        memset(server, 0, sizeof(tls_server_t));
        return SOCK_LOCK_ERROR;
    }

    return SOCK_OK;
}

void tls_server_destroy(tls_server_t *server)
{
    lock_destroy(&server->lock);
    gnutls_dh_params_deinit(server->dh_params);
    gnutls_certificate_free_credentials(server->cred);
    tls_server_cache_destroy(&server->cache);
    memset(server, 0, sizeof(tls_server_t));
}

int tls_server_set(void *buf, gnutls_datum_t key, gnutls_datum_t data)
{
    int status = 0;
    int ret = 0;

    tls_server_t *server = (tls_server_t *)buf;
    ret = lock_get(&server->lock);
    if (ret < 0)
    {
        return SOCK_LOCK_ERROR;
    }
    status = tls_server_cache_set(&server->cache, key, data);
    ret = lock_put(&server->lock);
    if (ret < 0)
    {
        return SOCK_LOCK_ERROR;
    }
    return status;
}

gnutls_datum_t tls_server_get(void *buf, gnutls_datum_t key)
{
    gnutls_datum_t res = {0};
    int ret = 0;

    tls_server_t *server = (tls_server_t *)buf;
    ret = lock_get(&server->lock);
    if (ret < 0)
    {
        return res;
    }
    res = tls_server_cache_get(&server->cache, key);
    ret = lock_put(&server->lock);
    if (ret < 0)
    {
        res.size = 0;
    }
    return res;
}

int tls_server_delete(void *buf, gnutls_datum_t key)
{
    int status = 0;
    int ret = 0;

    tls_server_t *server = (tls_server_t *)buf;
    ret = lock_get(&server->lock);
    if (ret < 0)
    {
        return SOCK_LOCK_ERROR;
    }
    status =  tls_server_cache_delete(&server->cache, key);
    ret = lock_put(&server->lock);
    if (ret < 0)
    {
        return SOCK_LOCK_ERROR;
    }
    return status;
}
