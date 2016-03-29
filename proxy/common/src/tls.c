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
 *  @brief Include file for the FreeCoAP TLS client/server library
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#include "tls.h"
#include "util.h"

#include <stdio.h>

#define TLS_CLIENT_CACHE_SIZE        50
#define TLS_SERVER_CACHE_SIZE        50
#define TLS_MAX_SESSION_ID_SIZE      32
#define TLS_MAX_SESSION_DATA_SIZE  2048

typedef struct
{
    char addr[INET6_ADDRSTRLEN];
    unsigned char session_data[TLS_MAX_SESSION_DATA_SIZE];
    size_t session_data_size;
}
tls_client_cache_element_t;

typedef struct
{
    unsigned char session_id[TLS_MAX_SESSION_ID_SIZE];
    unsigned char session_data[TLS_MAX_SESSION_DATA_SIZE];
    size_t session_id_size;
    size_t session_data_size;
}
tls_server_cache_element_t;

#define TLS_CLIENT_NUM_DH_BITS 1024
#define TLS_SERVER_NUM_DH_BITS 1024

static int _tls_init = 0;
static int _tls_client_init = 0;
static int _tls_server_init = 0;
static int _tls_client_cache_init = 0;
static int _tls_server_cache_init = 0;
static gnutls_priority_t _tls_priority_cache = NULL;
static gnutls_certificate_credentials_t _tls_client_cred = NULL;
static gnutls_certificate_credentials_t _tls_server_cred = NULL;
#ifdef TLS_CLIENT_AUTH
static gnutls_dh_params_t _tls_client_dh_params = NULL;
#endif
static gnutls_dh_params_t _tls_server_dh_params = NULL;
static tls_client_cache_element_t *_tls_client_cache = NULL;
static int _tls_client_cache_index = 0;
static tls_server_cache_element_t *_tls_server_cache = NULL;
static int _tls_server_cache_index = 0;

static int tls_client_cache_init();
static void tls_client_cache_deinit();
static int tls_server_cache_init();
static void tls_server_cache_deinit();

int tls_init()
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

void tls_deinit()
{
    if (_tls_init)
    {
        gnutls_priority_deinit(_tls_priority_cache);
        gnutls_global_deinit();
        _tls_init = 0;
    }
}

gnutls_priority_t tls_priority_cache()
{
    if (!_tls_init)
        return NULL;
    return _tls_priority_cache;
}

int tls_client_init(const char *trust_file_name, const char *cert_file_name, const char *key_file_name)
{
    int ret = 0;

    if (_tls_client_init)
    {
        return SOCK_OK;
    }

    ret = tls_init();
    if (ret != SOCK_OK)
    {
        return ret;
    }

    ret = gnutls_certificate_allocate_credentials(&_tls_client_cred);
    if (ret != GNUTLS_E_SUCCESS)
    {
        return SOCK_TLS_INIT_ERROR;
    }

    ret = gnutls_certificate_set_x509_trust_file(_tls_client_cred, trust_file_name, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
    {
        gnutls_certificate_free_credentials(_tls_client_cred);
        _tls_client_cred = NULL;
        return SOCK_TLS_TRUST_ERROR;
    }

#ifdef TLS_CLIENT_AUTH
    if ((cert_file_name != NULL) && (key_file_name != NULL))
    {
        ret = gnutls_certificate_set_x509_key_file(_tls_client_cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_certificate_free_credentials(_tls_client_cred);
            _tls_client_cred = NULL;
            return SOCK_TLS_CRED_ERROR;
        }

        ret = gnutls_dh_params_init(&_tls_client_dh_params);
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_certificate_free_credentials(_tls_client_cred);
            _tls_client_cred = NULL;
            return SOCK_TLS_INIT_ERROR;
        }

        ret = gnutls_dh_params_generate2(_tls_client_dh_params, TLS_CLIENT_NUM_DH_BITS);
        if (ret != GNUTLS_E_SUCCESS)
        {
            gnutls_dh_params_deinit(_tls_client_dh_params);
            gnutls_certificate_free_credentials(_tls_client_cred);
            _tls_client_dh_params = NULL;
            _tls_client_cred = NULL;
            return SOCK_TLS_INIT_ERROR;
        }

        gnutls_certificate_set_dh_params(_tls_client_cred, _tls_client_dh_params);
    }
#endif

    ret = tls_client_cache_init();
    if (ret != SOCK_OK)
    {
#ifdef TLS_CLIENT_AUTH
        if (_tls_client_dh_params != NULL)
        {
            gnutls_dh_params_deinit(_tls_client_dh_params);
            _tls_client_dh_params = NULL;
        }
#endif
        gnutls_certificate_free_credentials(_tls_client_cred);
        _tls_client_cred = NULL;
        return ret;
    }

    _tls_client_init = 1;
    return SOCK_OK;
}

void tls_client_deinit()
{
    if (_tls_client_init)
    {
        gnutls_certificate_free_credentials(_tls_client_cred);
        tls_client_cache_deinit();
        _tls_client_cred = NULL;
        _tls_client_init = 0;
    }
}

gnutls_certificate_credentials_t tls_client_cred()
{
    return _tls_client_cred;
}

int tls_server_init(const char *trust_file_name, const char *cert_file_name, const char *key_file_name)
{
    int ret = 0;

    if (_tls_server_init)
    {
        return SOCK_OK;
    }

    ret = tls_init();
    if (ret != SOCK_OK)
    {
        return ret;
    }

    ret = gnutls_certificate_allocate_credentials(&_tls_server_cred);
    if (ret != GNUTLS_E_SUCCESS)
    {
        return SOCK_TLS_INIT_ERROR;
    }

#ifdef TLS_CLIENT_AUTH
    if (trust_file_name != NULL)
    {
        ret = gnutls_certificate_set_x509_trust_file(_tls_server_cred, trust_file_name, GNUTLS_X509_FMT_PEM);
        if (ret < 0)
        {
            gnutls_certificate_free_credentials(_tls_server_cred);
            _tls_server_cred = NULL;
            return SOCK_TLS_TRUST_ERROR;
        }
    }
#endif

#if 0
    /* set certificate revocation list */
    ret = gnutls_certificate_set_x509_crl_file(_tls_server_cred, trust_file_name, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
    {
        gnutls_certificate_free_credentials(_tls_server_cred);
        _tls_server_cred = NULL;
        return SOCK_TLS_CRED_ERROR;
    }
#endif

    ret = gnutls_certificate_set_x509_key_file(_tls_server_cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_certificate_free_credentials(_tls_server_cred);
        _tls_server_cred = NULL;
        return SOCK_TLS_CRED_ERROR;
    }

    ret = gnutls_dh_params_init(&_tls_server_dh_params);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_certificate_free_credentials(_tls_server_cred);
        _tls_server_cred = NULL;
        return SOCK_TLS_INIT_ERROR;
    }

    ret = gnutls_dh_params_generate2(_tls_server_dh_params, TLS_SERVER_NUM_DH_BITS);
    if (ret != GNUTLS_E_SUCCESS)
    {
        gnutls_dh_params_deinit(_tls_server_dh_params);
        gnutls_certificate_free_credentials(_tls_server_cred);
        _tls_server_dh_params = NULL;
        _tls_server_cred = NULL;
        return SOCK_TLS_INIT_ERROR;
    }

    gnutls_certificate_set_dh_params(_tls_server_cred, _tls_server_dh_params);

    ret = tls_server_cache_init();
    if (ret != SOCK_OK)
    {
        gnutls_dh_params_deinit(_tls_server_dh_params);
        gnutls_certificate_free_credentials(_tls_server_cred);
        _tls_server_dh_params = NULL;
        _tls_server_cred = NULL;
        return ret;
    }

    _tls_server_init = 1;

    return SOCK_OK;
}

void tls_server_deinit()
{
    if (_tls_server_init)
    {
        gnutls_dh_params_deinit(_tls_server_dh_params);
        gnutls_certificate_free_credentials(_tls_server_cred);
        tls_server_cache_deinit();
        _tls_server_dh_params = NULL;
        _tls_server_cred = NULL;
        _tls_server_init = 0;
    }
}

gnutls_certificate_credentials_t tls_server_cred()
{
    return _tls_server_cred;
}

int tls_client_cache_init()
{
    if (!_tls_client_cache_init)
    {
        _tls_client_cache = (tls_client_cache_element_t *)calloc(TLS_CLIENT_CACHE_SIZE, sizeof(tls_client_cache_element_t));
        if (_tls_client_cache == NULL)
            return SOCK_MEM_ALLOC_ERROR;
        _tls_client_cache_init = 1;
    }
    return SOCK_OK;
}

void tls_client_cache_deinit()
{
    if (_tls_client_cache_init)
    {
        free(_tls_client_cache);
        _tls_client_cache = NULL;
        _tls_client_cache_init = 0;
    }
}

int tls_client_cache_set(char *addr, gnutls_datum_t data)
{
    int found = 0;
    int i = 0;

    if (!_tls_client_cache_init)
        return -1;
    if (data.size > TLS_MAX_SESSION_DATA_SIZE)
        return -1;

    found = 0;
    for (i = 0; i < TLS_CLIENT_CACHE_SIZE; i++)
    {
        if (strcmp(addr, _tls_client_cache[i].addr) == 0)
        {
            found = 1;
            break;
        }
    }
    if (!found)
    {
        i = _tls_client_cache_index++;
        _tls_client_cache_index %= TLS_CLIENT_CACHE_SIZE;
    }

    util_strncpy(_tls_client_cache[i].addr, addr, INET6_ADDRSTRLEN);
    memcpy(_tls_client_cache[i].session_data, data.data, data.size);
    _tls_client_cache[i].session_data_size = data.size;

    return 0;
}

gnutls_datum_t tls_client_cache_get(char *addr)
{
    gnutls_datum_t res = {0};
    int i = 0;

    res.data = NULL;
    res.size = 0;

    if (!_tls_client_cache_init)
        return res;

    for (i = 0; i < TLS_CLIENT_CACHE_SIZE; i++)
    {
        if (strcmp(addr, _tls_client_cache[i].addr) == 0)
        {
            res.data = _tls_client_cache[i].session_data;
            res.size = _tls_client_cache[i].session_data_size;
            return res;
        }
    }
    return res;
}

int tls_server_cache_init()
{
    if (!_tls_server_cache_init)
    {
        _tls_server_cache = (tls_server_cache_element_t *)calloc(1, TLS_SERVER_CACHE_SIZE * sizeof(tls_server_cache_element_t));
        if (_tls_server_cache == NULL)
            return SOCK_MEM_ALLOC_ERROR;
        _tls_server_cache_init = 1;
    }
    return SOCK_OK;
}

void tls_server_cache_deinit()
{
    if (_tls_server_cache_init)
    {
        free(_tls_server_cache);
        _tls_server_cache = NULL;
        _tls_server_cache_init = 0;
    }
}

int tls_server_cache_set(void *buf, gnutls_datum_t key, gnutls_datum_t data)
{
    if (!_tls_server_cache_init)
        return -1;
    if (key.size > TLS_MAX_SESSION_ID_SIZE)
        return -1;
    if (data.size > TLS_MAX_SESSION_DATA_SIZE)
        return -1;

    memcpy(_tls_server_cache[_tls_server_cache_index].session_id, key.data, key.size);
    _tls_server_cache[_tls_server_cache_index].session_id_size = key.size;

    memcpy(_tls_server_cache[_tls_server_cache_index].session_data, data.data, data.size);
    _tls_server_cache[_tls_server_cache_index].session_data_size = data.size;

    _tls_server_cache_index++;
    _tls_server_cache_index %= TLS_SERVER_CACHE_SIZE;

    return 0;
}

gnutls_datum_t tls_server_cache_get(void *buf, gnutls_datum_t key)
{
    gnutls_datum_t res = {0};
    int i = 0;

    res.data = NULL;
    res.size = 0;

    if (!_tls_server_cache_init)
        return res;

    for (i = 0; i < TLS_SERVER_CACHE_SIZE; i++)
    {
        if ((key.size == _tls_server_cache[i].session_id_size)
         && (memcmp(key.data, _tls_server_cache[i].session_id, key.size) == 0))
        {
            res.size = _tls_server_cache[i].session_data_size;
            res.data = (unsigned char *)gnutls_malloc(res.size);
            if (res.data == NULL)
                return res;
            memcpy(res.data, _tls_server_cache[i].session_data, res.size);
            return res;
        }
    }
    return res;
}

int tls_server_cache_delete(void *buf, gnutls_datum_t key)
{
    int i = 0;

    if (!_tls_server_cache_init)
        return -1;

    for (i = 0; i < TLS_SERVER_CACHE_SIZE; i++)
    {
        if ((key.size == _tls_server_cache[i].session_id_size)
         && (memcmp(key.data, _tls_server_cache[i].session_id, key.size) == 0))
        {
            _tls_server_cache[i].session_id_size = 0;
            _tls_server_cache[i].session_data_size = 0;
            return 0;
        }
    }
    return -1;
}
