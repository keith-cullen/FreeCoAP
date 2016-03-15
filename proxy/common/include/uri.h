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
 *  @file uri.h
 *
 *  @brief Include file for the FreeCoAP URI library
 */

#ifndef URI_H
#define URI_H

#define uri_get_scheme(uri)    ((uri)->scheme)                                  /**< Get the scheme from a URI */
#define uri_get_userinfo(uri)  ((uri)->userinfo)                                /**< Get the userinfo from a URI */
#define uri_get_host(uri)      ((uri)->host)                                    /**< Get the host from a URI */
#define uri_get_port(uri)      ((uri)->port)                                    /**< Get the port from a URI */
#define uri_get_path(uri)      ((uri)->path)                                    /**< Get the path from a URI */
#define uri_get_query(uri)     ((uri)->query)                                   /**< Get the query from a URI */
#define uri_get_fragment(uri)  ((uri)->fragment)                                /**< Get the fragment from a URI */

typedef struct
{
    char *scheme;                                                               /**< Scheme */
    char *userinfo;                                                             /**< User-Info */
    char *host;                                                                 /**< Host */
    char *port;                                                                 /**< Port */
    char *path;                                                                 /**< Path */
    char *query;                                                                /**< Query */
    char *fragment;                                                             /**< Fragment */
}
uri_t;

/**
 *  @brief Initialise a URI structure
 *
 *  @param[out] uri Pointer to a URI structure
 */
void uri_create(uri_t *uri);

/**
 *  @brief Deinitialise a URI structure
 *
 *  @param[in,out] uri Pointer to a URI structure
 */
void uri_destroy(uri_t *uri);

/**
 *  @brief Parse a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the URI
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_parse(uri_t *uri, const char *str);

/**
 *  @brief Copy a URI
 *
 *  @param[in,out] dest Pointer to the destination URI structure
 *  @param[in] src Pointer to the source URI structure
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_copy(uri_t *dest, uri_t *src);

/**
 *  @brief Set the scheme in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the scheme
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_scheme(uri_t *uri, const char *str);

/**
 *  @brief Set the user-info in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the user-info
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_userinfo(uri_t *uri, const char *str);

/**
 *  @brief Set the host in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the host
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_host(uri_t *uri, const char *str);

/**
 *  @brief Set the port in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the port
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_port(uri_t *uri, const char *str);

/**
 *  @brief Set the path in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the path
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_path(uri_t *uri, const char *str);

/**
 *  @brief Set the query in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the query
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_query(uri_t *uri, const char *str);

/**
 *  @brief Set the fragment in a URI
 *
 *  @param[in,out] uri Pointer to a URI structure
 *  @param[in] str String representation of the fragment
 *
 *  @retval Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int uri_set_fragment(uri_t *uri, const char *str);

/**
 *  @brief Generate a URI
 *
 *  @param[in] uri Pointer to a URI structure
 *  @param[out] buf Pointer to a buffer to contain the generated URI
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the generated URI or error code
 *  @retval >0 Length of the generated message
 *  @retval <0 Error
 */
size_t uri_generate(uri_t *uri, char *buf, size_t len);

#endif
