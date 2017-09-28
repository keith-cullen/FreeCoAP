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
 *  @file coap_server.h
 *
 *  @brief Include file for the FreeCoAP server library
 */

#ifndef COAP_SERVER_H
#define COAP_SERVER_H

#include <time.h>
#include <netinet/in.h>
#ifdef COAP_DTLS_EN
#include "tinydtls.h"
#include "dtls.h"
#endif
#include "coap_msg.h"
#include "coap_ipv.h"

#define COAP_SERVER_NUM_TRANS         8                                         /**< Maximum number of active transactions per server */
#define COAP_SERVER_ADDR_BUF_LEN      128                                       /**< Buffer length for host addresses */
#define COAP_SERVER_DIAG_PAYLOAD_LEN  128                                       /**< Buffer length for diagnostic payloads */

/**
 *  @brief Response type enumeration
 */
typedef enum
{
    COAP_SERVER_PIGGYBACKED = 0,                                                /**< Piggybacked response */
    COAP_SERVER_SEPARATE = 1                                                    /**< Separate response */
}
coap_server_resp_t;

/**
 *  @brief URI path structure
 */
typedef struct coap_server_path
{
    char *str;                                                                  /**< String containing a path */
    struct coap_server_path *next;                                              /**< Pointer to the next URI path structure in the list */
}
coap_server_path_t;

/**
 *  @brief URI path list structure
 */
typedef struct
{
    coap_server_path_t *first;                                                  /**< Pointer to the first URI path structure in the list */
    coap_server_path_t *last;                                                   /**< Pointer to the last URI path structure in the list */
}
coap_server_path_list_t;

#ifdef COAP_DTLS_EN

/**
 *  @brief Server DTLS state enumeration
 */
typedef enum
{
    COAP_SERVER_DTLS_UNCONNECTED = 0,                                           /**< DTLS session is not active */
    COAP_SERVER_DTLS_CONNECTED,                                                 /**< DTLS session is active */
    COAP_SERVER_DTLS_ALERT                                                      /**< A DTLS alert message was received from the client */
}
coap_server_dtls_state_t;

#endif

struct coap_server;

/**
 *  @brief Transaction structure
 */
typedef struct coap_server_trans
{
    int active;                                                                 /**< Flag to indicate if this transaction structure contains valid data */
    time_t last_use;                                                            /**< The time that this transaction structure was last used */
    int timer_fd;                                                               /**< Timer file descriptor */
    struct timespec timeout;                                                    /**< Timeout value */
    unsigned num_retrans;                                                       /**< Current number of retransmissions */
    coap_ipv_sockaddr_in_t client_sin;                                          /**< Socket structure */
    socklen_t client_sin_len;                                                   /**< Socket structure length */
    char client_addr[COAP_SERVER_ADDR_BUF_LEN];                                 /**< String to hold the client address */
    coap_msg_t req;                                                             /**< Last request message received for this transaction */
    coap_msg_t resp;                                                            /**< Last response message sent for this transaction */
    struct coap_server *server;                                                 /**< Pointer to the containing server structure */
#ifdef COAP_DTLS_EN
    coap_server_dtls_state_t state;                                             /**< Current state of the DTLS session */
    dtls_context_t *ctx;                                                        /**< DTLS context */
    session_t sess;                                                             /**< DTLS session */
    char *app_start;                                                            /**< Start of application data */
    size_t app_len;                                                             /**< Length of application data */
#endif
}
coap_server_trans_t;

/**
 *  @brief Server structure
 */
typedef struct coap_server
{
    int sd;                                                                     /**< Socket descriptor */
    unsigned msg_id;                                                            /**< Last message ID value used in a response message */
    coap_server_path_list_t sep_list;                                           /**< List of URI paths that require separate responses */
    coap_server_trans_t trans[COAP_SERVER_NUM_TRANS];                           /**< Array of transaction structures */
    int (* handle)(struct coap_server *, coap_msg_t *, coap_msg_t *);           /**< Call-back function to handle requests and generate responses */
#ifdef COAP_DTLS_EN
    dtls_ecdsa_key_t ecdsa_key;                                                 /**< ECDSA keys */
    const unsigned char *ecdsa_access_x;                                        /**< Buffer containing the x components of the ECDSA access control list */
    const unsigned char *ecdsa_access_y;                                        /**< Buffer containing the y components of the ECDSA access control list */
    unsigned ecdsa_access_num;                                                  /**< Number of entries in the ECDSA access control list */
    unsigned ecdsa_size;                                                        /**< Size of an ECDSA component */
#endif
}
coap_server_t;

#ifdef COAP_DTLS_EN

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] handle Call-back function to handle client requests
 *  @param[in] host Pointer to a string containing the host address of the server
 *  @param[in] port Port number of the server
 *  @param[in] ecdsa_priv_key Buffer containing the ECDSA private key
 *  @param[in] ecdsa_pub_key_x Buffer containing the x component of the ECDSA public key
 *  @param[in] ecdsa_pub_key_y Buffer containing the y component of the ECDSA public key
 *  @param[in] ecdsa_access_x Buffer containing the x components of the ECDSA access control list
 *  @param[in] ecdsa_access_y Buffer containing the y components of the ECDSA access control list
 *  @param[in] ecdsa_access_num Number of entries in the ECDSA access control list
 *  @param[in] ecdsa_size Size of an ECDSA component
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_server_create(coap_server_t *server,
                       int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *),
                       const char *host,
                       const char *port,
                       const unsigned char *ecdsa_priv_key,
                       const unsigned char *ecdsa_pub_key_x,
                       const unsigned char *ecdsa_pub_key_y,
                       const unsigned char *ecdsa_access_x,
                       const unsigned char *ecdsa_access_y,
                       unsigned ecdsa_access_num,
                       unsigned ecdsa_size);

#else  /* !COAP_DTLS_EN */

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] handle Call-back function to handle client requests
 *  @param[in] host Pointer to a string containing the host address of the server
 *  @param[in] port Port number of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_server_create(coap_server_t *server,
                       int (* handle)(coap_server_t *, coap_msg_t *, coap_msg_t *),
                       const char *host,
                       const char *port);

#endif  /* COAP_DTLS_EN */

/**
 *  @brief Deinitialise a server structure
 *
 *  @param[in,out] server Pointer to a server structure
 */
void coap_server_destroy(coap_server_t *server);

/**
 *  @brief Get a new message ID value
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns message ID value
 */
unsigned coap_server_get_next_msg_id(coap_server_t *server);

/**
 *  @brief Register a URI path that requires a separate response
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] str String representation of a URI path
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */ 
int coap_server_add_sep_resp_uri_path(coap_server_t *server, const char *str);

/**
 *  @brief Run the server
 *
 *  Listen for incoming requests. For each request received,
 *  call the handle call-back function in the server structure
 *  and send the response to the client.
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_server_run(coap_server_t *server);

#endif
