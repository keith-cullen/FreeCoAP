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
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#endif
#include "coap_msg.h"
#include "coap_ipv.h"

#define COAP_SERVER_NUM_TRANS                       8                           /**< Maximum number of active transactions per server */
#define COAP_SERVER_ADDR_BUF_LEN                    128                         /**< Buffer length for host addresses */
#define COAP_SERVER_DIAG_PAYLOAD_LEN                128                         /**< Buffer length for diagnostic payloads */

#define coap_server_trans_get_type(trans)           ((trans)->type)             /**< Get the type of transaction */
#define coap_server_trans_get_req(trans)            (&(trans)->req)             /**< Get the last request message received for this transaction */
#define coap_server_trans_get_resp(trans)           (&(trans)->resp)            /**< Get the last response message sent for this transaction */
#define coap_server_trans_get_body(trans)           ((trans)->body)             /**< Get the body of a blockwise transfer */
#define coap_server_trans_get_body_len(trans)       ((trans)->body_len)         /**< Get the length of the body of a blockwise transfer */
#define coap_server_trans_get_body_end(trans)       ((trans)->body_end)         /**< Get the amount of relevant data in body of a blockwise transfer */
#define coap_server_trans_set_body_end(trans, i)    ((trans)->body_end = (i))   /**< Get the amount of relevant data in body of a blockwise transfer */

/**
 *  @brief Transaction type enumeration
 */
typedef enum
{
    COAP_SERVER_TRANS_REGULAR = 0,                                              /**< Regular (i.e. non-blockwise) transaction */
    COAP_SERVER_TRANS_BLOCKWISE_GET = 1,                                        /**< Blockwise GET transaction */
    COAP_SERVER_TRANS_BLOCKWISE_PUT1 = 2,                                       /**< Request phase of a blockwise PUT transaction */
    COAP_SERVER_TRANS_BLOCKWISE_PUT2 = 3,                                       /**< Response phase of a blockwise PUT transaction */
    COAP_SERVER_TRANS_BLOCKWISE_POST1 = 4,                                      /**< Request phase of a Blockwise POST transaction */
    COAP_SERVER_TRANS_BLOCKWISE_POST2 = 5                                       /**< Response phase of a Blockwise POST transaction */
}
coap_server_trans_type_t;

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
 *  @brief Forward declaration of transaction structure
 */
struct coap_server_trans;

/**
 *  @brief Server transaction handler callback function
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
typedef int (* coap_server_trans_handler_t)(struct coap_server_trans *trans, coap_msg_t *req, coap_msg_t *resp);

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

struct coap_server;

/**
 *  @brief Transaction structure
 */
typedef struct coap_server_trans
{
    int active;                                                                 /**< Flag to indicate if this transaction structure contains valid data */
    coap_server_trans_type_t type;                                              /**< Transaction type */
    time_t last_use;                                                            /**< The time that this transaction structure was last used */
    int timer_fd;                                                               /**< Timer file descriptor */
    struct timespec timeout;                                                    /**< Timeout value */
    unsigned num_retrans;                                                       /**< Current number of retransmissions */
    coap_ipv_sockaddr_in_t client_sin;                                          /**< Socket structure */
    socklen_t client_sin_len;                                                   /**< Socket structure length */
    char client_addr[COAP_SERVER_ADDR_BUF_LEN];                                 /**< String to hold the client address */
    coap_msg_t req;                                                             /**< Last request message received for this transaction */
    coap_msg_t resp;                                                            /**< Last response message sent for this transaction */
    char *body;                                                                 /**< Pointer to a buffer for blockwise transfers */
    size_t body_len;                                                            /**< Length of the buffer for blockwise transfers */
    size_t body_end;                                                            /**< Amount of relevant data in the buffer for blockwise transfers */
    unsigned block1_size;                                                       /**< Block1 size for blockwise transfers */
    unsigned block2_size;                                                       /**< Block2 size for blockwise transfers */
    size_t block1_next;                                                         /**< Byte offset of the next block in the request */
    size_t block2_next;                                                         /**< Byte offset of the next block in the response */
    char block_uri[COAP_MSG_OP_URI_PATH_MAX_LEN + 1];                           /**< The URI for the current blockwise transfer */
    coap_msg_success_t block_detail;                                            /**< Code detail for a PUT or POST blockwise operation */
    coap_server_trans_handler_t block_rx;                                       /**< User-supplied callback function to be called when the body of a blockwise transfer has been fully received */
    struct coap_server *server;                                                 /**< Pointer to the containing server structure */
#ifdef COAP_DTLS_EN
    gnutls_session_t session;                                                   /**< DTLS session */
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
    coap_server_trans_handler_t handle;                                         /**< Call-back function to handle requests and generate responses */
#ifdef COAP_DTLS_EN
    gnutls_certificate_credentials_t cred;                                      /**< DTLS credentials */
    gnutls_priority_t priority;                                                 /**< DTLS priorities */
    gnutls_dh_params_t dh_params;                                               /**< Diffie-Hellman parameters */
#endif
}
coap_server_t;

/**
 *  @brief Handle a library-level blockwise transfer
 *
 *  Configure the transaction structure to do a library-level
 *  blockwise transfer. This function should be called by the
 *  application from the handle callback function.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *  @param[in] block1_size Preferred block1 size
 *  @param[in] block2_size Preferred block2 size
 *  @param[in] body Buffer containing the body
 *  @param[in] body_len length of the buffer
 *  @param[in] block_rx Callback function to be called when the body of a blockwise transfer has been fully received
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_server_trans_handle_blockwise(coap_server_trans_t *trans,
                                       coap_msg_t *req,
                                       coap_msg_t *resp,
                                       unsigned block1_size,
                                       unsigned block2_size,
                                       char *body,
                                       size_t body_len,
                                       coap_server_trans_handler_t block_rx);

#ifdef COAP_DTLS_EN

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] handle Call-back function to handle client requests
 *  @param[in] host String containing the host address of the server
 *  @param[in] port String containing the port number of the server
 *  @param[in] key_file_name String containing the DTLS key file name
 *  @param[in] cert_file_name String containing the DTLS certificate file name
 *  @param[in] trust_file_name String containing the DTLS trust file name
 *  @param[in] crl_file_name String containing the DTLS certificate revocation list file name
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_server_create(coap_server_t *server,
                       coap_server_trans_handler_t handle,
                       const char *host,
                       const char *port,
                       const char *key_file_name,
                       const char *cert_file_name,
                       const char *trust_file_name,
                       const char *crl_file_name);

#else  /* !COAP_DTLS_EN */

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] handle Call-back function to handle client requests
 *  @param[in] host String containing the host address of the server
 *  @param[in] port String containing the port number of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_server_create(coap_server_t *server,
                       coap_server_trans_handler_t handle,
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
