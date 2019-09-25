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
 *  @file cross.h
 *
 *  @brief Include file for the FreeCoAP HTTP/COAP message/URI cross library
 */

#ifndef CROSS_H
#define CROSS_H

#include "coap_msg.h"
#include "http_msg.h"

#define CROSS_COAP_REQ_TYPE  COAP_MSG_CON                                     /**< CoAP request message type */

/**
 *  @brief Convert a HTTP response code to a string representation
 *
 *  @param[in] code HTTP response code
 *
 *  @returns String representation
 */
const char *cross_http_resp_code_to_str(unsigned code);

/**
 *  @brief Convert a HTTP URI to the URI in a CoAP message
 *
 *  @param[out] coap_msg Pointer to a CoAP message structure
 *  @param[in] http_uri String containing the HTTP URI
 *
 *  The HTTP URI must be an absolute URI.
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int cross_uri_http_to_coap(coap_msg_t *coap_msg, const char *http_uri);

/**
 *  @brief Convert the URI in a CoAP message to a HTTP URI
 *
 *  @param[out] buf Buffer to hold the HTTP URI
 *  @param[in] len Length of the buffer to hold the HTTP URI
 *  @param[in] coap_msg Point to a CoAP message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int cross_uri_coap_to_http(char *buf, size_t len, coap_msg_t *coap_msg);

/**
 *  @brief Convert a HTTP request message to a CoAP request message
 *
 *  @param[out] coap_msg Pointer to a CoAP message structure
 *  @param[out] coap_body Buffer to hold the body of a blockwise transfer
 *  @param[in] coap_body_len Length of the buffer to hold the body of a blockwise transfer
 *  @param[out] coap_body_end Pass-by-reference vallue to return the amount of relevant data in the buffer
 *  @param[in] http_msg Pointer to a HTTP message structure
 *  @param[out] code HTTP response code
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int cross_req_http_to_coap(coap_msg_t *coap_msg, char *coap_body, size_t coap_body_len, size_t *coap_body_end, http_msg_t *http_msg, unsigned *code);

/**
 *  @brief Convert a CoAP response message to a HTTP response message
 *
 *  @param[out] http_msg Pointer to a HTTP message structure
 *  @param[in] coap_msg Pointer to a CoAP message structure
 *  @param[in] coap_body Buffer to hold the body of a blockwise transfer
 *  @param[in] coap_body_len Length of the buffer to hold the body of a blockwise transfer
 *  @param[out] code HTTP response code
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int cross_resp_coap_to_http(http_msg_t *http_msg, coap_msg_t *coap_msg, const char *coap_body, size_t coap_body_len, unsigned *code);

#endif
