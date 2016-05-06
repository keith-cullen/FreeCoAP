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
 *  @file sock.c
 *
 *  @brief Source file for the FreeCoAP socket library
 */

#include <stdlib.h>
#include "sock.h"

static const char *sock_error_str[] = {
    /*   0 */    "ok",
    /*  -1 */    "received interrupt",
    /*  -2 */    "timeout",
    /*  -3 */    "no memory",
    /*  -4 */    "invalid socket type",
    /*  -5 */    "invalid argument",

    /*  -6 */    "unable to open socket",
    /*  -7 */    "unable to configure socket",
    /*  -8 */    "unable to resolve address",
    /*  -9 */    "unable to bind to address",
    /* -10 */    "unable to listen on socket",
    /* -11 */    "unable to accept connection",
    /* -12 */    "unable to connect to server",
    /* -13 */    "unable to read from socket",
    /* -14 */    "unable to write to socket",

    /* -15 */    "unable to initialise SSL",
    /* -16 */    "unable to load SSL trust file",
    /* -17 */    "unable to load SSL certificate file",
    /* -18 */    "unable to load SSL key file",
    /* -19 */    "unable to configure socket for SSL",
    /* -20 */    "unable to complete SSL handshake",
    /* -21 */    "SSL cache error",

    /* -22 */    "unable to initialise TLS",
    /* -23 */    "unable to load TLS trust file",
    /* -24 */    "unable to load TLS credentials",
    /* -25 */    "unable to configure socket for TLS",
    /* -26 */    "unable to complete TLS handshake",
    /* -27 */    "TLS rehandshake refused",
    /* -28 */    "TLS warning alert received",
    /* -29 */    "TLS cache error",

    /* -30 */    "peer certificate verification failed",
    /* -31 */    "unable to close socket",

    /* -32 */    "lock error"
};

const char *sock_strerror(int error)
{
    int i = -error;

    if ((i < 0) || (i >= SOCK_NUM_ERRORS))
    {
        return NULL;
    }
    return sock_error_str[i];
}
