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
 *  @file proxy.c
 *
 *  @brief Main file for the FreeCoAP HTTP/CoAP proxy application
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include "listener.h"
#include "connection.h"
#include "param.h"
#include "tls.h"
#include "coap_mem.h"
#include "coap_log.h"

#define DEF_MAX_LOG_LEVEL  COAP_LOG_INFO                                        /**< Default maximum log level */
#define CONFIG_FILE_NAME   "proxy.conf"                                         /**< Configuration file name */
#define SOCKET_TIMEOUT     120                                                  /**< Timeout for TLS/IPv6 socket operations */
#define SOCKET_BACKLOG     10                                                   /**< Backlog queue size for the listening TLS/IPv6 socket */
#define SMALL_BUF_NUM      128                                                  /**< Number of buffers in the small memory allocator */
#define SMALL_BUF_LEN      256                                                  /**< Length of each buffer in the small memory allocator */
#define MEDIUM_BUF_NUM     128                                                  /**< Number of buffers in the medium memory allocator */
#define MEDIUM_BUF_LEN     1024                                                 /**< Length of each buffer in the medium memory allocator */
#define LARGE_BUF_NUM      32                                                   /**< Number of buffers in the large memory allocator */
#define LARGE_BUF_LEN      8192                                                 /**< Length of each buffer in the large memory allocator */

int go = 1;                                                                     /**< Global variable used to indicate to the listener module to run or stop */

/**
 *  @brief Signal handler for the interrupt signal
 *
 *  @param[in] signo Signal number
 */
static void signal_handler(int signo)
{
    go = 0;
}

/**
 *  @brief Helper function to list command line options
 */
static void usage(void)
{
    printf("usage: proxy [options]\n");
    printf("options:\n");
    printf("    -h help\n");
    printf("    -v verbose\n");
    printf("    -c config-file\n");
}

/**
 *  @brief Main function for the FreeCoAP HTTP/CoAP proxy application
 *
 *  @param[in] argc Number of command line arguments
 *  @param[in] argv Array of pointers to command line arguments
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(int argc, char **argv)
{
    const struct option long_opts[] =
    {
        {"help",    no_argument,       NULL, 'h'},
        {"config",  required_argument, NULL, 'c'},
        {0, 0, 0, 0}
    };
    struct sigaction sah = {{0}};
    struct sigaction sai = {{0}};
    const char *config_file_name = CONFIG_FILE_NAME;
    const char *short_opts = ":hc:";
    const char *gnutls_ver = NULL;
    tls_server_t server = {0};
    listener_t *listener = NULL;
    unsigned listener_index = 0;
    param_t param = {0};
    int long_index = 0;
    int ret = 0;
    int c = 0;

    /* initialise signal handler */
    sah.sa_handler = signal_handler;
    sah.sa_flags = 0;
    sai.sa_handler = SIG_IGN;
    sai.sa_flags = 0;
    if ((sigemptyset(&sai.sa_mask) == -1)
     || (sigfillset(&sah.sa_mask)  == -1)    /* block all signals while handling this one */
     || (sigaction(SIGHUP,  &sah, NULL) == -1)
     || (sigaction(SIGINT,  &sah, NULL) == -1)
     || (sigaction(SIGQUIT, &sah, NULL) == -1)
     || (sigaction(SIGABRT, &sah, NULL) == -1)
     || (sigaction(SIGPIPE, &sai, NULL) == -1)
     || (sigaction(SIGTERM, &sah, NULL) == -1)
        )
    {
        fprintf(stderr, "Error: unable to set singal handler\n");
        return EXIT_FAILURE;
    }

    /* disable getopt() error messages */
    opterr = 0;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, &long_index)) != -1)
    {
        switch (c)
        {
        case 'h' :
            usage();
            return EXIT_SUCCESS;
            break;
        case 'c' :
            config_file_name = optarg;
            break;
        case ':' :  /* missing operand */
            if ((argv[optind - 1][0] == '-') && (argv[optind - 1][1] == '-'))
                fprintf(stderr, "Error: option '%s' requires an argument\n", argv[optind - 1] + 2);
            else
                fprintf(stderr, "Error: option '%c' requires an argument\n", optopt);
            return EXIT_FAILURE;
            break;
        case '?' :
            if ((argv[optind - 1][0] == '-') && (argv[optind - 1][1] == '-'))
                fprintf(stderr, "Error: unknown option '%s'\n", argv[optind - 1] + 2);
            else
                fprintf(stderr, "Error: unknown option '%c'\n", optopt);
            return EXIT_FAILURE;
            break;
        default :
            usage();
            return EXIT_FAILURE;
        }
    }
    if (optind < argc)
    {
        fprintf(stderr, "Error: unknown option '%s'\n", argv[optind]);
        return EXIT_FAILURE;
    }

    coap_log_set_level(DEF_MAX_LOG_LEVEL);

    /*
     * from here on error messages are written to the log file
     */

    ret = coap_mem_all_create(SMALL_BUF_NUM, SMALL_BUF_LEN,
                              MEDIUM_BUF_NUM, MEDIUM_BUF_LEN,
                              LARGE_BUF_NUM, LARGE_BUF_LEN);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return EXIT_FAILURE;
    }

    ret = param_create(&param, config_file_name);
    if (ret < 0)
    {
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }

    coap_log_set_level(param_get_max_log_level(&param));

    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        param_destroy(&param);
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }
    coap_log_info("GnuTLS version: %s", gnutls_ver);

    /* initialise SSL/TLS */
    ret = tls_init();
    if (ret != SOCK_OK)
    {
        coap_log_error("Unable to initialise TLS library");
        param_destroy(&param);
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }

    ret = tls_server_create(&server,
                            param_get_http_server_trust_file_name(&param),
                            param_get_http_server_cert_file_name(&param),
                            param_get_http_server_key_file_name(&param));
    if (ret != SOCK_OK)
    {
        coap_log_error("Unable to initialise TLS server");
        tls_deinit();
        param_destroy(&param);
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }

    ret = connection_init();
    if (ret < 0)
    {
        coap_log_error("Unable to initialise connection module");
        tls_server_destroy(&server);
        tls_deinit();
        param_destroy(&param);
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }

    listener = listener_new(listener_index,
                            &server,
                            &param,
                            SOCKET_TIMEOUT,
                            SOCKET_BACKLOG);
    if (listener == NULL)
    {
        tls_server_destroy(&server);
        tls_deinit();
        param_destroy(&param);
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }

    ret = listener_run(listener);
    if (ret < 0)
    {
        listener_delete(listener);
        tls_server_destroy(&server);
        tls_deinit();
        param_destroy(&param);
        coap_mem_all_destroy();
        return EXIT_FAILURE;
    }

    /* the listener runs in its own thread,
     * waits for a signal and cleans up after itself
     * i.e. calls listener_delete()
     */

    coap_log_notice("Proxy running");

    while (go)
    {
        sleep(3600);
    }
    sleep(2);

    coap_log_notice("Proxy stopped");

    tls_server_destroy(&server);
    tls_deinit();
    param_destroy(&param);
    coap_mem_all_destroy();
    return EXIT_SUCCESS;
}
