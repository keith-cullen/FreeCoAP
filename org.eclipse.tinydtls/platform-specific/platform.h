/************************************************************************/
/* Contiki-specific parameters                                          */
/************************************************************************/

#ifndef _PLATFORM_H_
#define _PLATFORM_H_ 1

#ifdef CONTIKI
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "contiki-conf.h"

/* global constants for constrained devices running Contiki */
#ifndef DTLS_PEER_MAX
/** The maximum number DTLS peers (i.e. sessions). */
#  define DTLS_PEER_MAX 1
#endif

#ifndef DTLS_HANDSHAKE_MAX
/** The maximum number of concurrent DTLS handshakes. */
#  define DTLS_HANDSHAKE_MAX 1
#endif

#ifndef DTLS_SECURITY_MAX
/** The maximum number of concurrently used cipher keys */
#  define DTLS_SECURITY_MAX (DTLS_PEER_MAX + DTLS_HANDSHAKE_MAX)
#endif

#ifndef DTLS_HASH_MAX
/** The maximum number of hash functions that can be used in parallel. */
#  define DTLS_HASH_MAX (3 * DTLS_PEER_MAX)
#endif

/** do not use uthash hash tables */
#define DTLS_PEERS_NOHASH 1

/************************************************************************/
/* Specific Contiki platforms                                           */
/************************************************************************/

#if CONTIKI_TARGET_ECONOTAG
#  include "platform-specific/config-econotag.h"
#endif /* CONTIKI_TARGET_ECONOTAG */

#ifdef CONTIKI_TARGET_CC2538DK
#  include "platform-specific/config-cc2538dk.h"
#endif /* CONTIKI_TARGET_CC2538DK */

#ifdef CONTIKI_TARGET_WISMOTE
#  include "platform-specific/config-wismote.h"
#endif /* CONTIKI_TARGET_WISMOTE */

#ifdef CONTIKI_TARGET_SKY
#  include "platform-specific/config-sky.h"
#endif /* CONTIKI_TARGET_SKY */

#ifdef CONTIKI_TARGET_MINIMAL_NET
#  include "platform-specific/config-minimal-net.h"
#endif /* CONTIKI_TARGET_MINIMAL_NET */

#endif /* CONTIKI */

#endif /* _PLATFORM_H_ */
