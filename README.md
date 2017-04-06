FreeCoAP
========

An implementation of the CoAP protocol for GNU/Linux consisting of:

- a CoAP message parser/formatter library

- a CoAP client library

- a CoAP server library

- a CoAP client test application

- a CoAP server test application

- a HTTP/CoAP proxy application

- a HTTP client test application

- more than 10,000 lines of unit test code

Copyright (c) 2015 - 2017 Keith Cullen

Released under a BSD style license.

Tested on Intel Galileo, Raspberry Pi and BeagleBone Black.


Branches
========

master
------

- DTLS for CoAP implemented using GnuTLS
    - X.509 certificates (RFC 7252 section 9.1.3.3)
- TLS for HTTP implemented using GnuTLS
    - X.509 certificates (RFC 7252 section 9.1.3.3)

tinydtls
--------

- DTLS for CoAP implemented using tinydtls
    - raw public key certificates (RFC 7252 section 9.1.3.2)
- TLS for HTTP implemented using GnuTLS
    - X.509 certificates (RFC 7252 section 9.1.3.3)


Build and Test Instructions
===========================

To test the message/parser formatter
------------------------------------

$ cd FreeCoAP/test/test_coap_msg

$ make

$ ./test_coap_msg

To test the CoAP client and CoAP server test applications with CoAP/IPv4
------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make dtls=n

$ ./test_coap_server

(In a different terminal)

$ cd FreeCoAP/test/test_coap_client

$ make dtls=n

$ ./test_coap_client

To test the CoAP client and CoAP server test applications with CoAP/DTLS/IPv4
-----------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make

$ ./test_coap_server

(In a different terminal)

$ cd FreeCoAP/test/test_coap_client

$ make

$ ./test_coap_client

To test the CoAP client and CoAP server test applications with CoAP/IPv6
------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make ip6=y dtls=n

$ ./test_coap_server

(In a different terminal)

$ cd FreeCoAP/test/test_coap_client

$ make ip6=y dtls=n

$ ./test_coap_client

To test the CoAP client and CoAP server test applications with CoAP/DTLS/IPv6
-----------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make ip6=y

$ ./test_coap_server

(In a different terminal)

$ cd FreeCoAP/test/test_coap_client

$ make ip6=y

$ ./test_coap_client

To test the HTTP/CoAP proxy application with HTTP/TLS/IPv4 and CoAP/DTLS/IPv4
-----------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make

$ ./test_coap_server

(In a second terminal)

$ cd FreeCoAP/test/test_proxy_http_coap

$ make

$ ./proxy

(In a third terminal)

$ cd FreeCoAP/test/test_http_client

$ make

$ ./test_http_client

To test the HTTP/CoAP proxy application with HTTP/TLS/IPv6 and CoAP/DTLS/IPv6
-----------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make ip6=y

$ ./test_coap_server

(In a second terminal)

$ cd FreeCoAP/test/test_proxy_http_coap

$ make http_ip6=y coap_ip6=y

$ ./proxy

(In a third terminal)

$ cd FreeCoAP/test/test_http_client

$ make http_ip6=y coap_ip6=y

$ ./test_http_client

To test the HTTP/CoAP proxy application with HTTP/TLS/IPv4 and CoAP/DTLS/IPv6
-----------------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ make ip6=y

$ ./test_coap_server

(In a second terminal)

$ cd FreeCoAP/test/test_proxy_http_coap

$ make coap_ip6=y

$ ./proxy

(In a third terminal)

$ cd FreeCoAP/test/test_http_client

$ make coap_ip6=y

$ ./test_http_client


Certificates and Keys
=====================

To generate X.509 certificates and keys
---------------------------------------
(for master and tinydtls branches)

$ cd FreeCoAP/certs/gen_certs

$ ./gen_certs.sh

Follow the instructions.

The new certificate and key files will be placed in the FreeCoAP/certs directory.

The client, server and proxy applications will pick up the new certificates and keys automatically.

To generate raw public/private keys
-----------------------------------
(for tinydtls branch)

$ cd FreeCoAP/raw_keys

$ ./gen_keys.sh

The new key files will be placed in the FreeCoAP/raw_keys directory.

The client, server and proxy applications will pick up the new keys automatically.


Validation History
==================

0.3-tinydtls
------------

BeagleBone Black
----------------
Angstrom v2015.06

Linux beaglebone 4.1.4 #1 SMP PREEMPT Tue Jan 5 09:33:15 GMT 2016 armv7l GNU/Linux

GnuTLS 3.2.0

tinydtls 0.8.6

HP Pavilion
-----------
Ubuntu 15.04

Linux 3.19.0-15-generic #15-Ubuntu SMP Thu Apr 16 23:32:37 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.2.0

tinydtls 0.8.6


v0.3
----

BeagleBone Black
----------------
Angstrom v2015.06

Linux beaglebone 4.1.4 #1 SMP PREEMPT Tue Jan 5 09:33:15 GMT 2016 armv7l GNU/Linux

GnuTLS 3.2.0

HP Pavilion
-----------
Ubuntu 15.04

Linux 3.19.0-15-generic #15-Ubuntu SMP Thu Apr 16 23:32:37 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.2.0


v0.2
----

BeagleBone Black
----------------
Angstrom v2015.06

Linux beaglebone 4.1.4 #1 SMP PREEMPT Tue Jan 5 09:33:15 GMT 2016 armv7l GNU/Linux

GnuTLS 3.2.0

HP Pavilion
-----------
Ubuntu 15.04

Linux 3.19.0-15-generic #15-Ubuntu SMP Thu Apr 16 23:32:37 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.2.0


v0.1
----

Intel Galileo Gen1
------------------
Quark BSP 1.2

Linux quark 3.14.28-ltsi-yocto-standard #1 Tue Oct 20 01:46:36 IST 2015 i586 GNU/Linux

GnuTLS 3.3.5

Raspberry Pi model B
--------------------
Raspbian wheezy

Linux 3.12.28+ #709 PREEMPT Mon Sep 8 15:28:00 BST 2014 armv6l GNU/Linux

GnuTLS 3.2.0

BeagleBone Black
----------------
Angstrom v2015.06

Linux beaglebone 4.1.4 #1 SMP PREEMPT Tue Jan 5 09:33:15 GMT 2016 armv7l GNU/Linux

GnuTLS 3.2.0

Lenovo ThinkPad X240
--------------------
Fedora 21

Linux 4.1.8-100.fc21.x86_64 #1 SMP Tue Sep 22 12:13:06 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.2.0

HP Pavilion
-----------
Ubuntu 15.04

Linux 3.19.0-15-generic #15-Ubuntu SMP Thu Apr 16 23:32:37 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.2.0
