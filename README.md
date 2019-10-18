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

- CoAP client sample applications

- CoAP server sample applications

- more than 10,000 lines of unit test code

Copyright (c) 2015 - 2019 Keith Cullen

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


Autotools
=========

To generate a configure script
------------------------------

$ cd FreeCoAP

$ autoreconf --install

To build and install FreeCoAP as a library
------------------------------------------

$ configure

$ make

$ make install

(Note: The FreeCoAP library built using this process requires GnuTLS and cannot be used without DTLS.)


Sample Applications
===================

To run the transfer_client and transfer_server sample applications with CoAP/IPv4
---------------------------------------------------------------------------------

$ cd FreeCoAP/sample/transfer_server

$ make dtls=n

$ ./transfer_server 0.0.0.0 10000

(In a different terminal)

$ cd FreeCoAP/sample/transfer_client

$ make dtls=n

$ ./transfer_client 127.0.0.1 10000 filename

To run the transfer_client and transfer_server sample applications with CoAP/DTLS/IPv4
--------------------------------------------------------------------------------------

$ cd FreeCoAP/sample/transfer_server

$ make

$ ./transfer_server 0.0.0.0 10000

(In a different terminal)

$ cd FreeCoAP/sample/transfer_client

$ make

$ ./transfer_client 127.0.0.1 10000 filename

To run the transfer_client and transfer_server sample applications with CoAP/IPv6
---------------------------------------------------------------------------------

$ cd FreeCoAP/sample/transfer_server

$ make dtls=n ip6=y

$ ./transfer_server ::0 10000

(In a different terminal)

$ cd FreeCoAP/sample/transfer_client

$ make dtls=n ip6=y

$ ./transfer_client ::1 10000 filename

To run the transfer_client and transfer_server sample applications with CoAP/DTLS/IPv6
--------------------------------------------------------------------------------------

$ cd FreeCoAP/sample/transfer_server

$ make ip6=y

$ ./transfer_server ::0 10000

(In a different terminal)

$ cd FreeCoAP/sample/transfer_client

$ make ip6=y

$ ./transfer_client ::1 10000 filename

To run the time_client and time_server sample applications with CoAP/IPv4
-------------------------------------------------------------------------

$ cd FreeCoAP/sample/time_server

$ make dtls=n

$ ./time_server 0.0.0.0 10000

(In a different terminal)

$ cd FreeCoAP/sample/time_client

$ make dtls=n

$ ./time_client 127.0.0.1 10000

To run the time_client and time_server sample applications with CoAP/DTLS/IPv4
------------------------------------------------------------------------------

$ cd FreeCoAP/sample/time_server

$ make

$ ./time_server 0.0.0.0 10000

(In a different terminal)

$ cd FreeCoAP/sample/time_client

$ make

$ ./time_client 127.0.0.1 10000

To run the time_client and time_server sample applications with CoAP/IPv6
-------------------------------------------------------------------------

$ cd FreeCoAP/sample/time_server

$ make dtls=n ip6=y

$ ./time_server ::0 10000

(In a different terminal)

$ cd FreeCoAP/sample/time_client

$ make dtls=n ip6=y

$ ./time_client ::1 10000

To run the time_client and time_server sample applications with CoAP/DTLS/IPv6
------------------------------------------------------------------------------

$ cd FreeCoAP/sample/time_server

$ make ip6=y

$ ./time_server ::0 10000

(In a different terminal)

$ cd FreeCoAP/sample/time_client

$ make ip6=y

$ ./time_client ::1 10000

To run the reg_client and reg_server sample applications with CoAP/IPv4
-----------------------------------------------------------------------

$ cd FreeCoAP/sample/reg_server

$ make dtls=n

$ ./reg_server 0.0.0.0 10000

(In a different terminal)

$ cd FreeCoAP/sample/reg_client

$ make dtls=n

$ ./reg_client 127.0.0.1 10000

To run the reg_client and reg_server sample applications with CoAP/DTLS/IPv4
----------------------------------------------------------------------------

$ cd FreeCoAP/sample/reg_server

$ make

$ ./reg_server 0.0.0.0 10000

(In a different terminal)

$ cd FreeCoAP/sample/reg_client

$ make

$ ./reg_client 127.0.0.1 10000

To run the reg_client and reg_server sample applications with CoAP/IPv6
-----------------------------------------------------------------------

$ cd FreeCoAP/sample/reg_server

$ make dtls=n ip6=y

$ ./reg_server ::0 10000

(In a different terminal)

$ cd FreeCoAP/sample/reg_client

$ make dtls=n ip6=y

$ ./reg_client ::1 10000

To run the reg_client and reg_server sample applications with CoAP/DTLS/IPv6
----------------------------------------------------------------------------

$ cd FreeCoAP/sample/reg_server

$ make ip6=y

$ ./reg_server ::0 10000

(In a different terminal)

$ cd FreeCoAP/sample/reg_client

$ make ip6=y

$ ./reg_client ::1 10000


Test Applications
=================

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

v0.7-tinydtls
-------------

HP Pavilion
-----------
Ubuntu 16.04

Linux 4.15.0-64-generic #73~16.04.1-Ubuntu SMP Fri Sep 13 09:56:18 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.5.15

tinydtls 0.8.6

BeagleBone Black
----------------
Debian 9

Linux beaglebone 4.14.71-ti-r80 #1 SMP PREEMPT Fri Oct 5 23:50:11 UTC 2018 armv7l GNU/Linux

GnuTLS 3.5.8

tinydtls 0.8.6

Raspberry Pi 3 model B
----------------------
Raspbian buster

Linux raspberrypi 4.19.57-v7+ #1244 SMP Thu Jul 4 18:45:25 BST 2019 armv7l GNU/Linux

GnuTLS 3.6.7

tinydtls 0.8.6


v0.7
----

HP Pavilion
-----------
Ubuntu 16.04

Linux 4.15.0-64-generic #73~16.04.1-Ubuntu SMP Fri Sep 13 09:56:18 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.5.15

BeagleBone Black
----------------
Debian 9

Linux beaglebone 4.14.71-ti-r80 #1 SMP PREEMPT Fri Oct 5 23:50:11 UTC 2018 armv7l GNU/Linux

GnuTLS 3.5.8

Raspberry Pi 3 model B
----------------------
Raspbian buster

Linux raspberrypi 4.19.57-v7+ #1244 SMP Thu Jul 4 18:45:25 BST 2019 armv7l GNU/Linux

GnuTLS 3.6.7


v0.6-tinydtls
------------

HP Pavilion
-----------
Ubuntu 16.04

Linux 4.13.0-32-generic #35~16.04.1-Ubuntu SMP Thu Jan 25 10:13:43 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.5.15

tinydtls 0.8.6


v0.6
----

HP Pavilion
-----------
Ubuntu 16.04

Linux 4.13.0-32-generic #35~16.04.1-Ubuntu SMP Thu Jan 25 10:13:43 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.5.15


v0.5-tinydtls
------------

HP Pavilion
-----------
Ubuntu 16.04

Linux 4.10.0-37-generic #41~16.04.1-Ubuntu SMP Fri Oct 6 22:42:59 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.5.15

tinydtls 0.8.6

Raspberry Pi model B
--------------------
Raspbian stretch

Linux raspberrypi 4.9.41+ #1023 Tue Aug 8 15:47:12 BST 2017 armv6l GNU/Linux

GnuTLS 3.5.15

tinydtls 0.8.6

BeagleBone Black
----------------
Debian 9.1

Linux beaglebone 4.4.88-ti-r125 #1 SMP Thu Sep 21 19:23:24 UTC 2017 armv7l GNU/Linux

GnuTLS 3.5.8

tinydtls 0.8.6


v0.5
----

HP Pavilion
-----------
Ubuntu 16.04

Linux 4.10.0-37-generic #41~16.04.1-Ubuntu SMP Fri Oct 6 22:42:59 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.5.15

Raspberry Pi model B
--------------------
Raspbian stretch

Linux raspberrypi 4.9.41+ #1023 Tue Aug 8 15:47:12 BST 2017 armv6l GNU/Linux

GnuTLS 3.5.15

BeagleBone Black
----------------
Debian 9.1

Linux beaglebone 4.4.88-ti-r125 #1 SMP Thu Sep 21 19:23:24 UTC 2017 armv7l GNU/Linux

GnuTLS 3.5.8


v0.4-tinydtls
------------

HP Pavilion
-----------
Ubuntu 15.04

Linux 3.19.0-15-generic #15-Ubuntu SMP Thu Apr 16 23:32:37 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.3.8

tinydtls 0.8.6


v0.4
----

HP Pavilion
-----------
Ubuntu 15.04

Linux 3.19.0-15-generic #15-Ubuntu SMP Thu Apr 16 23:32:37 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

GnuTLS 3.3.8


v0.3-tinydtls
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
