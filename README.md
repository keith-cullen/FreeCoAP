========
FreeCoAP
========

An implementation of the CoAP protocol for GNU/Linux consisting of:

- a CoAP message parser/formatter library

- a CoAP client library

- a CoAP server library

- unit test code for the message parser/formatter

- a client test application

- a server test application

Copyright (c) 2015 Keith Cullen

Released under a BSD style license.

Tested on Intel Galileo, Raspberry Pi and BeagleBone Black.


Build Instructions
=================

To build the message parser/formatter for the host machine
----------------------------------------------------------

$ cd FreeCoAP/test/test_coap_msg

$ ./build_host

To build the message parser/formatter for Intel Quark
-----------------------------------------------------

$ cd FreeCoAP/test/test_coap_msg

$ ./build_quark

(assumes that the Quark SDK has been installed in /opt/iot-devkit/1.7.2)

To build the server test application for the host machine
---------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ ./build_host

To build the server test application with DTLS for the host machine
-------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ ./build_host dtls

To build the server test application for Intel Quark
----------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ ./build_quark

(assumes that the Quark SDK has been installed in /opt/iot-devkit/1.7.2)

To build the server test application with DTLS for Intel Quark
--------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ ./build_quark dtls

(assumes that the Quark SDK has been installed in /opt/iot-devkit/1.7.2)

To build the client test application for the host machine
---------------------------------------------------------

$ cd FreeCoAP/test/test_coap_client

$ ./build_host

To build the client test application with DTLS for the host machine
-------------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_client

$ ./build_host dtls

To build the client test application for Intel Quark
----------------------------------------------------

$ cd FreeCoAP/test/test_coap_client

$ ./build_quark

(assumes that the Quark SDK has been installed in /opt/iot-devkit/1.7.2)

To build the client test application with DTLS for Intel Quark
--------------------------------------------------------------

$ cd FreeCoAP/test/test_coap_client

$ ./build_quark dtls

(assumes that the Quark SDK has been installed in /opt/iot-devkit/1.7.2)


Test Instructions
=================

To test the message/parser formatter
------------------------------------

$ cd FreeCoAP/test/test_coap_msg

$ ./test_coap_msg

To test the client and server test applications
-----------------------------------------------

$ cd FreeCoAP/test/test_coap_server

$ ./test_coap_server

(In a different terminal window)

$ cd FreeCoAP/test/test_coap_client

$ ./test_coap_client


Validation History
==================

v0.1
----

Intel Galileo Gen1
------------------
Quark BSP 1.2

Linux 3.14.28-ltsi-yocto-standard #1 Tue Oct 20 01:46:36 IST 2015 GNU/Linux

GnuTLS 3.3.5

Raspberry Pi model B
--------------------
Raspbian wheezy

Linux 3.12.28+ #709 PREEMPT Mon Sep 8 15:28:00 BST 2014 armv6l GNU/Linux

GnuTLS 3.2.0

Beagle Bone Black
-----------------
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
