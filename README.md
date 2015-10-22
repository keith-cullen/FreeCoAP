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

Tested on Intel Galileo.


Build Instructions
=================

To build the message parser/formatter for the host machine
----------------------------------------------------------

$ cd FreeCoAP/test_msg

$ ./build_host

To build the message parser/formatter for Intel Quark
-----------------------------------------------------

$ cd FreeCoAP/test_msg

$ ./build_quark

(assumes that the Quark SDK has been installed at /opt/iot-devkit/1.7.2)

To build the server test application for the host machine
---------------------------------------------------------

$ cd FreeCoAP/test_server

$ ./build_host

To build the server test application with DTLS for the host machine
-------------------------------------------------------------------

$ cd FreeCoAP/test_server

$ ./build_host dtls

To build the server test application for Intel Quark
----------------------------------------------------

$ cd FreeCoAP/test_server

$ ./build_quark

(assumes that the Quark SDK has been installed at /opt/iot-devkit/1.7.2)

To build the server test application with DTLS for Intel Quark
--------------------------------------------------------------

$ cd FreeCoAP/test_server

$ ./build_quark dtls

(assumes that the Quark SDK has been installed at /opt/iot-devkit/1.7.2)

To build the client test application for the host machine
---------------------------------------------------------

$ cd FreeCoAP/test_client

$ ./build_host

To build the client test application with DTLS for the host machine
-------------------------------------------------------------------

$ cd FreeCoAP/test_client

$ ./build_host dtls

To build the client test application for Intel Quark
----------------------------------------------------

$ cd FreeCoAP/test_client

$ ./build_quark

(assumes that the Quark SDK has been installed at /opt/iot-devkit/1.7.2)

To build the client test application with DTLS for Intel Quark
--------------------------------------------------------------

$ cd FreeCoAP/test_client

$ ./build_quark dtls

(assumes that the Quark SDK has been installed at /opt/iot-devkit/1.7.2)


Test Instructions
=================

To test the message/parser formatter
------------------------------------

$ cd FreeCoAP/test_msg

$ ./test_msg

To test the client and server test applications
-----------------------------------------------

$ cd FreeCoAP/test_server

$ ./server

(In a different terminal window)

$ cd FreeCoAP/test_client

$ ./client


Validation History
==================

v0.1
----

Ubuntu 15.04, Linux 3.19.0, x86_64, with GnuTLS 3.2.0

Fedora 21, Linux 4.1.8, x86_64, with GnuTLS 3.2.0

Quark BSP 1.2, Linux 3.14.28, i586 with GnuTLS 3.3.5
