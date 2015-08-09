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


Test Instructions
=================

To build and test the message parser/formatter
----------------------------------------------

$ cd coap/test_msg

$ make

$ ./test_msg


To build and run the server test application
--------------------------------------------

$ cd coap/test_server

$ make

$ ./server

To build and run the client test application
--------------------------------------------

$ cd coap/test_client

$ make

$ ./client

To build and run the server test application with DTLS enabled
--------------------------------------------------------------

$ cd coap/test_server

$ make dtls=y

$ ./server

To build and run the client test application with DTLS enabled
--------------------------------------------------------------

$ cd coap/test_client

$ make dtls=y

$ ./client
