========
FreeCoAP
========

An implementation of the CoAP protocol for GNU/Linux consisting of:

- a CoAP message parser/formatter library

- a CoAP client library

- a CoAP server library

- unit test code for the message parser/formatter

- a sample test client application

- a sample test server application

Copyright (c) 2015 Keith Cullen

Released under a BSD style license.

Contact: <keithcullen77@gmail.com>


Test Instructions
=================

To build and test the message parser/formatter
----------------------------------------------

$ cd coap/test_msg

$ make

$ ./test_msg


To build and test the client/server
-----------------------------------

By default:

The client and server test applications run on the same system.

The server test application listens on UDP port 12436.

$ cd coap/test_server

$ make

$ ./server

(in a different termninal)

$ cd coap/test_client

$ make

$ ./client
