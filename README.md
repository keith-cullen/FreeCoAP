=========
coap-zero
=========

An implementation of a CoAP message parser/formatter, a CoAP client and a CoAP server.

Keith Cullen <keithcullen77@gmail.com>


Test Instructions
=================

GNU/Linux

To build and test the message parser/formatter
----------------------------------------------
$ cd coap/test_msg
$ make
$ ./test_msg

To test the client/server
-------------------------
By default:
  The client and server test applications run on the same system.
  The server test application listens on UDP port 12436.

$ cd coap/test_server
$ make
$ ./server

$ cd coap/test_client
$ make
$ ./client
