#!/bin/bash

echo "---------------------"
echo "Generating Client Key"
echo "---------------------"
openssl ecparam -genkey -name prime256v1 -out client.pem

echo "-----------------------------"
echo "Generating Client Private Key"
echo "-----------------------------"
openssl ec -in client.pem -outform DER | tail -c +8 | head -c 32 | xxd -p -c 32 > client_priv_key.txt

echo "----------------------------"
echo "Generating Client Public Key"
echo "----------------------------"
openssl ec -in client.pem -pubout -outform DER | tail -c 64 | xxd -p -c 64 > client_pub_key.txt

echo "---------------------"
echo "Generating Server Key"
echo "---------------------"
openssl ecparam -genkey -name prime256v1 -out server.pem

echo "-----------------------------"
echo "Generating Server Private Key"
echo "-----------------------------"
openssl ec -in server.pem -outform DER | tail -c +8 | head -c 32 | xxd -p -c 32 > server_priv_key.txt

echo "----------------------------"
echo "Generating Server Public Key"
echo "----------------------------"
openssl ec -in server.pem -pubout -outform DER | tail -c 64 | xxd -p -c 64 > server_pub_key.txt

echo "-------------------------------------"
echo "Generating Client Access Control List"
echo "-------------------------------------"
cp server_pub_key.txt client_access.txt

echo "-------------------------------------"
echo "Generating Server Access Control List"
echo "-------------------------------------"
cp client_pub_key.txt server_access.txt
