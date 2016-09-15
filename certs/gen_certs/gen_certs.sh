#!/bin/bash

set -e # exit on error

# remove a file if it exists
function rmcond {
    if [ -e $1 ]; then
	rm $1
	echo "removed ${1}"
    else
	echo "        ${1}"
    fi
}

# remove all existing keys, certs and signing requests
echo "------------------------------------------------"
echo "Remove existing keys, certs and signing requests"
echo "------------------------------------------------"
rmcond ./root_server/100001.pem
rmcond ./root_server/certindex.txt
rmcond ./root_server/certindex.txt.attr
rmcond ./root_server/certindex.txt.attr.old
rmcond ./root_server/certindex.txt.old
rmcond ./root_server/root_server_cert.pem
rmcond ./root_server/root_server_privkey.pem
rmcond ./root_server/serial.txt
rmcond ./root_server/serial.txt.old
rmcond ./server/server_cert.csr
rmcond ./server/server_cert.pem
rmcond ./server/server_privkey.pem
rmcond ./root_client/100001.pem
rmcond ./root_client/certindex.txt
rmcond ./root_client/certindex.txt.attr
rmcond ./root_client/certindex.txt.attr.old
rmcond ./root_client/certindex.txt.old
rmcond ./root_client/root_client_cert.pem
rmcond ./root_client/root_client_privkey.pem
rmcond ./root_client/serial.txt
rmcond ./root_client/serial.txt.old
rmcond ./client/client_cert.csr
rmcond ./client/client_cert.pem
rmcond ./client/client_privkey.pem

# reset the serial.txt files
echo '100001' > root_server/serial.txt
echo '100001' > root_client/serial.txt

# reset the certindex.txt files
touch root_server/certindex.txt
touch root_client/certindex.txt

echo "------------------------------"
echo "Create Root Server Private Key"
echo "------------------------------"
#openssl genrsa -out ./root_server/root_server_privkey.pem 2048
openssl ecparam -name secp256r1 -genkey -param_enc explicit -out ./root_server/root_server_privkey.pem

echo "------------------------------"
echo "Create Root Server Certificate"
echo "------------------------------"
# the -x509 option outputs a self signed certificate instead of a certificate request
openssl req -config ./root_server.conf -new -x509 -days 3652 -key ./root_server/root_server_privkey.pem -out ./root_server/root_server_cert.pem

echo "-------------------------"
echo "Create Server Private Key"
echo "-------------------------"
#openssl genrsa -out ./server/server_privkey.pem 2048
openssl ecparam -name secp256r1 -genkey -out ./server/server_privkey.pem

echo "---------------------------------"
echo "Create Server Certificate Request"
echo "---------------------------------"
openssl req -config ./server.conf -new -key ./server/server_privkey.pem -out ./server/server_cert.csr

echo "-------------------------------"
echo "Sign Server Certificate Request"
echo "-------------------------------"
openssl ca -config ./root_server.conf -cert ./root_server/root_server_cert.pem -keyfile ./root_server/root_server_privkey.pem -out ./server/server_cert.pem -infiles ./server/server_cert.csr

echo "------------------------------"
echo "Create Root Client Private Key"
echo "------------------------------"
#openssl genrsa -out ./root_client/root_client_privkey.pem 2048
openssl ecparam -name secp256r1 -genkey -out ./root_client/root_client_privkey.pem

echo "------------------------------"
echo "Create Root Client Certificate"
echo "------------------------------"
# the -x509 option outputs a self signed certificate instead of a certificate request
openssl req -config ./root_client.conf -new -x509 -days 3652 -key ./root_client/root_client_privkey.pem -out ./root_client/root_client_cert.pem

echo "-------------------------"
echo "Create Client Private Key"
echo "-------------------------"
#openssl genrsa -out ./client/client_privkey.pem 2048
openssl ecparam -name secp256r1 -genkey -out ./client/client_privkey.pem

echo "---------------------------------"
echo "Create Client Certificate Request"
echo "---------------------------------"
openssl req -config ./client.conf -new -key ./client/client_privkey.pem -out ./client/client_cert.csr

echo "-------------------------------"
echo "Sign Client Certificate Request"
echo "-------------------------------"
openssl ca -config ./root_client.conf -cert ./root_client/root_client_cert.pem -keyfile ./root_client/root_client_privkey.pem -out ./client/client_cert.pem -infiles ./client/client_cert.csr

echo "--------------------------------------------------"
echo "copy keys and certificates to the parent directory"
echo "--------------------------------------------------"
cp ./root_server/root_server_cert.pem ..
echo "root_server_cert.pem copied to the parent directory"
cp ./server/server_cert.pem ..
echo "server_cert.pem copied to the parent directory"
cp ./server/server_privkey.pem ..
echo "server_privkey.pem copied to the parent directory"
cp ./root_client/root_client_cert.pem ..
echo "root_client_cert.pem copied to the parent directory"
cp ./client/client_cert.pem ..
echo "client_cert.pem copied to the parent directory"
cp ./client/client_privkey.pem ..
echo "client_privkey.pem copied to the parent directory"

echo "-------"
echo "Success"
echo "-------"
