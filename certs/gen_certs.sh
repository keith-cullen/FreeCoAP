#!/bin/bash

# remove a file if it exists
function rmcond {
    if [ -e $1 ]; then
	/bin/rm $1
    fi
}

rmcond root_server_privkey.pem
rmcond root_server_cert.pem
rmcond server_privkey.pem
rmcond server_cert.pem
rmcond root_client_privkey.pem
rmcond root_client_cert.pem
rmcond client_privkey.pem
rmcond client_cert.pem

echo "----------------------------------------"
echo "Root Server Private Key"
echo "----------------------------------------"
certtool --generate-privkey \
         --ecc \
         --curve secp256r1 \
         --outfile root_server_privkey.pem
echo ""

echo "----------------------------------------"
echo "Root Server Certificate"
echo "----------------------------------------"
certtool --generate-self-signed \
         --ecc \
         --curve secp256r1 \
         --template root_template.txt \
         --outfile root_server_cert.pem \
         --load-privkey root_server_privkey.pem
echo ""

echo "----------------------------------------"
echo "Server Private Key"
echo "----------------------------------------"
certtool --generate-privkey \
         --ecc \
         --curve secp256r1 \
         --outfile server_privkey.pem
echo ""

echo "----------------------------------------"
echo "Server Certificate"
echo "----------------------------------------"
certtool --generate-certificate \
         --ecc \
         --curve secp256r1 \
         --template server_template.txt \
         --outfile server_cert.pem \
         --load-privkey server_privkey.pem \
         --load-ca_certificate root_server_cert.pem \
         --load-ca-privkey root_server_privkey.pem
echo ""

echo "----------------------------------------"
echo "Root Client Private Key"
echo "----------------------------------------"
certtool --generate-privkey \
         --ecc \
         --curve secp256r1 \
         --outfile root_client_privkey.pem
echo ""

echo "----------------------------------------"
echo "Root Client Certificate"
echo "----------------------------------------"
certtool --generate-self-signed \
         --ecc \
         --curve secp256r1 \
         --template root_template.txt \
         --outfile root_client_cert.pem \
         --load-privkey root_client_privkey.pem
echo ""

echo "----------------------------------------"
echo "Client Private Key"
echo "----------------------------------------"
certtool --generate-privkey \
         --ecc \
         --curve secp256r1 \
         --outfile client_privkey.pem
echo ""

echo "----------------------------------------"
echo "Client Certificate"
echo "----------------------------------------"
certtool --generate-certificate \
         --ecc \
         --curve secp256r1 \
         --template client_template.txt \
         --outfile client_cert.pem \
         --load-privkey client_privkey.pem \
         --load-ca_certificate root_client_cert.pem \
         --load-ca-privkey root_client_privkey.pem
echo ""
