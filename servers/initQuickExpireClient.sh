#!/bin/bash

# Generate Keys and CSRs
openssl req -new -nodes -newkey rsa:4096 -keyout ../IoT/client.key \
-out client.csr -config client.cnf

# Sign Certificates
EXPIRY=$(date -u -v+1M +"%Y%m%d%H%M%SZ")

openssl x509 -req -in client.csr -copy_extensions=copy -CA ca/root-ca.crt -CAkey ca/root-ca.key -CAcreateserial -sha256 -not_after "$EXPIRY" -out ../IoT/client.crt

rm -f client.csr

cp ../IoT/client.key ../IoT/go/client.key
cp ../IoT/client.crt ../IoT/go/client.crt
