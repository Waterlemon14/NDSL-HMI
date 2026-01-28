#!/bin/bash

# Generate Keys and CSRs
# Client
openssl req -new -nodes -newkey rsa:4096 -keyout ../IoT/client.key \
-out client.csr -config client.cnf
# CA
openssl req -new -nodes -newkey rsa:4096 -keyout ca/ca_server.key \
-out ca_server.csr -config server.cnf
# RA
openssl req -new -nodes -newkey rsa:4096 -keyout ra/id_server.key \
-out id_server.csr -config server.cnf
# Data Server
openssl req -new -nodes -newkey rsa:4096 -keyout data/server.key \
-out server.csr -config server.cnf

# Sign Certificates
# Client
openssl x509 -req -in client.csr -copy_extensions=copy -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out ../IoT/client.crt -days 365 -sha256
# CA
openssl x509 -req -in ca_server.csr -copy_extensions=copy -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out ca/ca_server.crt -days 365 -sha256
# RA
openssl x509 -req -in id_server.csr -copy_extensions=copy -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out ra/id_server.crt -days 365 -sha256
# Data Server
openssl x509 -req -in server.csr -copy_extensions=copy -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out data/server.crt -days 365 -sha256
