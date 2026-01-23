#!/bin/bash

# Generate Server Private Key
openssl req -new -nodes -newkey rsa:4096 -keyout server.key \
-out server.csr -config server.cnf


# Make Certificate Signing Request
# openssl req -new -key server.key -out server.csr \
# -subj "/C=PH/ST=Metro Manila/L=Quezon City/O=server/CN=ndsl-server.com" \
# -addext "subjectAltName=DNS:ndsl-server.com,DNS:localhost,IP:127.0.0.1"

# Send CSR to CA and receive signed Certificate
# curl --data-binary @server.csr -H "Content-Type: application/pem-csr" http://localhost:15000/sign -o server.crt
