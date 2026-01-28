#!/bin/bash

# Sign Server Cert
openssl x509 -req -in server.csr -copy_extensions=copy -CA certs/root-ca.crt -CAkey root-ca.key -CAcreateserial -out certs/server.crt -days 365 -sha256
