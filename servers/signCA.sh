#!/bin/bash

# Sign Server Cert
openssl x509 -req -in ca_server.csr -copy_extensions=copy -CA certs/root-ca.crt -CAkey root-ca.key -CAcreateserial -out certs/ca_server.crt -days 365 -sha256
