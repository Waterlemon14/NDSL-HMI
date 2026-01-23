#!/bin/bash

# Sign Client Cert
openssl x509 -req -in client.csr -copy_extensions=copy -CA certs/root-ca.crt -CAkey root-ca.key -CAcreateserial -out certs/client.crt -days 365 -sha256
