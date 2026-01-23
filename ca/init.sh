#!/bin/bash

# Generate CA Private Key
openssl genrsa -out root-ca.key 4096

# Self-sign CA certificate
openssl req -x509 -new -nodes -key root-ca.key \
-sha256 -days 3650 -config root-ca.cnf -out certs/root-ca.crt # can remove -nodes flag to encrypt private key with password you provide

# 
# openssl x509 -in certs/ca.crt -out certs/ca.crt -outform PEM


# Public copy of public key and CA cert
# cp public.key ../shared/CAPublic.key
cp certs/root-ca.crt ../middleware/data/ca.crt
# cp certs/root-ca.crt ../device/ca.crt