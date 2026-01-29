#!/bin/bash

# Generate CA Private Key
openssl genrsa -out root-ca.key 4096

# Self-sign CA certificate
openssl req -x509 -new -nodes -key root-ca.key \
-sha256 -days 3650 -config root-ca.cnf -out root-ca.crt # can remove -nodes flag to encrypt private key with password you provide

# Public copy of  CA cert
cp root-ca.crt ../IoT/go/root-ca.crt
cp root-ca.crt data/root-ca.crt
cp root-ca.crt ra/root-ca.crt
cp root-ca.crt ca/root-ca.crt
cp root-ca.key ca/root-ca.key