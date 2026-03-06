#!/bin/bash

# Generate CA Private Key
openssl genrsa -out ca/root-ca.key 4096

# Self-sign CA certificate
openssl req -x509 -new -nodes -key ca/root-ca.key \
-sha256 -days 3650 -config ca/root-ca.cnf -out ca/root-ca.crt # can remove -nodes flag to encrypt private key with password you provide

# Public copy of  CA cert
cp ca/root-ca.crt data/root-ca.crt
cp ca/root-ca.crt ra/root-ca.crt

cp ca/root-ca.crt ../IoT/go/root-ca.crt
cp ca/root-ca.crt ../IoT/esp8266/data/root-ca.crt
cp ca/root-ca.crt ../IoT/esp32/data/root-ca.crt
cp ca/root-ca.crt ../IoT/pico/data/root-ca.crt