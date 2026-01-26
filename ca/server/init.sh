#!/bin/bash

# Generate Server Private Key
openssl req -new -nodes -newkey rsa:4096 -keyout ca_server.key \
-out ca_server.csr -config server.cnf