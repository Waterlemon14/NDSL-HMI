#!/bin/bash

# Generate Server Private Key
openssl req -new -nodes -newkey rsa:4096 -keyout id_server.key \
-out id_server.csr -config server.cnf