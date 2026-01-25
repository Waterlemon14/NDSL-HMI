init.sh
#!/bin/bash

# Generate Keys
openssl genpkey -algorithm RSA -out ca.key
openssl genpkey -algorithm RSA -out ca_server_private.key
openssl genpkey -algorithm RSA -out id_server_private.key

# Self-sign CA certificate
openssl req -config CA.cnf -new -x509 -key ca.key \
-out ca.crt -extensions ca_cert_ext \
-subj "/C=PH/O=CA"

# Make Certificate Signing Requests
openssl req -new -key ca_server_private.key -out ca_server.csr \
-subj "/C=PH/ST=Metro Manila/L=Quezon City/O=server/CN=localhost" \
-addext "subjectAltName=DNS:localhost,IP:172.19.83.216"

openssl req -new -key id_server_private.key -out id_server.csr \
-subj "/C=PH/ST=Metro Manila/L=Quezon City/O=server/CN=localhost" \
-addext "subjectAltName=DNS:localhost,IP:192.168.0.212"

# Sign necessary certificate requests
openssl x509 -req -in ca_server.csr -CA ca.crt -CAkey ca.key \
-CAcreateserial -out ca_server.crt -days 365 -copy_extensions copy

openssl x509 -req -in id_server.csr -CA ca.crt -CAkey ca.key \
-CAcreateserial -out id_server.crt -days 365 -copy_extensions copy

# Public copy of public key and CA cert
# cp public.key ../shared/CAPublic.key
cp ca.crt ../ca.crt

# Move non-CA files outside
mv id_server_private.key ../
mv id_server.csr ../
mv id_server.crt ../