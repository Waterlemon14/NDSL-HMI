#!/bin/bash
# Deploy CA server only
# Usage: sudo bash deploy-ca.sh

set -euo pipefail

APP_DIR="/opt/ndsl-hmi"

echo "=== Deploying CA server ==="

# Build
echo "--- Building CA server ---"
cd "$APP_DIR/ca"
go build -o ca-server .
echo "CA server built"

# Generate new keys and certificates for CA server
openssl req -new -nodes -newkey rsa:4096 -keyout ca/ca_server.key \
-out ca_server.csr -config server.cnf
openssl x509 -req -in ca_server.csr -copy_extensions=copy -CA ca/root-ca.crt -CAkey ca/root-ca.key -CAcreateserial -out ca/ca_server.crt -days 365 -sha256
rm -f ca_server.csr

# Fix ownership and permissions
chown -R ec2-user:ec2-user "$APP_DIR/ca"
sudo chmod 644 $APP_DIR/ca/ca_server.crt
sudo chmod 644 $APP_DIR/ca/ca_server.key

# Install and restart systemd service
echo "--- Restarting CA service ---"
cp "$APP_DIR/deploy/ndsl-ca.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ndsl-ca
systemctl restart ndsl-ca

echo ""
echo "=== CA deploy complete ==="
echo ""
systemctl status ndsl-ca --no-pager
