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
openssl req -new -nodes -newkey rsa:4096 -keyout $APP_DIR/ca/ca_server.key -out $APP_DIR/ca/ca_server.csr -config $APP_DIR/ca/server.cnf
openssl x509 -req -in $APP_DIR/ca/ca_server.csr -copy_extensions=copy -CA $APP_DIR/ca/root-ca.crt -CAkey $APP_DIR/ca/root-ca.key -CAcreateserial -out $APP_DIR/ca/ca_server.crt -days 365 -sha256
rm -f $APP_DIR/ca/ca_server.csr

# Fix ownership and permissions
chown -R ec2-user:ec2-user "$APP_DIR/ca"
chmod 644 $APP_DIR/ca/ca_server.crt
chmod 644 $APP_DIR/ca/ca_server.key

# Install and restart systemd service
echo "--- Restarting CA service ---"
cp "$APP_DIR/ca/ndsl-ca.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ndsl-ca
systemctl restart ndsl-ca

echo ""
echo "=== CA deploy complete ==="
echo ""
systemctl status ndsl-ca --no-pager
