#!/bin/bash
# Deploy Data server only
# Usage: sudo bash deploy-data.sh

set -euo pipefail

APP_DIR="/opt/ndsl-hmi"

echo "=== Deploying Data server ==="

# Build
echo "--- Building Data server ---"
cd "$APP_DIR/data"
go build -o data-server .
echo "Data server built"

# Generate new keys and certificates for data server
openssl req -new -nodes -newkey rsa:4096 -keyout data/server.key \
-out server.csr -config server.cnf
openssl x509 -req -in server.csr -copy_extensions=copy -CA ca/root-ca.crt -CAkey ca/root-ca.key -CAcreateserial -out data/server.crt -days 365 -sha256
rm -f root-ca.key
rm -f server.csr

# Fix ownership and permissions
chown -R ec2-user:ec2-user "$APP_DIR/data"
sudo chmod 644 $APP_DIR/data/server.crt
sudo chmod 644 $APP_DIR/data/server.key

# Install and restart systemd service
echo "--- Restarting Data service ---"
cp "$APP_DIR/deploy/ndsl-data.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ndsl-data
systemctl restart ndsl-data

echo ""
echo "=== Data deploy complete ==="
echo ""
systemctl status ndsl-data --no-pager
