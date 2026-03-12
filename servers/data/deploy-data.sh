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
openssl req -new -nodes -newkey rsa:4096 -keyout $APP_DIR/data/server.key \
-out $APP_DIR/data/server.csr -config $APP_DIR/data/server.cnf
openssl x509 -req -in $APP_DIR/data/server.csr -copy_extensions=copy -CA $APP_DIR/data/root-ca.crt -CAkey $APP_DIR/data/root-ca.key -CAcreateserial -out $APP_DIR/data/server.crt -days 365 -sha256
# rm -f $APP_DIR/data/root-ca.key
rm -f $APP_DIR/data/server.csr

# Fix ownership and permissions
chown -R ec2-user:ec2-user "$APP_DIR/data"
sudo chmod 644 $APP_DIR/data/server.crt
sudo chmod 644 $APP_DIR/data/server.key

sudo chmod 644 $APP_DIR/data/root-ca.crt

# Install and restart systemd service
echo "--- Restarting Data service ---"
cp "$APP_DIR/data/ndsl-data.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ndsl-data
systemctl restart ndsl-data

echo ""
echo "=== Data deploy complete ==="
echo ""
systemctl status ndsl-data --no-pager
