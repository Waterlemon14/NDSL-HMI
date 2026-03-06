#!/bin/bash
# Deploy RA server only
# Usage: sudo bash deploy-ra.sh

set -euo pipefail

APP_DIR="/opt/ndsl-hmi"

echo "=== Deploying RA server ==="

# Setup Python environment
echo "--- Setting up RA server ---"
cd "$APP_DIR/ra"
if [ ! -d venv ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
deactivate
echo "RA server configured"

# Generate new keys and certificates for RA server
openssl req -new -nodes -newkey rsa:4096 -keyout ra/id_server.key \
-out id_server.csr -config server.cnf
openssl x509 -req -in id_server.csr -copy_extensions=copy -CA ca/root-ca.crt -CAkey ca/root-ca.key -CAcreateserial -out ra/id_server.crt -days 365 -sha256
rm -f root-ca.key
rm -f id_server.csr

# Fix ownership and permissions
chown -R ec2-user:ec2-user "$APP_DIR/ra"
sudo chmod 644 $APP_DIR/ra/id_server.crt
sudo chmod 644 $APP_DIR/ra/id_server.key

# Install and restart systemd service
echo "--- Restarting RA service ---"
cp "$APP_DIR/deploy/ndsl-ra.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ndsl-ra
systemctl restart ndsl-ra

echo ""
echo "=== RA deploy complete ==="
echo ""
systemctl status ndsl-ra --no-pager
