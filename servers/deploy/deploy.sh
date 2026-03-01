#!/bin/bash
# NDSL-HMI Deployment Script
# Run on the EC2 instance after setup.sh and after syncing project files
# Usage: sudo bash deploy.sh

set -euo pipefail

APP_DIR="/opt/ndsl-hmi"
SERVERS_DIR="$APP_DIR/servers"

echo "=== NDSL-HMI Deploy ==="

# 1. Build CA server
echo "--- Building CA server ---"
cd "$SERVERS_DIR/ca"
go build -o ca-server .
echo "CA server built"

# 2. Build Data server
echo "--- Building Data server ---"
cd "$SERVERS_DIR/data"
go build -o data-server .
echo "Data server built"

# 3. Setup RA Python environment
echo "--- Setting up RA server ---"
cd "$SERVERS_DIR/ra"
if [ ! -d venv ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
deactivate
echo "RA server configured"

# 4. Fix ownership
chown -R ndsl:ndsl "$APP_DIR"

# 5. Install and enable systemd services
echo "--- Installing systemd services ---"
cp "$SERVERS_DIR/deploy/ndsl-ca.service" /etc/systemd/system/
cp "$SERVERS_DIR/deploy/ndsl-ra.service" /etc/systemd/system/
cp "$SERVERS_DIR/deploy/ndsl-data.service" /etc/systemd/system/
systemctl daemon-reload

systemctl enable ndsl-ca ndsl-ra ndsl-data
systemctl restart ndsl-ca
systemctl restart ndsl-ra
systemctl restart ndsl-data

echo ""
echo "=== Deploy complete ==="
echo ""
systemctl status ndsl-ca ndsl-ra ndsl-data --no-pager
