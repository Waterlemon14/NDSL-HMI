#!/bin/bash
# Deploy RA server only
# Usage: bash deploy-ra.sh

set -euo pipefail

APP_DIR="/opt/ndsl-hmi"

echo "=== Deploying RA server ==="

# Setup Python environment
echo "--- Setting up RA server ---"
cd "$APP_DIR/ra"
if [ ! -d venv ]; then
    python3.13 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
deactivate
echo "RA server configured"

# Generate new keys and certificates for RA server
openssl req -new -nodes -newkey rsa:4096 -keyout $APP_DIR/ra/id_server.key -out $APP_DIR/ra/id_server.csr -config $APP_DIR/ra/server.cnf
openssl x509 -req -in $APP_DIR/ra/id_server.csr -copy_extensions=copy -CA $APP_DIR/ra/root-ca.crt -CAkey $APP_DIR/ra/root-ca.key -CAcreateserial -out $APP_DIR/ra/id_server.crt -days 365 -sha256
# rm -f $APP_DIR/ra/root-ca.key
rm -f $APP_DIR/ra/id_server.csr

# Fix ownership and permissions
chown -R ec2-user:ec2-user "$APP_DIR/ra"
chmod 644 $APP_DIR/ra/id_server.crt
chmod 644 $APP_DIR/ra/id_server.key

chmod 644 $APP_DIR/ra/root-ca.crt

chmod 644 $APP_DIR/ra/config.toml
chmod 644 $APP_DIR/ra/config.toml
chmod 644 $APP_DIR/ra/cs-198-2-keystore-signed.p12
chmod 644 $APP_DIR/ra/cs-198-2-keystore.p12

chmod 644 $APP_DIR/ra/.env

chmod 777 $APP_DIR/ra/authenticator.log

# Install and restart systemd service
echo "--- Restarting RA service ---"
cp "$APP_DIR/ra/ndsl-ra.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ndsl-ra
systemctl restart ndsl-ra

# Setup nginx as reverse proxy for TLS/mTLS termination
echo "--- Setting up nginx ---"
yum install -y nginx || apt-get install -y nginx
cp "$APP_DIR/ra/nginx-ra.conf" /etc/nginx/conf.d/ndsl-ra.conf
rm -f /etc/nginx/conf.d/default.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

echo ""
echo "=== RA deploy complete ==="
echo ""
systemctl status ndsl-ra --no-pager
systemctl status nginx --no-pager
