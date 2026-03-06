#!/bin/bash
# EC2 Instance Bootstrap Script for NDSL-HMI
# Run once on a fresh Amazon Linux 2023 or Ubuntu 24.04 instance
# Usage: sudo bash setup.sh

set -euo pipefail

echo "=== NDSL-HMI EC2 Setup ==="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

# 1. Install system dependencies
echo "--- Installing system dependencies ---"
if [ "$OS" = "amzn" ]; then
    dnf update -y
    dnf install -y python3 python3-pip python3-devel gcc git libzbar-devel
elif [ "$OS" = "ubuntu" ]; then
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv python3-dev gcc libzbar0 libpq-dev
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# 2. Create app user and directory
echo "--- Creating directory ---"
mkdir -p /opt/ndsl-hmi
chown -R ec2-user:ec2-user /opt/ndsl-hmi

echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Update .env files with EC2_PUBLIC_IP and DJANGO_SECRET_KEY"
echo "  2. Update server.cnf with EC2 IP in SANs, then regenerate TLS certs"
echo "  3. Run: sudo bash /opt/ndsl-hmi/ra/deploy-ra.sh"
