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

# 1. Configure 1GB swap (critical for t3.nano with 0.5GB RAM)
echo "--- Setting up 1GB swap ---"
if [ ! -f /swapfile ]; then
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "Swap configured"
else
    echo "Swap already exists"
fi

# 2. Install system dependencies
echo "--- Installing system dependencies ---"
if [ "$OS" = "amzn" ]; then
    dnf update -y
    dnf install -y golang python3 python3-pip python3-devel gcc zbar
elif [ "$OS" = "ubuntu" ]; then
    apt-get update -y
    apt-get install -y golang-go python3 python3-pip python3-venv python3-dev gcc libzbar0 libpq-dev
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# 3. Create app user and directory
echo "--- Creating ndsl user and directory ---"
if ! id -u ndsl &>/dev/null; then
    useradd -r -m -s /bin/bash ndsl
fi
mkdir -p /opt/ndsl-hmi
chown -R ndsl:ndsl /opt/ndsl-hmi

echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Copy project files to /opt/ndsl-hmi/"
echo "  2. Run: bash /opt/ndsl-hmi/servers/deploy/deploy.sh"
echo "  3. Update .env files with correct EC2_PUBLIC_IP"
echo "  4. Regenerate TLS certificates with EC2 IP in SANs"
