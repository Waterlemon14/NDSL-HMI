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

# 1. Configure 1GB swap (recommended for t2.micro with 1GB RAM during Go builds)
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

# 2. Install Go from official tarball (package manager versions are too old)
GO_VERSION="1.25.1"
if ! go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    echo "--- Installing Go ${GO_VERSION} ---"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GOARCH="amd64" ;;
        aarch64) GOARCH="arm64" ;;
        *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    curl -OL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    rm "go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    echo "Go ${GO_VERSION} installed"
else
    echo "Go ${GO_VERSION} already installed"
fi

# 3. Create app user and directory
echo "--- Creating directory ---"
mkdir -p /opt/ndsl-hmi
chown -R ec2-user:ec2-user /opt/ndsl-hmi

echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Update .env files with EC2_PUBLIC_IP and DJANGO_SECRET_KEY"
echo "  2. Update server.cnf with EC2 IP in SANs, then regenerate TLS certs"
echo "  3. Run: sudo bash /opt/ndsl-hmi/ca/deploy-ca.sh"
