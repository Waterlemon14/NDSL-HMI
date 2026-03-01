# AWS EC2 Deployment Guide

## Instance Setup

1. Launch a **t3.nano** instance (~$3.80/month)
   - AMI: Amazon Linux 2023 or Ubuntu 24.04
   - Storage: 8 GB gp3 (default)
   - Key pair: Create or select an SSH key

2. Allocate an **Elastic IP** (free while attached to a running instance)
   - EC2 > Elastic IPs > Allocate > Associate with your instance

## Security Group Configuration

### Option A: Public Internet Access

Create a security group with these inbound rules:

| Type       | Port  | Source      | Description          |
|------------|-------|-------------|----------------------|
| SSH        | 22    | Your IP     | SSH access           |
| Custom TCP | 8000  | 0.0.0.0/0  | RA server (HTTPS)    |
| Custom TCP | 8443  | 0.0.0.0/0  | Data server (mTLS)   |
| Custom TCP | 15000 | 0.0.0.0/0  | CA server (HTTPS)    |

To restrict to specific IPs, replace `0.0.0.0/0` with your IP range (e.g., `203.0.113.0/24`).

### Option B: Private/VPN Access

Create a security group with these inbound rules:

| Type       | Port  | Source           | Description          |
|------------|-------|------------------|----------------------|
| SSH        | 22    | Your IP          | SSH access           |
| Custom TCP | 8000  | 10.0.0.0/8       | RA server (VPC only) |
| Custom TCP | 8443  | 10.0.0.0/8       | Data server          |
| Custom TCP | 15000 | 10.0.0.0/8       | CA server            |

Access via SSH tunnels from your local machine:

```bash
# Forward all 3 ports through SSH
ssh -i key.pem -L 8000:localhost:8000 -L 8443:localhost:8443 -L 15000:localhost:15000 ec2-user@<EC2_IP>
```

Then access servers at `https://localhost:8000`, etc.

## Deployment Steps

```bash
# 1. SSH into EC2
ssh -i key.pem ec2-user@<EC2_IP>

# 2. Run initial setup (once)
sudo bash /opt/ndsl-hmi/servers/deploy/setup.sh

# 3. Copy project files (from local machine)
rsync -avz --exclude='.git' --exclude='node_modules' --exclude='__pycache__' \
  -e "ssh -i key.pem" \
  /path/to/1NDSL-HMI/ ec2-user@<EC2_IP>:/opt/ndsl-hmi/

# 4. Update .env files with EC2 IP
#    - servers/ra/.env: set EC2_PUBLIC_IP=<your-elastic-ip>
#    - servers/ra/.env: set DJANGO_DEBUG=False
#    - servers/ra/.env: set DJANGO_SECRET_KEY=<generate-a-real-key>

# 5. Regenerate TLS certificates with EC2 IP in SANs
#    Update server.cnf to include the EC2 IP, then:
cd /opt/ndsl-hmi/servers
bash initCA.sh        # Only if root CA doesn't exist yet
bash initServers.sh   # Regenerate server certs

# 6. Deploy (build, migrate, restart services)
sudo bash /opt/ndsl-hmi/servers/deploy/deploy.sh
```

## Managing Services

```bash
# Check status of all 3 servers
sudo systemctl status ndsl-ca ndsl-ra ndsl-data

# View logs
sudo journalctl -u ndsl-ca -f        # CA logs
sudo journalctl -u ndsl-ra -f        # RA logs
sudo journalctl -u ndsl-data -f      # Data logs

# Restart a specific service
sudo systemctl restart ndsl-ra

# Stop all services
sudo systemctl stop ndsl-ca ndsl-ra ndsl-data
```

## Cost Summary

| Resource            | Monthly Cost  |
|---------------------|---------------|
| t3.nano (on-demand) | ~$3.80        |
| 8 GB gp3 EBS        | ~$0.64        |
| Elastic IP           | Free          |
| Supabase (free tier) | Free          |
| **Total**            | **~$4.44**    |

With 1-year reserved instance: **~$2.15/month**
