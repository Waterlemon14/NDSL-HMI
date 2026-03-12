# AWS EC2 Deployment Guide

## Instance Setup

1. Launch a **t2.micro** instance (free tier eligible for 12 months)
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

> **Note:** The CA server (port 15000) is internal-only — it is called by the RA on localhost and does not need to be exposed.

To restrict to specific IPs, replace `0.0.0.0/0` with your IP range (e.g., `203.0.113.0/24`).

### Option B: Private/VPN Access

Create a security group with these inbound rules:

| Type       | Port  | Source           | Description          |
|------------|-------|------------------|----------------------|
| SSH        | 22    | Your IP          | SSH access           |
| Custom TCP | 8000  | 10.0.0.0/8       | RA server (VPC only) |
| Custom TCP | 8443  | 10.0.0.0/8       | Data server          |

Access via SSH tunnels from your local machine:

```bash
# Forward RA and Data ports through SSH
ssh -i key.pem -L 8000:localhost:8000 -L 8443:localhost:8443 ec2-user@<EC2_IP>
```

Then access servers at `https://localhost:8000`, etc.

## Deployment Steps

```bash
# 1. Copy project files (from local machine)
rsync -avz --exclude='.git' --exclude='node_modules' --exclude='__pycache__' \
   --exclude='IoT' --exclude='.claude' --exclude='.cursor' --exclude='.vscode' \
   --exclude='servers/ra/venv' \
   -e "ssh -i aldemita_morp.pem" \
   /Users/eisenii/Desktop/Projects/1NDSL-HMI/ ec2-user@<EC2_IP>:/opt/ndsl-hmi/

# 2. SSH into EC2
ssh -i key.pem ec2-user@<EC2_IP>

# 3. Run initial setup (once)
sudo bash /opt/ndsl-hmi/servers/deploy/setup.sh

# 4. Update .env files on the EC2 instance
#    servers/ra/.env:
#      - EC2_PUBLIC_IP=<your-elastic-ip>
#      - DJANGO_SECRET_KEY='<generate with command below>'
#
#    Generate a secret key:
#      python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
#
#    IMPORTANT: Wrap the secret key value in single quotes in the .env file
#    to prevent # and $ characters from being interpreted as comments/variables.

# 5. Update server.cnf with EC2 IP, then regenerate TLS certificates
#    Edit servers/server.cnf:
#      - Change CN to your EC2 IP
#      - Add your EC2 IP to [alt_names] (keep localhost for internal communication):
#          DNS.1 = localhost
#          IP.1 = 127.0.0.1
#          IP.2 = <your-elastic-ip>
#
#    Then regenerate certificates:
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

### During AWS Free Tier (first 12 months)

| Resource            | Monthly Cost  |
|---------------------|---------------|
| t2.micro (free tier) | Free          |
| 8 GB gp3 EBS        | Free (30 GB included) |
| Elastic IP           | Free          |
| Supabase (free tier) | Free          |
| **Total**            | **Free**      |

### After Free Tier expires

| Resource              | Monthly Cost  |
|-----------------------|---------------|
| t2.micro (on-demand)  | ~$8.50        |
| 8 GB gp3 EBS          | ~$0.64        |
| Elastic IP             | Free          |
| Supabase (free tier)   | Free          |
| **Total**              | **~$9.14**    |

With 1-year reserved instance: **~$5.40/month**
