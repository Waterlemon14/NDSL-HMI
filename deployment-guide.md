# AWS EC2 Deployment Guide (3-Instance, Multi-Region)

This guide deploys each server (CA, RA, Data) on its own EC2 instance in a separate AWS region. All inter-instance communication uses TLS over the public internet.

## Architecture Overview

| Instance | Server | Port  | Region (example)       |
|----------|--------|-------|------------------------|
| CA       | CA     | 15000 | us-west-1              |
| RA       | RA     | 8000  | ap-southeast-2         |
| Data     | Data   | 8443  | eu-north-1             |

The RA instance communicates with the CA instance over the public internet (HTTPS).

## Instance Setup

1. Launch a **t2.micro** instance in each region (free tier covers 750 hrs/month per region)
   - AMI: Amazon Linux 2023 or Ubuntu 24.04
   - Storage: 8 GB gp3 (default)
   - Key pair: Create or select an SSH key (one per region)

2. Allocate an **Elastic IP** in each region and associate it with the instance
   - EC2 > Elastic IPs > Allocate > Associate with the instance

3. Note down the Elastic IPs:
   - `<CA_IP>` — CA instance's Elastic IP
   - `<RA_IP>` — RA instance's Elastic IP
   - `<DATA_IP>` — Data instance's Elastic IP

## Security Group Configuration

Create a security group for each instance in its respective region.

### CA Instance Security Group

| Type       | Port  | Source         | Description                |
|------------|-------|----------------|----------------------------|
| SSH        | 22    | Your IP        | SSH access                 |
| Custom TCP | 15000 | `<RA_IP>`/32   | RA -> CA certificate calls |

> **Note:** Only the RA instance's Elastic IP should have access to port 15000. Do not expose the CA to `0.0.0.0/0`.

### RA Instance Security Group

| Type       | Port  | Source      | Description       |
|------------|-------|-------------|-------------------|
| SSH        | 22    | Your IP     | SSH access        |
| Custom TCP | 8000  | 0.0.0.0/0   | RA server (HTTPS) |

### Data Instance Security Group

| Type       | Port  | Source      | Description          |
|------------|-------|-------------|----------------------|
| SSH        | 22    | Your IP     | SSH access           |
| Custom TCP | 8443  | 0.0.0.0/0   | Data server (mTLS)   |

To restrict public access to specific IPs, replace `0.0.0.0/0` with your IP range (e.g., `203.0.113.0/24`).

> **Note:** When the RA instance's Elastic IP changes (e.g., instance replacement), update the CA security group to match.

## Deployment Steps

### 1. Copy project files to each instance

```bash
# Common rsync options
RSYNC_EXCLUDE='--exclude=.git --exclude=__pycache__ \
  --exclude=IoT --exclude=.claude --exclude=.cursor --exclude=.vscode'

# CA instance
rsync -avz $RSYNC_EXCLUDE \
  -e "ssh -i ~/.ssh/aldemita_morp_ca.pem" \
  /Users/eisenii/Desktop/Projects/1NDSL-HMI/ca ec2-user@<CA_IP>:/opt/ndsl-hmi/ca

# RA instance
rsync -avz $RSYNC_EXCLUDE \
  -e "ssh -i ~/.ssh/aldemita_morp_ra.pem" \
  /Users/eisenii/Desktop/Projects/1NDSL-HMI/ra ec2-user@<RA_IP>:/opt/ndsl-hmi/ra

# Data instance
rsync -avz $RSYNC_EXCLUDE \
  -e "ssh -i ~/.ssh/aldemita_morp_data.pem" \
  /Users/eisenii/Desktop/Projects/1NDSL-HMI/data ec2-user@<DATA_IP>:/opt/ndsl-hmi/data
```

### 2. Run initial setup on each instance (once)

SSH into each instance and run:

```bash
sudo bash /opt/ndsl-hmi/servers/ca/setup.sh
sudo bash /opt/ndsl-hmi/servers/ra/setup.sh
sudo bash /opt/ndsl-hmi/servers/data/setup.sh
```

### 3. Configure environment and certificates

#### RA instance `.env`

Update `servers/ra/.env`:
  - `EC2_PUBLIC_IP=<RA_IP>`
  - `CA_URL=https://<CA_IP>:15000` (so the RA can reach the CA over the internet)
  - `DJANGO_SECRET_KEY='<generate with command below>'`

Generate a secret key:
```bash
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

> **IMPORTANT:** Wrap the secret key value in single quotes in the .env file
> to prevent `#` and `$` characters from being interpreted as comments/variables.

#### TLS certificates

Generate the root CA **once**, then distribute `root-ca.crt` and `root-ca.key` to the other two instances before running `setup.sh`. Delete `root-ca.key` on non-CA instances after.

```bash
# On the first instance
cd /opt/ndsl-hmi/servers
bash initCA.sh
```

Edit `servers/server.cnf` on each instance with the appropriate IPs in `[alt_names]`:

**CA instance** `server.cnf`:
```
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = <CA_IP>
```

**RA instance** `server.cnf`:
```
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = <RA_IP>
```

**Data instance** `server.cnf`:
```
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = <DATA_IP>
```

Then regenerate server certificates on each instance:
### 4. Deploy each server

```bash
# On the CA instance
sudo bash /opt/ndsl-hmi/servers/deploy/deploy-ca.sh

# On the RA instance
sudo bash /opt/ndsl-hmi/servers/deploy/deploy-ra.sh

# On the Data instance
sudo bash /opt/ndsl-hmi/servers/deploy/deploy-data.sh
```

```bash
# On the RA instance — fix cert permissions
sudo chmod 644 /opt/ndsl-hmi/servers/ra/id_server.crt
sudo chmod 644 /opt/ndsl-hmi/servers/ra/id_server.key
```

## RA -> CA Connection

The RA server currently has the CA URL hardcoded to `localhost:15000` in:
- `idverification/views/views_device.py` (sign, renew)
- `idverification/views/views_data.py` (revoke)
- `idverification/views/views_ra.py` (revoke)

With separate instances, these must be updated to point to `https://<CA_IP>:15000`. Consider making this configurable via the `CA_URL` environment variable in `.env`.

## Managing Services

```bash
# On each instance, check the relevant service
sudo systemctl status ndsl-ca       # CA instance
sudo systemctl status ndsl-ra       # RA instance
sudo systemctl status ndsl-data     # Data instance

# View logs
sudo journalctl -u ndsl-ca -f       # CA instance
sudo journalctl -u ndsl-ra -f       # RA instance
sudo journalctl -u ndsl-data -f     # Data instance

# Restart a service
sudo systemctl restart ndsl-ra      # example

# SSH into each instance
ssh -i ca-key.pem ec2-user@<CA_IP>
ssh -i ra-key.pem ec2-user@<RA_IP>
ssh -i data-key.pem ec2-user@<DATA_IP>
```

## Cost Summary

### During AWS Free Tier (first 12 months)

The free tier includes 750 hrs/month of t2.micro **per region**, so all 3 instances are covered.

| Resource                   | Monthly Cost  |
|----------------------------|---------------|
| 3x t2.micro (free tier)   | Free          |
| 3x 8 GB gp3 EBS           | Free (30 GB included per region) |
| 3x Elastic IP              | Free          |
| Supabase (free tier)       | Free          |
| Data transfer (cross-region) | ~$0.50 (minimal RA <-> CA traffic) |
| **Total**                  | **~$0.50**    |

### After Free Tier expires

| Resource                     | Monthly Cost  |
|------------------------------|---------------|
| 3x t2.micro (on-demand)     | ~$25.50       |
| 3x 8 GB gp3 EBS             | ~$1.92        |
| 3x Elastic IP                | Free          |
| Supabase (free tier)         | Free          |
| Data transfer (cross-region) | ~$0.50        |
| **Total**                    | **~$27.92**   |

With 1-year reserved instances: **~$16.70/month**
