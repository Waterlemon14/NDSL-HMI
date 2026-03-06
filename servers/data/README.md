# Data Server

A Go-based HTTPS service that receives telemetry data from IoT devices over mutual TLS (mTLS). Performs anomaly detection based on reporting intervals and coordinates with the RA server to manage device states.

---

## API Endpoints

All endpoints are served over HTTPS on port **8443** with **mandatory client certificate verification** (mTLS).

### `POST /data` — Submit Telemetry

Receives temperature readings from IoT devices.

**Request body:**
```json
{
  "temp": 25.5,
  "time": "2026-03-06T10:30:00Z",
  "MAC": "aa:bb:cc:dd:ee:ff"
}
```

**Behavior by device state:**

| Device State | Action |
|-------------|--------|
| `connected` | Accept data, run anomaly detection, insert into database |
| `reconnecting` | Call RA `/reconnect/<mac>/` to transition device to connected, then accept data |
| `suspended` | Silently reject |
| `revoked` | Silently reject |

**Anomaly detection:**
- Compares the current timestamp against the device's last `created_at` entry
- If the gap exceeds **10 seconds**, the device is flagged as disconnected
- On anomaly: calls RA `POST /report/` with `{"mac": "<mac>", "anomaly": "disconnected"}`, which suspends the device

**Response:** `200 OK` (no body) on success.

---

### `POST /ping` — Health Check

Echoes back the request body with a pong response.

**Request body:** Any JSON
**Response:**
```json
{
  "requestMessage": "<echoed body>",
  "responseMessage": "pong"
}
```

---

## TLS Configuration

| Setting | Value |
|---------|-------|
| Port | 8443 |
| Client auth | `RequireAndVerifyClientCert` (mTLS enforced) |
| Min TLS version | 1.2 |
| Session tickets | Disabled |
| Server certificate | `server.crt` (signed by root CA) |
| Server key | `server.key` (4096-bit RSA) |
| Client CA | `root-ca.crt` (same root CA as all other components) |

All IoT devices must present a valid client certificate signed by the root CA to communicate with this server.

---

## Database

### PostgreSQL (Supabase)

Stores received telemetry data:

```sql
CREATE TABLE IF NOT EXISTS received_data (
    id               SERIAL PRIMARY KEY,
    mac              TEXT,
    temp             DOUBLE PRECISION,
    client_timestamp TIMESTAMP,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Shared RA Database

The data server also queries the RA's `idverification_device` table to check device state:

```sql
SELECT state FROM idverification_device WHERE mac = $1 LIMIT 1;
```

This means both the RA and data server share the same PostgreSQL database.

---

## RA Server Integration

The data server makes outbound HTTPS calls to the RA server (at `localhost:8000`) using mTLS:

| Call | When | Purpose |
|------|------|---------|
| `GET /reconnect/<mac>/` | Device state is `reconnecting` | Transition device back to `connected` |
| `POST /report/` | Anomaly detected (>10s gap) | Report disconnect anomaly, suspends device |

---

## Configuration

### Environment Variables (`.env`)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (Supabase) |

Loaded via `godotenv` (optional — logs a warning if missing).

### Files

| File | Description |
|------|-------------|
| `server.crt` | Server TLS certificate (signed by root CA) |
| `server.key` | Server TLS private key |
| `root-ca.crt` | Root CA certificate (validates client certs + RA calls) |
| `server.cnf` | OpenSSL config for generating server certificate |
| `.env` | Environment variables |
| `ndsl-data.service` | systemd unit file |

### Certificate Configuration (`server.cnf`)

```ini
[req_distinguished_name]
CN = 13.211.126.142

[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
IP.2  = 13.211.126.142
```

---

## Setup & Deployment

### 1. Initialize the server

```bash
bash init.sh
```

Generates `server.key` and `server.crt` using the OpenSSL config in `server.cnf`.

### 2. Sign the certificate

Have the CA sign the server certificate (see CA README for instructions), or use `deploy-data.sh` which handles this automatically.

### 3. Run locally

```bash
# Create .env with DATABASE_URL
go run .
```

### 4. Bootstrap EC2 instance (one-time, production)

```bash
sudo bash setup.sh
```

- Detects OS (Amazon Linux 2023 or Ubuntu 24.04)
- Creates 1GB swap (for Go builds on t2.micro)
- Installs Go 1.25.1
- Creates `/opt/ndsl-hmi` directory

### 5. Deploy

```bash
sudo bash deploy-data.sh
```

- Builds the `data-server` binary
- Generates TLS certificates from `server.cnf`, signed by root CA
- Installs and starts the `ndsl-data` systemd service

---

## systemd Service

**Service name:** `ndsl-data`

```ini
[Unit]
Description=NDSL Data Server
After=network.target ndsl-ra.service

[Service]
Type=simple
User=ndsl
WorkingDirectory=/opt/ndsl-hmi/servers/data
ExecStart=/opt/ndsl-hmi/servers/data/data-server
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/ndsl-hmi/servers/data/.env

[Install]
WantedBy=multi-user.target
```

Depends on `ndsl-ra.service` — the RA must be running before the data server starts (since the data server calls RA endpoints).

---

## Dependencies

| Module | Version | Purpose |
|--------|---------|---------|
| `github.com/jackc/pgx/v5` | 5.8.0 | PostgreSQL driver with connection pooling |
| `github.com/joho/godotenv` | 1.5.1 | `.env` file loader |

Go version: **1.25.1**

---

## Service Startup Order

The recommended startup order across all services:

```
1. ndsl-ca    (port 15000)  — Certificate Authority
2. ndsl-ra    (port 8000)   — Registration Authority
3. ndsl-data  (port 8443)   — Data Server
```

This is enforced by `After=` directives in the systemd unit files.