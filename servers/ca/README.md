# Certificate Authority (CA) Server

A Go-based HTTPS service that issues, renews, and revokes X.509 certificates for the NDSL-HMI PKI infrastructure. Maintains a certificate revocation list in PostgreSQL (Supabase).

---

## API Endpoints

All endpoints are served over HTTPS on port **15000** (configurable via `-addr` flag).

### `POST /sign` — Issue a Certificate

Accepts either a PEM-encoded CSR or a JSON payload with a raw public key.

**Option A — PEM CSR:**
```
Content-Type: application/x-pem-file

-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
```

**Option B — JSON public key:**
```json
{
  "public_key": "<hex-encoded ECDH P-256 uncompressed public key>",
  "ip_address": "192.168.1.100",
  "subject": {
    "country": "PH",
    "state": "Metro Manila",
    "locality": "Quezon City",
    "organization": "MyIoTProject",
    "common_name": "192.168.1.100"
  }
}
```

**Response:** PEM-encoded X.509 certificate (`application/x-pem-file`)

Certificate properties:
- 128-bit cryptographically random serial number
- Validity: `now - 5min` to `now + N days` (N set by `-days` flag, default 1)
- Key Usage: DigitalSignature, KeyEncipherment
- Extended Key Usage: ServerAuth, ClientAuth
- SANs copied from CSR (DNS names, IPs, email addresses)

---

### `POST /renew` — Renew a Certificate

**Request body:** PEM-encoded certificate to renew

**Validation:**
1. Verifies the certificate was signed by this CA
2. Checks the certificate has not been revoked

**Response:** PEM-encoded new certificate with a fresh serial number, same subject and SANs.

**Error codes:**
- `403 Forbidden` — certificate has been revoked

---

### `POST /revoke` — Revoke a Certificate

**Request body:**
```json
{
  "serial_number": "<hex-encoded serial>",
  "reason": "optional reason"
}
```
Or provide the certificate directly:
```json
{
  "certificate": "<PEM-encoded certificate>",
  "reason": "optional reason"
}
```
Provide one of `serial_number` or `certificate`, not both.

**Response:**
```json
{
  "status": "revoked",
  "serial_number": "<hex-encoded serial>"
}
```

**Error codes:**
- `409 Conflict` — certificate already revoked

---

### `GET /revoked` — List Revoked Certificates

**Response:** JSON array ordered by revocation time (newest first):
```json
[
  {
    "serial_number": "a1b2c3...",
    "revoked_at": "2026-03-06T10:30:00Z",
    "reason": "user_revoked"
  }
]
```

---

## Configuration

### Command-line flags

| Flag | Default | Description |
|------|---------|-------------|
| `-ca-cert` | `root-ca.crt` | Path to root CA certificate |
| `-ca-key` | `root-ca.key` | Path to root CA private key |
| `-addr` | `:15000` | Listen address |
| `-days` | `1` | Certificate validity period in days |

### Environment variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (Supabase) |

Loaded from `.env` via `godotenv`.

### Files

| File | Description |
|------|-------------|
| `root-ca.crt` | Self-signed root CA certificate (4096-bit RSA, 10-year validity) |
| `root-ca.key` | Root CA private key (encrypted) |
| `root-ca.srl` | OpenSSL serial number tracker |
| `ca_server.crt` | TLS certificate for the CA HTTPS server itself |
| `ca_server.key` | TLS private key for the CA server |
| `server.cnf` | OpenSSL config for generating `ca_server.crt` |
| `.env` | Environment variables (`DATABASE_URL`) |
| `ndsl-ca.service` | systemd unit file |

---

## Database

Uses PostgreSQL (Supabase) with a single table:

```sql
CREATE TABLE IF NOT EXISTS revoked_certificates (
    serial_number TEXT PRIMARY KEY,
    revoked_at    TIMESTAMP NOT NULL,
    reason        TEXT
);
```

---

## Setup & Deployment

### 1. Initialize the CA (one-time)

```bash
bash initCA.sh
```

This generates the root CA key pair and distributes `root-ca.crt` to all components:
- `servers/data/root-ca.crt`
- `servers/ra/root-ca.crt`
- `IoT/go/root-ca.crt`
- `IoT/esp8266/data/root-ca.crt`
- `IoT/esp32/data/root-ca.crt`
- `IoT/pico/data/root-ca.crt`

### 2. Bootstrap EC2 instance (one-time, production)

```bash
sudo bash setup.sh
```

- Creates 1GB swap (needed for Go builds on t2.micro)
- Installs Go 1.25.1
- Creates `/opt/ndsl-hmi` directory

### 3. Deploy

```bash
sudo bash deploy-ca.sh
```

- Builds the `ca-server` binary
- Generates `ca_server.crt`/`ca_server.key` from `server.cnf`, signed by the root CA
- Installs and starts the `ndsl-ca` systemd service

### 4. Run locally (development)

```bash
# Create .env with DATABASE_URL
go run .
```

---

## systemd Service

**Service name:** `ndsl-ca`

```ini
[Unit]
Description=NDSL CA Server
After=network.target

[Service]
Type=simple
User=ndsl
WorkingDirectory=/opt/ndsl-hmi/servers/ca
ExecStart=/opt/ndsl-hmi/servers/ca/ca-server
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/ndsl-hmi/servers/ca/.env

[Install]
WantedBy=multi-user.target
```

---

## Dependencies

| Module | Version | Purpose |
|--------|---------|---------|
| `github.com/jackc/pgx/v5` | 5.8.0 | PostgreSQL driver with connection pooling |
| `github.com/joho/godotenv` | 1.5.1 | `.env` file loader |

Go version: **1.25.1**

---

## Security Notes

- The root CA key (`root-ca.key`) is the trust anchor for the entire system. Keep it secure.
- All private key formats are supported: RSA PKCS#1, EC, and PKCS#8.
- Renewal requests are rejected if the certificate has been revoked.
- All signing, renewal, and revocation operations are logged with serial numbers and subject CNs.
- Request body size is limited to 10MB.