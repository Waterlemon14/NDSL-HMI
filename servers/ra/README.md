# Registration Authority (RA) Server

A Django-based web application that manages IoT device registration, user identity verification (via MOSIP), ownership challenges, and certificate lifecycle operations. Acts as the intermediary between IoT devices, users, and the Certificate Authority.

---

## Architecture Overview

```
User (Browser)                    IoT Device
     │                                │
     │ Scan QR, verify OTP            │ POST /receive-device-data/
     │ Select device                  │ GET  /download-cert/<mac>/
     │ Complete ownership challenge   │ POST /renew-cert/<mac>/
     ▼                                ▼
┌─────────────────────────────────────────┐
│              RA Server (:8000)          │
│  Django + Gunicorn + TLS               │
│                                         │
│  MOSIP Auth ←→ User identity           │
│  Ownership Challenge ←→ Device proof   │
│  Certificate Proxy ←→ CA Server        │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│    CA Server (:15000)    │
│    /sign /renew /revoke  │
└──────────────────────────┘
```

---

## API Endpoints

### Authentication & Identity

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | QR code scanning page (MOSIP-issued QR) |
| POST | `/verify-qr/` | Extract UIN from QR, trigger MOSIP OTP generation |
| GET/POST | `/enter-otp/` | OTP entry form and MOSIP OTP verification |
| GET | `/logout-view/` | Log out and clear session |

### Device Registration & Ownership

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/select-device/` | List unregistered devices; initiate ownership flow |
| GET | `/ownership-challenge/<device_id>/` | Display ownership challenge page |
| POST | `/start-challenge/<device_id>/` | Begin a challenge round (returns random interval) |
| POST | `/check-status/<device_id>/` | Verify device disconnect/reconnect during challenge |

### Device Certificate Management

| Method | Path | Description |
|--------|------|-------------|
| POST | `/receive-device-data/` | Device submits IP, MAC, public key or CSR |
| GET | `/download-cert/<mac>/` | Device downloads its signed certificate |
| POST | `/renew-cert/<mac>/` | Device submits current cert for renewal |

### Device Monitoring & Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/view-device/` | Dashboard showing user's registered devices |
| POST | `/report/` | Report device anomaly (disconnect/theft) |
| POST | `/reconnect/<mac>/` | Mark a suspended device as reconnected |

---

## User Authentication Flow (MOSIP)

1. **QR Scan** — User scans a MOSIP-issued QR code containing their UIN, first name, and last name
2. **OTP Request** — RA calls `MOSIPAuthenticator.genotp(UIN)` which sends an OTP via phone/email
3. **OTP Verification** — User enters OTP; RA calls `MOSIPAuthenticator.auth(UIN, OTP, transactionID)`
4. **Session Creation** — On success, a `User` record is created (or retrieved) and a Django session is established

The `User` model uses the MOSIP UIN as the unique identifier. Passwords are set to unusable since authentication is handled entirely by MOSIP.

---

## Ownership Challenge Protocol

A 3-round challenge that proves the user has physical control of the device. Each round consists of:

### Round Structure

1. **Disconnect phase** (11–20 seconds, randomized)
   - User initiates via `POST /start-challenge/<id>/`
   - Server generates a random interval and records the start time
   - User must physically disconnect the device

2. **Verification** (`POST /check-status/<id>/` with `action=end`)
   - Server checks that `device.updatedAt` falls outside the `[start, end]` window
   - If the device was truly offline for the entire interval: `challengeCount++`
   - If the device reported data during the interval: `challengeCount = 0` (reset)

3. **Reconnect window** (30 seconds)
   - User must reconnect the device within 30 seconds
   - Frontend polls `POST /check-status/<id>/` with `action=check` every second
   - If `device.updatedAt` falls within the reconnect window: `challengeCount++`

After **3 successful rounds** (`CHALLENGE_COUNT_THRESHOLD = 3`):
- `device.owner` is set to the authenticated user
- `device.state` transitions to `RECONNECTING`
- The device can now download its signed certificate

---

## Certificate Lifecycle

### Issuance

When a device calls `GET /download-cert/<mac>/` and the ownership challenge is complete:

- **If device has a `public_key`:** RA sends a JSON payload to the CA's `/sign` endpoint:
  ```json
  {
    "PublicKey": "<hex public key>",
    "IPAddress": "<device IP>",
    "Subject": {
      "Country": "PH",
      "State": "Metro Manila",
      "Locality": "Quezon City",
      "Organization": "MyIoTProject",
      "CommonName": "<device IP>"
    }
  }
  ```
- **If device has a `csr`:** RA forwards the PEM-encoded CSR directly to `/sign`
- The signed certificate is cached in `device.certificate` and returned to the device

### Renewal

`POST /renew-cert/<mac>/` — The device sends its current certificate; RA forwards it to the CA's `/renew` endpoint and stores the renewed certificate.

### Revocation

From the `/view-device/` dashboard, a user can revoke a device's certificate:
1. RA sends `POST /revoke` to the CA with the certificate and reason `"user_revoked"`
2. `device.certificate` is cleared
3. `device.state` is set to `REVOKED`
4. `device.challengeCount` is reset to 0

---

## Device State Machine

```
                    ┌──────────────┐
     Registration   │  CONNECTED   │  Device has no certificate/owner
     ───────────>   │              │
                    └──────┬───────┘
                           │ Ownership challenge passed (3 rounds)
                           ▼
                    ┌──────────────┐
                    │ RECONNECTING │  Awaiting certificate download
                    │              │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
   ┌────────────┐  ┌─────────────┐  ┌───────────┐
   │ SUSPENDED  │  │  CONNECTED  │  │  REVOKED   │
   │ (anomaly)  │  │ (reconnect) │  │ (user act) │
   └────────────┘  └─────────────┘  └───────────┘
```

**States:**
| State | Meaning |
|-------|---------|
| `connected` | Device is active, no certificate yet |
| `reconnecting` | Ownership verified, pending certificate |
| `suspended` | Device reported as disconnected (anomaly) |
| `revoked` | Certificate revoked by user |

---

## Database Models

### Device

| Field | Type | Description |
|-------|------|-------------|
| `mac` | CharField (unique) | Device MAC address |
| `ip` | CharField | Device IP address |
| `public_key` | CharField (nullable) | Hex-encoded ECC public key |
| `manufacturer` | TextField | Resolved via macvendors.com if unknown |
| `csr` | TextField (nullable) | PEM-encoded CSR |
| `challengeCount` | SmallIntegerField | Ownership challenge progress (0–3) |
| `interval` | SmallIntegerField | Challenge timing interval (ms) |
| `certificate` | TextField (nullable) | Signed X.509 certificate (PEM) |
| `owner` | ForeignKey → User (nullable) | Assigned owner |
| `state` | CharField | One of: connected, reconnecting, suspended, revoked |
| `updatedAt` | DateTimeField (auto) | Last activity timestamp |

### User

| Field | Type | Description |
|-------|------|-------------|
| `uin` | CharField (unique) | MOSIP Unique Identification Number |
| `firstName` | TextField | From MOSIP QR |
| `lastName` | TextField | From MOSIP QR |

Extends `AbstractBaseUser`. Password is set to unusable (MOSIP-only auth).

### Notification

| Field | Type | Description |
|-------|------|-------------|
| `user` | ForeignKey → User | Recipient |
| `message` | TextField | Notification text |
| `level` | CharField | success, info, warning, or error |
| `is_read` | BooleanField | Read status |
| `created_at` | DateTimeField (auto) | Creation timestamp |

---

## Configuration

### Environment Variables (`.env`)

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Django secret key |
| `DATABASE_NAME` | PostgreSQL database name |
| `DATABASE_USER` | Database username |
| `DATABASE_PASSWORD` | Database password |

### MOSIP Configuration (`config.toml`)

| Section | Key Settings |
|---------|-------------|
| `[mosip_auth]` | Partner ID, MISP license key, API key, auth version |
| `[mosip_auth_server]` | IDA auth URL, domain URI |
| `[crypto_encrypt]` | Symmetric key sizes, encrypt cert path, decrypt keystore path/password |
| `[crypto_signature]` | Algorithm (RS256), signing keystore path/password |

### MOSIP Certificates

| File | Description |
|------|-------------|
| `ida_partner.pem` | MOSIP encryption certificate |
| `cs-198-2-keystore.p12` | MOSIP decryption keystore |
| `cs-198-2-keystore-signed.p12` | MOSIP signing keystore |

### TLS Certificates

| File | Description |
|------|-------------|
| `id_server.crt` | RA server TLS certificate |
| `id_server.key` | RA server TLS private key |
| `root-ca.crt` | Root CA certificate (for CA communication) |
| `server.cnf` | OpenSSL config with SANs for localhost and EC2 IP |

---

## Setup & Deployment

### 1. Create virtual environment and install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure MOSIP

- Place `config.toml`, keystore files (`.p12`), and `ida_partner.pem` in the `ra/` directory
- Update partner credentials in `config.toml` as needed

### 3. Configure database

```bash
# Set DATABASE_NAME, DATABASE_USER, DATABASE_PASSWORD in .env
python manage.py migrate
```

### 4. (Optional) Seed test data

```bash
python manage.py seed --total 10          # Create 10 dummy devices
python manage.py seed --total 5 --user "John" --clear  # Clear and re-seed with owner
python manage.py clear_devices            # Remove all devices
```

### 5. Run locally

```bash
python manage.py runserver
```

### 6. Deploy to EC2

```bash
sudo bash setup.sh       # One-time: install dependencies
sudo bash deploy-ra.sh   # Build, configure TLS, install systemd service
```

---

## systemd Service

**Service name:** `ndsl-ra`

```ini
[Unit]
Description=NDSL RA Server (Django/Gunicorn)
After=network.target ndsl-ca.service

[Service]
Type=simple
User=ndsl
WorkingDirectory=/opt/ndsl-hmi/servers/ra
ExecStart=gunicorn verification.wsgi:application -c gunicorn_config.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Gunicorn config:** Binds to `0.0.0.0:8000`, 2 workers, TLS via `id_server.crt`/`id_server.key`.

---

## Dependencies

Key Python packages (see `requirements.txt` for full list):

| Package | Purpose |
|---------|---------|
| `Django==5.2.8` | Web framework |
| `mosip-auth-sdk` | MOSIP identity authentication |
| `gunicorn` | Production WSGI server |
| `psycopg2-binary==2.9.10` | PostgreSQL adapter |
| `cryptography==43.0.3` | Cryptographic operations |
| `jwcrypto==1.5.6` | JWT handling (MOSIP) |
| `requests==2.32.5` | HTTP client for CA calls |
| `whitenoise==6.8.2` | Static file serving |
| `pyzbar==0.1.9` | QR code reading |
| `opencv-python==4.12.0.88` | Image processing |
| `dynaconf==3.2.11` | TOML config management |
| `factory_boy` | Test data generation |

Python version: **3.13**

---

## Project Structure

```
ra/
├── verification/          # Django project settings
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py / asgi.py
├── idverification/        # Main Django app
│   ├── models.py          # Device, User, Notification models
│   ├── urls.py            # App-level URL routing
│   ├── helper.py          # Device selection by IP proximity
│   ├── factories.py       # Factory Boy definitions
│   ├── views/
│   │   ├── views_ra.py    # Auth, ownership challenge, device management
│   │   ├── views_device.py # Certificate issuance, renewal
│   │   └── views_data.py  # Anomaly reporting, reconnection
│   ├── mosip/
│   │   └── otp_auth.py    # MOSIP OTP generation and verification
│   ├── templates/         # HTML templates (QR scan, OTP, challenge, dashboard)
│   └── management/commands/
│       ├── seed.py        # Seed dummy devices
│       └── clear_devices.py
├── static/
│   ├── script.js          # QR scanning frontend
│   └── challenge.js       # Ownership challenge frontend
├── config.toml            # MOSIP partner configuration
├── requirements.txt
├── gunicorn_config.py
├── manage.py
└── deploy scripts, service files, certificates
```