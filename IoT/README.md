# IoT Clients

This directory contains firmware and software implementations for IoT devices that communicate with the NDSL-HMI backend infrastructure using mutual TLS (mTLS) with elliptic curve cryptography.

All devices follow a common workflow:
1. Generate an ECC P-256 key pair on first boot
2. Submit a certificate signing request (CSR) or raw public key to the RA server
3. Retrieve a signed X.509 certificate after the owner completes an ownership challenge
4. Use the certificate for mTLS communication with the data server

---

## Devices

### ESP32 (`esp32/`)

**Platform:** Espressif ESP32 (Xtensa LX6)

**Files:**
| File | Description |
|------|-------------|
| `esp32.ino` | Main Arduino sketch |
| `data/root-ca.crt` | Root CA certificate (uploaded to SPIFFS) |

**Overview:**
Full-featured IoT client with automatic certificate renewal. Generates a proper CSR using the on-chip mbedTLS library and submits it to the RA for signing. Sends temperature telemetry to the data server over mTLS every 3 seconds.

**Key characteristics:**
- **Crypto stack:** mbedTLS (built into ESP-IDF) — ECC P-256 key generation + CSR creation
- **Certificate storage:** SPIFFS filesystem (`client.crt`, `client.key`, `root-ca.crt`)
- **Certificate renewal:** Automatic — checks certificate expiry each loop iteration and renews if less than 24 hours remain
- **Data payload:** `{ temp, time, MAC }`
- **Data interval:** 3 seconds
- **Time sync:** NTP for certificate validation

**Libraries:**
- `WiFi.h`, `WiFiClientSecure.h`, `HTTPClient.h` — networking
- `SPIFFS.h` — on-device filesystem
- `ArduinoJson.h` — JSON serialization
- mbedTLS headers (`mbedtls/pk.h`, `mbedtls/x509_csr.h`, `mbedtls/entropy.h`, `mbedtls/ctr_drbg.h`, `mbedtls/x509_crt.h`)

**Certificate flow:**
1. Generates ECC P-256 private key and stores it in SPIFFS
2. Creates a PEM-encoded CSR from the key
3. POSTs IP, MAC, and CSR to the RA (`/receive-device-data/`)
4. Polls RA (`/download-cert/<mac>/`) until a signed certificate is available
5. Stores the signed certificate in SPIFFS
6. Uses cert + key for mTLS connections to the data server
7. Before each data send, checks expiry and POSTs to `/renew-cert/<mac>/` if needed

---

### ESP8266 (`esp8266/`)

**Platform:** Espressif ESP8266 (Tensilica L106)

**Files:**
| File | Description |
|------|-------------|
| `esp8266.ino` | Main Arduino sketch |
| `data/root-ca.crt` | Root CA certificate (uploaded to LittleFS) |

**Overview:**
Lightweight IoT client for the more resource-constrained ESP8266. Uses the micro-ECC library for key generation (no CSR support) and BearSSL for TLS. Sends raw hex-encoded public keys to the RA instead of a full CSR.

**Key characteristics:**
- **Crypto stack:** uECC (micro-ECC, secp256r1) for key generation + BearSSL for TLS
- **Certificate storage:** LittleFS filesystem (`client.crt`, `private.key`, `public.key`, `root-ca.crt`)
- **Certificate renewal:** None — static certificate after initial issuance
- **Data payload:** `{ temp, time, MAC }`
- **Data interval:** Per loop iteration (~10ms)
- **RNG entropy:** ADC-based seeding

**Libraries:**
- `ESP8266WiFi.h`, `ESP8266HTTPClient.h` — networking
- `LittleFS.h` — on-device filesystem
- `uECC.h` — elliptic curve key generation (secp256r1)
- `ArduinoJson.h` — JSON serialization

**Certificate flow:**
1. Generates a 32-byte ECC private key and 64-byte public key via uECC
2. Encodes the public key as uncompressed hex (`04` + 128 hex chars)
3. POSTs IP, MAC, and hex public key to the RA (`/receive-device-data/`)
4. Polls RA (`/download-cert/<mac>/`) for the signed certificate
5. Converts the raw 32-byte private key to DER format for BearSSL compatibility
6. Uses cert + key for mTLS connections to the data server

---

### Raspberry Pi Pico W (`pico/`)

**WIP**

---

## Benchmarks

### ESP32 Benchmark (`esp32_benchmark/`)

**WIP**

Measures cryptographic and network performance over 10000 iterations:

| Operation | Min | Avg | Max |
|-----------|-----|-----|-----|
| ECC Key Generation | - | - | - |
| TLS Handshake | - | - | - |
| Data Send | - | - | - |
| Certificate Renewal | - | - | - |

### ESP8266 Benchmark (`esp8266_benchmark/`)

Measures performance over 10,000 iterations:

| Operation | Min | Avg | Max |
|-----------|-----|-----|-----|
| ECC Key Generation | - | - | - |
| TLS Handshake | - | - | - |
| Data Send | - | - | - |
| Certificate Renewal | - | - | - |

---

## Utility Scripts

### `serial_capture.py`

Captures benchmark results from a microcontroller's serial output and saves them as CSV.

```bash
python3 serial_capture.py esp32              # Auto-detect serial port
python3 serial_capture.py esp8266 -p /dev/ttyUSB0   # Specify port
```

- Auto-detects USB serial adapters (CP210X, CH340, FT232)
- Baud rate: 115200
- Output format: `TestType,Iteration,Elapsed_ms,Result`

### `summarize_results.py`

Aggregates all `results_*.csv` files and generates `final_benchmark_report.txt` with per-device, per-test statistics (mean, min, max, count).

---

## Network Topology

```
IoT Device                        RA Server (:8000)              CA Server (:15000)
┌──────────┐  POST /receive-      ┌──────────┐  POST /sign       ┌──────────┐
│ ESP32    │  device-data/        │          │  POST /renew      │          │
│ ESP8266  │ ──────────────────>  │    RA    │ ─────────────────>│    CA    │
│ Pico W   │  GET /download-cert/ │          │                   │          │
│ Go Client│ <──────────────────  │          │ <─────────────────│          │
└──────────┘                      └──────────┘  X.509 Cert       └──────────┘
     │
     │  POST /data (mTLS)         Data Server (:8443)
     └──────────────────────────> ┌──────────┐
                                  │   Data   │
                                  └──────────┘
```

## Device Comparison

| | ESP32 | ESP8266 | Pico W | Go Client |
|---|---|---|---|---|
| **TLS stack** | mbedTLS | BearSSL | BearSSL | crypto/tls |
| **Key generation** | mbedTLS CSR | uECC raw key | uECC raw key | Pre-provisioned |
| **Filesystem** | SPIFFS | LittleFS | LittleFS | OS filesystem |
| **Auto-renewal** | Yes | No | No | No |
| **Data interval** | 3s | ~10ms | 10s | 500ms |
| **RNG source** | mbedTLS entropy | ADC noise | Hardware RNG | OS entropy |