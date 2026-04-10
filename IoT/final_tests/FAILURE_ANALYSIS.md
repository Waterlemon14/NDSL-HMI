# Test Failure Analysis

Analysis of ~180 CSV benchmark files (10,000 iterations each) across ESP32, ESP8266, and Pico W devices, correlated with device firmware, server code, and error logs.

---

## 1. Pico CertificateRenewal — 13.5% failure rate (1,350 / 10,000)

**Dominant error:** `FAILED (truncated response)` (1,296 of 1,350 failures)

**Root cause — client-side buffer limitation:**

- Pico (and ESP8266) use BearSSL with an explicit **2048-byte buffer** for TLS I/O
- The certificate renewal flow returns a full PEM certificate (typically ~1.2-1.5KB) plus HTTP headers via the RA's nginx -> Django -> CA chain
- The Pico firmware validates the response with:
  ```cpp
  if (response.startsWith("-----BEGIN") && response.indexOf("-----END") > 0)
  ```
  If the response is truncated mid-PEM, this check fails and logs `"truncated response"`

**Server-side contributor:**

- The RA -> CA renewal call (`requests.post(ca_renew_url, ...)`) has **no timeout** set in Python. Under load, CA responses may be delayed, causing the RA's gunicorn workers (only **2 workers**) to block. Late/partial responses are then forwarded via nginx to the Pico, which times out before receiving the full body.

---

## 2. ESP32 mTLSHandshakeRA — 8.2% failure rate (830 / 10,000)

**Error:** Generic `FAILED` (timeout before handshake completion)

**Root cause — server bottleneck at RA port 8444:**

- Port 8444 on the RA is the **mTLS-terminating** nginx listener (`ssl_verify_client: on`), which requires full client cert verification before proxying to Django on port 8000
- The RA only runs **2 gunicorn workers**. Under sustained load from 10,000 iterations, the workers saturate
- The RA error logs show **1,202 SSL processing errors** and **4 worker timeout errors** during this test
- ESP32 uses mbedTLS which negotiates differently than BearSSL — the RA nginx logs show **"upstream sent no valid HTTP/1.0 header"** (10 occurrences) and **"connection reset by peer"** (10 occurrences), indicating Django/gunicorn crashing under concurrent mTLS load

**Why ESP8266/Pico don't fail here:**

- ESP8266 (3,639ms avg) and Pico (2,127ms avg) have different request pacing. The Pico is actually faster but sends requests more evenly. The ESP32's faster CPU but similar network latency (~3,538ms) likely causes **bursty request patterns** that overwhelm the 2-worker pool.

---

## 3. ESP8266 TLSHandshake — 1.89% failure rate (189 / 10,000)

**Error:** Generic `FAILED`

**Root cause — ESP8266 performance constraints:**

- ESP8266 has the slowest TLS handshake at **3,747ms average** (vs ESP32 at 1,311ms)
- BearSSL on the ESP8266's 80MHz single-core processor struggles with the ECC key exchange
- The data server logs show **518 client-related TLS errors** including "client offered unsupported versions" and **12 "missing signature_algorithms from TLS 1.2 peers"** — these indicate the ESP8266's BearSSL is sometimes sending malformed ClientHello messages under memory pressure
- The data server (`servers/data/main.go`) has `IdleTimeout: 10 * time.Second` and `SessionTicketsDisabled: true`, meaning every connection requires a full handshake with no session resumption

---

## 4. ESP32 mTLSHandshake — 1.88% failure rate (188 / 10,000)

**Error:** Generic `FAILED`

**Root cause — data server mTLS strict mode:**

- The data server enforces `tls.RequireAndVerifyClientCert` in Go
- The data server logs show **703 TLS handshake failures** and **110 invalid TLS errors**
- ESP32's mbedTLS occasionally fails the full mTLS exchange. The server's `SessionTicketsDisabled: true` forces a full handshake every time, increasing the window for failure
- The data server returns **no HTTP error response** on handler failures (errors are logged but the connection is silently dropped), making the ESP32 see a generic failure

---

## 5. ESP8266 DataSend — 0.68% failure rate (68 / 10,000)

**Errors:** `FAILED (HTTP -11: )` and `FAILED (HTTP -1: )`

- **HTTP -11**: Connection closed/reset by server (mapped from BearSSL error). The data server's 10-second `IdleTimeout` may be expiring between the mTLS handshake and the POST body transmission on the slower ESP8266
- **HTTP -1**: Connection refused or DNS failure. On AWS EC2, this can occur during brief network hiccups, and the ESP8266 has no retry logic for data sends

---

## 6. Minor failures (< 0.5%)

| Device | Test | Rate | Cause |
|--------|------|------|-------|
| Pico | mTLSHandshake | 0.31% | Occasional BearSSL handshake timeout against data server |
| ESP32 | CertificateRenewal | 0.12% | RA gunicorn worker timeout during CA forwarding |
| ESP8266 | CertificateRenewal | 0.14% | Same as ESP32 but less frequent due to slower request rate |
| ESP32 | DataSend | 0.01% | Single failure in 10,000 — likely transient network event |
| Pico | DataSend | 0.07% | Same class as ESP8266 DataSend |
| Pico | mTLSHandshakeRA | 0.08% | Rare RA worker saturation |

---

## Summary of Root Causes

| Root Cause | Affected Tests | Fix Location |
|---|---|---|
| **RA only has 2 gunicorn workers** | mTLSHandshakeRA (ESP32 8.2%), CertificateRenewal (all) | `servers/ra/gunicorn_config.py` — increase workers |
| **BearSSL 2048-byte buffer** on Pico | CertificateRenewal (Pico 13.5%) | `pico_benchmark/pico_benchmark.ino` — increase MFLN buffer |
| **No request timeout in RA->CA calls** | CertificateRenewal (all devices) | `servers/ra/idverification/views/views_device.py` — add `timeout=` to `requests.post()` |
| **Data server drops connections silently** | mTLSHandshake, DataSend (all devices) | `servers/data/main.go` — return proper HTTP error responses |
| **TLS session tickets disabled** | TLSHandshake (ESP8266), mTLSHandshake (ESP32) | `servers/data/main.go` — consider enabling session resumption |
| **ESP8266 CPU too slow for reliable BearSSL** | TLSHandshake (ESP8266 1.89%) | Hardware limitation — longer timeouts or session caching would help |
