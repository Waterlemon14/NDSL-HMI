// ESP32 Benchmark Test Suite
// Standalone sketch that benchmarks: ECC keygen, TLS handshake,
// certificate renewal, and data sending roundtrip.

// Network
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

// File system
#include <FS.h>
#include "SPIFFS.h"

#include <ArduinoJson.h>

// Synchronization
#include <time.h>

// Security packages
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/x509_crt.h"

// ─── Configuration ───────────────────────────────────────────────
// Set LOCAL_SERVER_IP to the IP of the machine running the servers on your LAN
#define LOCAL_SERVER_IP "192.168.0.212"

const char* ssid     = "ndsgwifi";
const char* password = "H1b2idinF2@";

// Local server endpoints (RA on :8000 via manage.py runserver, Data on :8443)
// const char* serverUrl       = "https://" LOCAL_SERVER_IP ":8443/data";
// const char* signUrl         = "http://" LOCAL_SERVER_IP ":8000/receive-device-data/";
// const char* certDownloadUrl = "http://" LOCAL_SERVER_IP ":8000/download-cert/";
// const char* renewUrl        = "http://" LOCAL_SERVER_IP ":8000/renew-cert/";

const char* serverUrl       = "https://51.20.87.204:8443/data";
const char* signUrl         = "https://13.239.57.125:8000/receive-device-data/";
const char* certDownloadUrl = "https://13.239.57.125:8000/download-cert/";
const char* renewUrl        = "https://13.239.57.125:8000/renew-cert/";

const int BENCHMARK_ITERATIONS = 10000;

// ─── Globals ─────────────────────────────────────────────────────
String ca_cert_str;
String client_cert_str;
String client_key_str;
String publicIP;

struct tm timeinfo;
time_t now;

bool benchmarkDone = false;

WiFiClientSecure mtlsClient;

// ─── SPIFFS Helpers (reused from production) ─────────────────────
String readFile(const char* path) {
  File file = SPIFFS.open(path, "r");
  if (!file) {
    Serial.printf("Failed to open %s for reading\n", path);
    return "";
  }
  String content = file.readString();
  file.close();
  return content;
}

void writeFile(const char* path, const char* content) {
  File file = SPIFFS.open(path, "w");
  if (!file) {
    Serial.printf("Failed to open %s for writing\n", path);
    return;
  }
  file.print(content);
  file.close();
}

// ─── NTP Sync (reused from production) ───────────────────────────
void setClock() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("Waiting for NTP time sync: ");
  now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(500);
    Serial.print(".");
    yield();
    now = time(nullptr);
  }
  Serial.println();
  gmtime_r(&now, &timeinfo);
  Serial.print("Current time: ");
  Serial.print(asctime(&timeinfo));
}

// ─── Key + CSR generation (production version, writes to SPIFFS) ─
void generateKeyAndCSR() {
  mbedtls_pk_context key;
  mbedtls_x509write_csr csr;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  unsigned char output_buf[2048];
  const char* pers = "csr_gen_ecc";

  mbedtls_pk_init(&key);
  mbedtls_x509write_csr_init(&csr);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                         (const unsigned char*)pers, strlen(pers));

  int ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (ret != 0) { Serial.printf("pk_setup failed: -0x%04x\n", -ret); return; }

  ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                             mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) { Serial.printf("ECC keygen failed: -0x%04x\n", -ret); return; }

  unsigned char key_buf[1600];
  mbedtls_pk_write_key_pem(&key, key_buf, sizeof(key_buf));
  writeFile("/client.key", (char*)key_buf);

  mbedtls_x509write_csr_set_key(&csr, &key);
  mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_subject_name(&csr, "C=CA, ST=., L=., O=., OU=., CN=localhost");

  memset(output_buf, 0, sizeof(output_buf));
  ret = mbedtls_x509write_csr_pem(&csr, output_buf, sizeof(output_buf),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret == 0) {
    writeFile("/client.csr", (char*)output_buf);
  } else {
    Serial.printf("CSR PEM failed: -0x%04x\n", -ret);
  }

  mbedtls_pk_free(&key);
  mbedtls_x509write_csr_free(&csr);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

// ─── Certificate request (reused from production) ────────────────
int requestCert() {
  String csr = readFile("/client.csr");
  if (csr == "") {
    Serial.println("Failed to read CSR from SPIFFS");
    return -1;
  }

  JsonDocument doc;
  doc["IP"]  = publicIP;
  doc["MAC"] = WiFi.macAddress();
  doc["CSR"] = csr;
  String jsonPayload;
  serializeJson(doc, jsonPayload);

  WiFiClient raClient;
  HTTPClient http;
  int responsecode = 0;

  http.begin(raClient, signUrl);
  while (responsecode != 202) {
    http.addHeader("Content-Type", "application/json");
    responsecode = http.POST(jsonPayload);
    Serial.printf("requestCert POST: %d\n", responsecode);
    if (responsecode != 202) delay(10000);
  }
  http.end();

  responsecode = 0;
  http.begin(raClient, certDownloadUrl + WiFi.macAddress() + "/");
  while (responsecode != 200) {
    delay(10000);
    Serial.println("Waiting for certificate...");
    responsecode = http.GET();
    if (responsecode == 200) {
      String signedCert = http.getString();
      writeFile("/client.crt", signedCert.c_str());
    }
  }
  http.end();
  return 0;
}

// ─── Benchmark 1: ECC Key Generation ────────────────────────────
// Generates ECC P-256 key + CSR entirely in memory (no SPIFFS writes)
void benchmarkKeyGeneration() {
  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    mbedtls_pk_context key;
    mbedtls_x509write_csr csr;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    unsigned char output_buf[2048];
    unsigned char key_buf[1600];
    const char* pers = "csr_gen_ecc";

    mbedtls_pk_init(&key);
    mbedtls_x509write_csr_init(&csr);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed RNG
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                           (const unsigned char*)pers, strlen(pers));

    // Generate ECC key
    mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

    unsigned long start = millis();
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                         mbedtls_ctr_drbg_random, &ctr_drbg);
    unsigned long elapsed = millis() - start;


    // Write key PEM to memory buffer (not SPIFFS)
    mbedtls_pk_write_key_pem(&key, key_buf, sizeof(key_buf));

    // Build CSR
    mbedtls_x509write_csr_set_key(&csr, &key);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_subject_name(&csr, "C=CA, ST=., L=., O=., OU=., CN=localhost");

    memset(output_buf, 0, sizeof(output_buf));
    mbedtls_x509write_csr_pem(&csr, output_buf, sizeof(output_buf),
                                mbedtls_ctr_drbg_random, &ctr_drbg);

    // Cleanup
    mbedtls_pk_free(&key);
    mbedtls_x509write_csr_free(&csr);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    Serial.printf("KeyGen,%d,%lu,SUCCESS\n", i + 1, elapsed);
  }
}

// ─── Benchmark 2: mTLS Handshake ─────────────────────────────────
void benchmarkmTLSHandshake() {
  IPAddress host(51, 20, 87, 204);
  int port = 8443;

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    unsigned long start = millis();
    bool connected = mtlsClient.connect(host, port);
    unsigned long elapsed = millis() - start;

    if (connected) {
      Serial.printf("mTLSHandshake,%d,%lu,SUCCESS\n", i + 1, elapsed);
    } else {
      Serial.printf("mTLSHandshake,%d,%lu,FAILED\n", i + 1, elapsed);
    }

    mtlsClient.stop();
    delay(500);
  }
}

// ─── Benchmark 3: Certificate Renewal ───────────────────────────
void benchmarkRenewal() {
  String url = String(renewUrl) + WiFi.macAddress() + "/";

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    HTTPClient renewHttp;

    if (!renewHttp.begin(mtlsClient, url)) {
      Serial.printf("CertificateRenewal,%d,0,FAILED\n", i + 1);
      continue;
    }

    renewHttp.addHeader("Content-Type", "application/x-pem-file");

    unsigned long start = millis();
    int httpCode = renewHttp.POST(client_cert_str);
    if (httpCode == 200) {
      unsigned long elapsed = millis() - start;
      String response = renewHttp.getString();
      renewHttp.end();

      if (response.startsWith("-----BEGIN") && response.indexOf("-----END") > 0) {
        client_cert_str = response;
        mtlsClient.setCertificate(client_cert_str.c_str());
        Serial.printf("CertificateRenewal,%d,%lu,SUCCESS\n", i + 1, elapsed);
      } else {
        Serial.printf("CertificateRenewal,%d,%lu,FAILED (truncated response)\n", i + 1, elapsed);
      }
    } else {
      unsigned long elapsed = millis() - start;
      String errBody = renewHttp.getString();
      Serial.printf("CertificateRenewal,%d,%lu,FAILED (HTTP %d: %s)\n", i + 1, elapsed, httpCode, errBody.c_str());
      renewHttp.end();
    }

    delay(100);
  }
  writeFile("/client.crt", client_cert_str.c_str());
}

// ─── Benchmark 4: Data Send Roundtrip ───────────────────────────
void benchmarkDataSend() {
  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    HTTPClient https;

    if (!https.begin(mtlsClient, serverUrl)) {
      Serial.printf("DataSend,%d,0,FAILED\n", i + 1);
      continue;
    }

    https.addHeader("Content-Type", "application/json");

    // Build JSON payload (same format as production)
    JsonDocument doc;
    doc["temp"] = random(1500, 2101) / 100.0;

    now = time(nullptr);
    timeinfo = *localtime(&now);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);

    doc["time"] = timeStr;
    doc["MAC"]  = WiFi.macAddress();

    String data;
    serializeJson(doc, data);

    unsigned long start = millis();
    int httpResponseCode = https.POST(data);
    String response = https.getString();
    unsigned long elapsed = millis() - start;

    if (httpResponseCode == 200) {
      Serial.printf("DataSend,%d,%lu,SUCCESS\n", i + 1, elapsed);
    } else {
      Serial.printf("DataSend,%d,%lu,FAILED (HTTP %d: %s)\n", i + 1, elapsed, httpResponseCode, response.c_str());
    }
    https.end();
    delay(300);
  }
}

// ─── Setup ───────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(3000);
  while (!Serial);

  Serial.println("\n===== ESP32 BENCHMARK TEST SUITE =====\n");

  // 1. Mount SPIFFS
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed!");
    return;
  }
  Serial.println("SPIFFS mounted");

  // 2. Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  // Get public IP
  {
    WiFiClient plainClient;
    HTTPClient http;
    http.begin(plainClient, "http://api.ipify.org");
    int httpResponseCode = http.GET();
    if (httpResponseCode > 0) {
      publicIP = http.getString();
      Serial.print("Public IP: ");
      Serial.println(publicIP);
    } else {
      Serial.printf("Failed to get public IP: %d\n", httpResponseCode);
    }
    http.end();
  }

  // 3. Sync NTP
  setClock();

  // 4. Load root CA
  ca_cert_str = readFile("/root-ca.crt");
  if (ca_cert_str == "") {
    Serial.println("CRITICAL: Could not load /root-ca.crt");
    while (1) delay(1000);
  }

  // 5. Ensure device has a valid certificate
  if (!SPIFFS.exists("/client.key")) {
    Serial.println("No client key found, generating...");
    generateKeyAndCSR();
  }
  if (!SPIFFS.exists("/client.crt")) {
    Serial.println("No client cert found, requesting...");
    requestCert();
    SPIFFS.remove("/client.csr");
  }

  // 6. Load client cert + key
  client_cert_str = readFile("/client.crt");
  client_key_str  = readFile("/client.key");

  if (client_cert_str == "" || client_key_str == "") {
    Serial.println("CRITICAL: Could not load client cert/key");
    while (1) delay(1000);
  }

  mtlsClient.setCACert(ca_cert_str.c_str());
  mtlsClient.setCertificate(client_cert_str.c_str());
  mtlsClient.setPrivateKey(client_key_str.c_str());

  Serial.println("\nPrerequisites complete. Starting benchmarks...\n");
}

// ─── Loop (one-shot benchmarks) ──────────────────────────────────
void loop() {
  if (benchmarkDone) {
    delay(10000);
    return;
  }

  Serial.println("\n===== BENCHMARK START =====");
  Serial.printf("WiFi RSSI: %d dBm\n", WiFi.RSSI());
  Serial.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());

  // Run all 4 benchmarks sequentially
  benchmarkDataSend();
  benchmarkRenewal();
  benchmarkKeyGeneration();
  benchmarkmTLSHandshake();

  Serial.println("\n===== BENCHMARK COMPLETE =====\n");

  benchmarkDone = true;
}
