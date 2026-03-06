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
const char* ssid     = "Paella🥘";
const char* password = "testpasstest";

const char* serverUrl       = "https://172.20.10.2:8443/data";
const char* signUrl         = "http://172.20.10.2:8000/receive-device-data/";
const char* certDownloadUrl = "http://172.20.10.2:8000/download-cert/";
const char* renewUrl        = "http://172.20.10.2:8000/renew-cert/";

const int BENCHMARK_ITERATIONS = 100;

// ─── Globals ─────────────────────────────────────────────────────
String ca_cert_str;
String client_cert_str;
String client_key_str;

struct tm timeinfo;
time_t now;

bool benchmarkDone = false;

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
  doc["IP"]  = WiFi.localIP().toString();
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

// ─── Benchmark Helpers ───────────────────────────────────────────
void printResults(const char* label, unsigned long results[], int count) {
  unsigned long minVal = results[0];
  unsigned long maxVal = results[0];
  unsigned long sum = 0;

  for (int i = 0; i < count; i++) {
    if (results[i] < minVal) minVal = results[i];
    if (results[i] > maxVal) maxVal = results[i];
    sum += results[i];
  }
  unsigned long avg = sum / count;

  Serial.printf("\n[%s] (%d iterations)\n", label, count);
  Serial.printf("  Min: %lu ms | Max: %lu ms | Avg: %lu ms\n", minVal, maxVal, avg);
  // Serial.print("  Raw:");
  // for (int i = 0; i < count; i++) {
  //   Serial.printf(" %lu", results[i]);
  //   if (i < count - 1) Serial.print(",");
  // }
  Serial.println();
}

// ─── Benchmark 1: ECC Key Generation ────────────────────────────
// Generates ECC P-256 key + CSR entirely in memory (no SPIFFS writes)
void benchmarkKeyGeneration() {
  static unsigned long results[BENCHMARK_ITERATIONS];
  Serial.println("\nRunning Key Generation benchmark...");

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

    results[i] = elapsed;

    // Cleanup
    mbedtls_pk_free(&key);
    mbedtls_x509write_csr_free(&csr);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    Serial.printf("  Iteration %d: %lu ms\n", i + 1, elapsed);
  }

  printResults("Key Generation", results, BENCHMARK_ITERATIONS);
}

// ─── Benchmark 2: TLS Handshake ─────────────────────────────────
// Measures TCP connect + full mTLS handshake to data server
void benchmarkTLSHandshake() {
  static unsigned long results[BENCHMARK_ITERATIONS];
  Serial.println("\nRunning TLS Handshake benchmark...");

  IPAddress host(172,20,10,2);
  int port = 8443;

  WiFiClientSecure tlsClient;
  tlsClient.setCACert(ca_cert_str.c_str());
  tlsClient.setCertificate(client_cert_str.c_str());
  tlsClient.setPrivateKey(client_key_str.c_str());
  

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    unsigned long start = millis();
    // bool connected = tlsClient.connect(host.c_str(), port);
    bool connected = tlsClient.connect(host, port);
    unsigned long elapsed = millis() - start;

    if (connected) {
      results[i] = elapsed;
      Serial.printf("  Iteration %d: %lu ms\n", i + 1, elapsed);
    } else {
      results[i] = elapsed;
      Serial.printf("  Iteration %d: FAILED (%lu ms)\n", i + 1, elapsed);
    }

    tlsClient.stop();
    delay(100);  // brief pause between handshakes
  }
  
  printResults("TLS Handshake", results, BENCHMARK_ITERATIONS);
}

// ─── Benchmark 3: Certificate Renewal ───────────────────────────
// Measures HTTP POST of current cert to RA renewal endpoint + response
void benchmarkRenewal() {
  static unsigned long results[BENCHMARK_ITERATIONS];
  Serial.println("\nRunning Certificate Renewal benchmark...");

  String url = String(renewUrl) + WiFi.macAddress() + "/";

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    WiFiClient raClient;
    HTTPClient renewHttp;

    if (!renewHttp.begin(raClient, url)) {
      Serial.printf("  Iteration %d: Failed to begin connection\n", i + 1);
      results[i] = 0;
      continue;
    }

    renewHttp.addHeader("Content-Type", "application/x-pem-file");

    unsigned long start = millis();
    int httpCode = renewHttp.POST(client_cert_str);
    String response = renewHttp.getString();
    unsigned long elapsed = millis() - start;

    results[i] = elapsed;

    if (httpCode == 200) {
      // Update cert in memory for subsequent iterations
      client_cert_str = response;
      Serial.printf("  Iteration %d: %lu ms (renewed)\n", i + 1, elapsed);
    } else {
      Serial.printf("  Iteration %d: %lu ms (HTTP %d)\n", i + 1, elapsed, httpCode);
    }

    renewHttp.end();
    delay(100);
  }
  
  printResults("Certificate Renewal", results, BENCHMARK_ITERATIONS);

  // Save the latest renewed cert to SPIFFS so mTLS still works
  writeFile("/client.crt", client_cert_str.c_str());
}

// ─── Benchmark 4: Data Send Roundtrip ───────────────────────────
// Measures HTTP POST of JSON data over established mTLS session
void benchmarkDataSend() {
  static unsigned long results[BENCHMARK_ITERATIONS];
  Serial.println("\nRunning Data Send Roundtrip benchmark...");

  // Establish persistent mTLS connection
  WiFiClientSecure dataClient;
  dataClient.setCACert(ca_cert_str.c_str());
  dataClient.setCertificate(client_cert_str.c_str());
  dataClient.setPrivateKey(client_key_str.c_str());

  HTTPClient https;

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    if (!https.begin(dataClient, serverUrl)) {
      Serial.printf("  Iteration %d: Failed to begin connection\n", i + 1);
      results[i] = 0;
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

    results[i] = elapsed;

    if (httpResponseCode > 0) {
      Serial.printf("  Iteration %d: %lu ms (HTTP %d)\n", i + 1, elapsed, httpResponseCode);
    } else {
      Serial.printf("  Iteration %d: %lu ms (Error: %s)\n", i + 1, elapsed,
                     https.errorToString(httpResponseCode).c_str());
    }

    https.end();
    delay(100);
  }

  printResults("Data Send Roundtrip", results, BENCHMARK_ITERATIONS);
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
  Serial.printf("IP: %s\n", WiFi.localIP().toString().c_str());

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

  Serial.println("\nPrerequisites complete. Starting benchmarks...\n");
}

// ─── Loop (one-shot benchmarks) ──────────────────────────────────
void loop() {
  if (benchmarkDone) {
    delay(10000);
    return;
  }

  Serial.println("\n===== ESP32 BENCHMARK RESULTS =====");
  Serial.printf("WiFi RSSI: %d dBm\n", WiFi.RSSI());
  Serial.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());

  // Run all 4 benchmarks sequentially
  // benchmarkKeyGeneration();
  // benchmarkTLSHandshake();
  // benchmarkRenewal();
  benchmarkDataSend();

  Serial.println("\n===== BENCHMARK COMPLETE =====\n");

  benchmarkDone = true;
}
