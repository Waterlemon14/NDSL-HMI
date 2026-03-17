// ESP8266 Benchmark Test Suite
// Standalone sketch that benchmarks: ECC keygen, TLS handshake,
// certificate renewal, and data sending roundtrip.

// Network
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

// Filesystem
#include <LittleFS.h>

// Synchronization
#include <time.h>

// Security
#include <uECC.h>
#include <esp8266_peri.h> // for RANDOM_REG32

// Utilities
#include <ArduinoJson.h>

// ─── Configuration ───────────────────────────────────────────────
// const char* ssid     = "test";
// const char* password = "passtest";

const char* ssid     = "ndsgwifi";
const char* password = "H1b2idinF2@";

const char* serverUrl       = "https://51.20.87.204:8443/data";
const char* signUrl         = "https://13.239.57.125:8000/receive-device-data/";
const char* certDownloadUrl = "https://13.239.57.125:8000/download-cert/";
const char* renewUrl        = "https://13.239.57.125:8000/renew-cert/";

const int BENCHMARK_ITERATIONS = 10;

// ─── Globals ─────────────────────────────────────────────────────
uint8_t sk[32];
uint8_t pk[64];
String caCert;
String clientCert;
String publicIP;
uint8_t key_der[121];
unsigned long expiration;

BearSSL::X509List* trustRoot = nullptr;
BearSSL::X509List* clientCertList = nullptr;
BearSSL::PrivateKey* deviceKey = nullptr;

WiFiClientSecure secureclient;

struct tm timeinfo;
time_t now;

bool benchmarkDone = false;

// ─── RNG for uECC ───────────────────────────────────────────────
static int RNG(uint8_t* dest, unsigned size) {
  while (size--) {
    *dest++ = (uint8_t)RANDOM_REG32;
  }
  return 1;
}

void printHex(uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

// ─── LittleFS Helpers ───────────────────────────────────────────
String readFile(const char* path) {
  File file = LittleFS.open(path, "r");
  if (!file) {
    Serial.printf("Failed to open %s for reading\n", path);
    return "";
  }
  String content = file.readString();
  file.close();
  return content;
}

void writeFile(const char* path, const char* content) {
  File file = LittleFS.open(path, "w");
  if (!file) {
    Serial.printf("Failed to open %s for writing\n", path);
    return;
  }
  file.print(content);
  file.close();
}

// ─── NTP Sync ───────────────────────────────────────────────────
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

// ─── Key generation (production version, writes to LittleFS) ────
void generateKeyPair() {
  Serial.println("Creating ECC key pair...");
  uECC_set_rng(&RNG);
  const struct uECC_Curve_t* curve = uECC_secp256r1();
  yield();

  if (uECC_make_key(pk, sk, curve)) {
    Serial.println("Successfully generated key pair!");
    yield();

    File skFile = LittleFS.open("/private.key", "w");
    if (skFile) { skFile.write(sk, 32); skFile.close(); }

    File pkFile = LittleFS.open("/public.key", "w");
    if (pkFile) { pkFile.write(pk, 64); pkFile.close(); }
  } else {
    Serial.println("Failed to generate key pair!");
  }
}

// ─── DER key construction ───────────────────────────────────────
void setupDeviceKey() {
  uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
  uint8_t mid[]  = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};

  memcpy(key_der, head, 7);
  memcpy(key_der + 7, sk, 32);
  memcpy(key_der + 39, mid, 18);
  memcpy(key_der + 57, pk, 64);
  deviceKey = new BearSSL::PrivateKey(key_der, 121);
}

// ─── Certificate request (production version) ───────────────────
int requestCert() {
  char pkbuffer[131];
  sprintf(pkbuffer, "04");
  for (int i = 0; i < 64; i++) {
    sprintf(pkbuffer + 2 + (i * 2), "%02x", pk[i]);
  }

  JsonDocument doc;
  doc["IP"] = publicIP;
  doc["MAC"] = WiFi.macAddress();
  doc["PublicKey"] = pkbuffer;
  String jsonPayload;
  serializeJson(doc, jsonPayload);

  HTTPClient https;
  int responsecode = 0;

  while (responsecode != 202) {
    secureclient.stop();
    delay(100);
    if (https.begin(secureclient, signUrl)) {
      https.addHeader("Content-Type", "application/json");
      responsecode = https.POST(jsonPayload);
      Serial.printf("requestCert POST: %d\n", responsecode);
      https.end();
    }
    if (responsecode != 202) delay(10000);
  }

  responsecode = 0;
  while (responsecode != 200) {
    delay(10000);
    Serial.println("Waiting for certificate...");
    https.begin(secureclient, certDownloadUrl + WiFi.macAddress() + "/");
    const char* headerKeys[] = {"X-Cert-Expires-At"};
    https.collectHeaders(headerKeys, 1);
    responsecode = https.GET();
    if (responsecode == 200) {
      clientCert = https.getString();
      expiration = https.header("X-Cert-Expires-At").toInt();
      writeFile("/client.crt", clientCert.c_str());
      writeFile("/expiration.txt", String(expiration).c_str());
    }
    https.end();
  }
  return 0;
}

// ─── Benchmark 1: ECC Key Generation (uECC) ─────────────────────
void benchmarkKeyGeneration() {
  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    uint8_t temp_sk[32];
    uint8_t temp_pk[64];

    uECC_set_rng(&RNG);
    const struct uECC_Curve_t* curve = uECC_secp256r1();

    unsigned long start = millis();
    uECC_make_key(temp_pk, temp_sk, curve);
    unsigned long elapsed = millis() - start;

    Serial.printf("KeyGen,%d,%lu,SUCCESS\n", i + 1, elapsed);

    delay(10);
  }
}

// ─── Benchmark 2: mTLS Handshake (BearSSL) ──────────────────────
void benchmarkmTLSHandshake() {
  IPAddress host(51, 20, 87, 204);
  int port = 8443;

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    unsigned long start = millis();
    bool connected = secureclient.connect(host, port);
    unsigned long elapsed = millis() - start;

    if (connected) {
      Serial.printf("mTLSHandshake,%d,%lu,SUCCESS\n", i + 1, elapsed);
    } else {
      Serial.printf("mTLSHandshake,%d,%lu,FAILED\n", i + 1, elapsed);
    }

    secureclient.stop();
    delay(500);
  }
}

// ─── Benchmark 3: Certificate Renewal ───────────────────────────
void benchmarkRenewal() {
  String url = String(renewUrl) + WiFi.macAddress() + "/";

  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    HTTPClient renewHttp;

    if (!renewHttp.begin(secureclient, url)) {
      Serial.printf("CertificateRenewal,%d,0,FAILED\n", i + 1);
      continue;
    }

    renewHttp.addHeader("Content-Type", "application/x-pem-file");

    unsigned long start = millis();
    int httpCode = renewHttp.POST(clientCert);
    if (httpCode == 200) {
      String response = renewHttp.getString();
      expiration = renewHttp.header("X-Cert-Expires-At").toInt();
      unsigned long elapsed = millis() - start;
      clientCert = response;
      Serial.printf("CertificateRenewal,%d,%lu,SUCCESS\n", i + 1, elapsed);
    } else {
      unsigned long elapsed = millis() - start;
      Serial.printf("CertificateRenewal,%d,%lu,FAILED\n", i + 1, elapsed);
    }

    renewHttp.end();
    delay(100);
  }
  writeFile("/client.crt", clientCert.c_str());
  writeFile("/expiration.txt", String(expiration).c_str());
}

// ─── Benchmark 4: Data Send Roundtrip (JSON + POST) ─────────────
void benchmarkDataSend() {
  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    HTTPClient https;

    if (!https.begin(secureclient, serverUrl)) {
      Serial.printf("DataSend,%d,0,FAILED\n", i + 1);
      continue;
    }

    https.addHeader("Content-Type", "application/json");

    JsonDocument doc;
    doc["temp"] = random(15, 21);

    now = time(nullptr);
    timeinfo = *localtime(&now);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);

    doc["time"] = timeStr;
    doc["MAC"] = WiFi.macAddress();

    String data;
    serializeJson(doc, data);

    unsigned long start = millis();
    int httpResponseCode = https.POST(data);
    String response = https.getString();
    unsigned long elapsed = millis() - start;

    if (httpResponseCode == 200) {
      Serial.printf("DataSend,%d,%lu,SUCCESS\n", i + 1, elapsed);
    } else {
      Serial.printf("DataSend,%d,%lu,FAILED\n", i + 1, elapsed);
    }
    https.end();
    delay(300);
  }
}

// ─── Setup ──────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(1000);
  while(!Serial);

  Serial.println("\n===== ESP8266 BENCHMARK TEST SUITE =====\n");

  // 1. Mount LittleFS
  if (!LittleFS.begin()) {
    Serial.println("LittleFS mount failed!");
    return;
  }
  Serial.println("LittleFS mounted");

  // 2. Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  // 3. Sync NTP
  setClock();

  // 4. Load root CA
  caCert = readFile("/root-ca.crt");
  if (caCert == "") {
    Serial.println("CRITICAL: Could not load /root-ca.crt");
    while (1) delay(1000);
  }

  trustRoot = new BearSSL::X509List(caCert.c_str());
  secureclient.setBufferSizes(1024, 1024);
  secureclient.setTrustAnchors(trustRoot);

  // 5. Get public IP
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

  // 6. Ensure device has a valid key pair
  if (LittleFS.exists("/private.key") && LittleFS.exists("/public.key")) {
    Serial.println("Existing keys loaded from flash.");
    File skFile = LittleFS.open("/private.key", "r");
    skFile.read(sk, 32);
    skFile.close();

    File pkFile = LittleFS.open("/public.key", "r");
    pkFile.read(pk, 64);
    pkFile.close();
  } else {
    generateKeyPair();
  }

  // 7. Ensure device has certificate
  if (!LittleFS.exists("/client.crt") || !LittleFS.exists("/expiration.txt")) {
    Serial.println("No client cert found, requesting...");
    requestCert();
  }

  // 8. Load client cert
  clientCert = readFile("/client.crt");
  expiration = readFile("/expiration.txt").toInt();

  if (clientCert == "") {
    Serial.println("CRITICAL: Could not load client cert");
    while (1) delay(1000);
  }

  // 9. Setup device key and configure BearSSL client
  setupDeviceKey();
  clientCertList = new BearSSL::X509List(clientCert.c_str());
  secureclient.setClientECCert(clientCertList, deviceKey, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, BR_KEYTYPE_RSA);

  Serial.println("\nPrerequisites complete. Starting benchmarks...\n");
}

// ─── Loop (one-shot benchmarks) ─────────────────────────────────
void loop() {
  if (benchmarkDone) {
    delay(10000);
    return;
  }

  Serial.println("\n===== BENCHMARK START =====");
  Serial.printf("WiFi RSSI: %d dBm\n", WiFi.RSSI());
  Serial.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());

  benchmarkmTLSHandshake();
  benchmarkRenewal();
  benchmarkDataSend();
  benchmarkKeyGeneration();

  Serial.println("\n===== BENCHMARK COMPLETE =====\n");

  benchmarkDone = true;
}
