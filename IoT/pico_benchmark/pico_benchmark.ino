#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <LittleFS.h>
#include <time.h>
#include <uECC.h>
#include <ArduinoJson.h>

// ─── Configuration ───────────────────────────────────────────────
const char* ssid     = "test";
const char* password = "passtest";

const char* server   = "192.168.0.212";
IPAddress host(192, 168, 0, 212);
const char* data_url    = "https://192.168.0.212:8443/data";
const int idport       = 8000;
const int commsport    = 8443;

const int BENCHMARK_ITERATIONS = 1000;

// ─── Globals ─────────────────────────────────────────────────────
uint8_t sk[32];
uint8_t pk[64];
String caCert;
String clientCert;
uint8_t key_der[121];

BearSSL::X509List* trustRoot = nullptr;
BearSSL::X509List* clientCertList = nullptr;
BearSSL::PrivateKey* deviceKey = nullptr;

WiFiClient client;
WiFiClientSecure secureclient;
HTTPClient http;
IPAddress ip;

bool benchmarkDone = false;

// ─── RNG Implementation ────────────────────────────────────────
// The RP2040 has a hardware random number generator used by the WiFi stack.
// We wrap the Arduino 'random' which is seeded by HW on this core.
static int RNG(uint8_t *dest, unsigned size) {
  while (size) {
    *dest = (uint8_t)random(256);
    dest++;
    size--;
  }
  return 1;
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

// ─── Benchmark 2: TLS Handshake (BearSSL) ───────────────────────
void benchmarkTLSHandshake() {
  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    unsigned long start = millis();
    bool connected = secureclient.connect(host, commsport);
    unsigned long elapsed = millis() - start;

    if (connected) {
      Serial.printf("TLSHandshake,%d,%lu,SUCCESS\n", i + 1, elapsed);
      secureclient.stop();
    } else {
      Serial.printf("TLSHandshake,%d,%lu,FAILED\n", i + 1, elapsed);
    }
    delay(500); // Allow sockets to clean up
  }
}

// ─── Benchmark 3: Data Send Roundtrip (JSON + POST) ──────────────
void benchmarkDataSend() {
  for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
    if (secureclient.connect(host, commsport)) {
      HTTPClient http;
      http.begin(secureclient, data_url);
      http.addHeader("Content-Type", "application/json");

      JsonDocument doc;
      time_t now = time(nullptr);
      struct tm* timeinfo = localtime(&now);
      char buffer[20]; 
      strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
      int temp = random(15, 21);
      doc["temp"] = temp;
      doc["time"] = buffer;
      doc["MAC"] = WiFi.macAddress();
      String data;
      serializeJson(doc, data);

      unsigned long start = millis();
      int httpCode = http.POST(data);
      String response = http.getString();
      unsigned long elapsed = millis() - start;
      
      if (httpCode > 0) {
        Serial.printf("DataSend,%d,%lu,HTTP%d\n", i + 1, elapsed, httpCode);
      } else {
        Serial.printf("DataSend,%d,%lu,\"ERROR:%s\"\n", i + 1, elapsed,
                      http.errorToString(httpCode).c_str());
      }
      http.end();
      secureclient.stop();
    }
    delay(10);
  }
}

// ─── Setup (Initialization logic preserved) ──────────────────────
void setup() {
  Serial.begin(115200);
  delay(1000);
  while(!Serial);

  Serial.println("\n===== PICO BENCHMARK TEST SUITE =====\n");

  LittleFS.begin();
  Serial.println("\nLittleFS Initialized");
  
  Serial.print("\nConnecting to WiFi.");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nWiFi Connected");

  // NTP Sync
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  Serial.print(F("Waiting for NTP time sync: "));
  time_t nowSecs = time(nullptr);
  while (nowSecs < 8 * 3600 * 2) {
    delay(500);
    Serial.print(F("."));
    yield();
    nowSecs = time(nullptr);
  }
  Serial.println();
  struct tm timeinfo;
  gmtime_r(&nowSecs, &timeinfo);
  Serial.print(F("Current time: "));
  Serial.print(asctime(&timeinfo));

  // Load root CA
  if (LittleFS.exists("/root-ca.crt")){
    Serial.println("Loading CA certificate...");
    File caFile = LittleFS.open("/root-ca.crt", "r");
    if (caFile) {
      caCert = caFile.readString();
      caCert.trim();
      caFile.close();
      Serial.println("CA certificate loaded");
    }
  } else {
    Serial.println("CRITICAL: Could not load /root-ca.crt");
    while (1) delay(1000);
  }

  // Ensure device has key-pair
  if (LittleFS.exists("/private.key") && LittleFS.exists("/public.key")) {
    Serial.println("Existing keys loaded from flash.");
    File skFile = LittleFS.open("/private.key", "r");
    skFile.read(sk, 32);
    skFile.close();

    File pkFile = LittleFS.open("/public.key", "r");
    pkFile.read(pk, 64);
    pkFile.close();
  } else {
    // Generate private-public key pair
    Serial.println("Creating ecc key pair");
    uECC_set_rng(&RNG);
    const struct uECC_Curve_t* curve = uECC_secp256r1();
    yield();
    if (uECC_make_key(pk, sk, curve)) {
      Serial.println("Successfully generated key pair!");

      yield();

      File skFile = LittleFS.open("/private.key", "w");
      if (skFile) {
        skFile.write(sk, 32);
        skFile.close();
        Serial.println("Private key saved");
      }

      File pkFile = LittleFS.open("/public.key", "w");
      if (pkFile) {
        pkFile.write(pk, 64);
        pkFile.close();
        Serial.println("Public key saved");
      }

    } else {
      Serial.println("Failed to generate key pair!");
    }
  }

  // Ensure device has certificate
  if (LittleFS.exists("/client.crt")){
    File certFile = LittleFS.open("/client.crt", "r");
    if (certFile) {
      clientCert = certFile.readString();
      certFile.close();
      Serial.println("Client certificate loaded from flash");
    }
  } else {
    Serial.println("Requesting certificate...");
    char pkbuffer[131];
    sprintf(pkbuffer, "04");
    for (int i = 0; i < 64; i++) {
        sprintf(pkbuffer + 2 + (i * 2), "%02x", pk[i]);
    }

    JsonDocument doc;
    doc["IP"] = ip.toString();
    doc["MAC"] = WiFi.macAddress();
    doc["PublicKey"] = pkbuffer;
    String jsonPayload;
    serializeJson(doc, jsonPayload);

    int responsecode = 0;
    http.begin(client, server, idport, "/receive-device-data/");
    while (responsecode != 202){
      Serial.println("Sending device data...");
      http.addHeader("Content-Type", "application/json");
      responsecode = http.POST(jsonPayload);
      Serial.println(responsecode);
      delay(10000);
    }
    http.end();

    responsecode = 0;
    while (responsecode != 200){
      delay(10000);
      Serial.println("Waiting for certificate...");
      http.begin(client, server, idport, "/download-cert/" + WiFi.macAddress() + "/");
      responsecode = http.GET();
      if (responsecode == 200){
        clientCert = http.getString();
      }
      http.end();
    }
    File certFile = LittleFS.open("/client.crt", "w");
    if (certFile) {
      certFile.print(clientCert);
      certFile.close();
      Serial.println("Certificate saved");
    } else {
      Serial.println("Certificate not found");
    }
  }

  // Prepare BearSSL Structures (The key_der wrapping you implemented)
  uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
  uint8_t mid[]  = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};
  memcpy(key_der, head, 7);
  memcpy(key_der + 7, sk, 32);
  memcpy(key_der + 39, mid, 18);
  memcpy(key_der + 57, pk, 64);
  
  deviceKey = new BearSSL::PrivateKey(key_der, 121);
  trustRoot = new BearSSL::X509List(caCert.c_str());
  clientCertList = new BearSSL::X509List(clientCert.c_str());

  secureclient.setBufferSizes(1024, 1024);
  secureclient.setTrustAnchors(trustRoot);
  secureclient.setClientECCert(clientCertList, deviceKey, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, BR_KEYTYPE_RSA);

  Serial.println("\nPrerequisites complete. Starting benchmarks...\n");
}

void loop() {
  if (benchmarkDone) return;

  Serial.println("\n===== BENCHMARK START =====");
  benchmarkKeyGeneration();
  benchmarkTLSHandshake();
  benchmarkDataSend();
  Serial.println("===== BENCHMARK COMPLETE =====");

  benchmarkDone = true;
}