#define NORMALOP  0
#define RESET     1

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

// Wifi credentials
// const char* ssid     = "test";
// const char* password = "passtest";

// const char* ssid     = "Paella🥘";
// const char* password = "testpasstest";

const char* ssid     = "ndsgwifi";
const char* password = "H1b2idinF2@";

// Servers
const char* serverUrl = "https://51.20.87.204:8443/data";
const char* signUrl = "https://13.239.57.125:8000/receive-device-data/";
const char* certDownloadUrl = "https://13.239.57.125:8000/download-cert/";
const char* renewUrl = "https://13.239.57.125:8000/renew-cert/";

WiFiClientSecure secureclient;
HTTPClient https;

// Globals to hold certificate data in memory
String caCert;
String clientCert;
String publicIP;

uint8_t sk[32];
uint8_t pk[64];
uint8_t key_der[121];
unsigned long expiration;

BearSSL::X509List* trustRoot = nullptr;
BearSSL::X509List* clientCertList = nullptr;
BearSSL::PrivateKey* deviceKey = nullptr;

struct tm timeinfo;
time_t now;

JsonDocument doc;
String data;

// RNG for uECC
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

// File System Helpers
String readFile(const char* path) {
  Serial.printf("Reading file: %s\n", path);

  File file = LittleFS.open(path, "r");
  if (!file) {
    Serial.println("  - Failed to open file for reading");
    return "";
  }

  String fileContent = file.readString();
  file.close();

  Serial.printf("  - Read %d bytes\n", fileContent.length());
  return fileContent;
}

void writeFile(const char* path, const char* content) {
  File file = LittleFS.open(path, "w");
  if (!file) {
    Serial.printf("Failed to open %s for writing\n", path);
    return;
  }
  if (file.print(content)) {
    Serial.printf("File saved: %s\n", path);
  } else {
    Serial.println("Write failed");
  }
  file.close();
}

void generateKeyPair() {
  Serial.println("Creating ECC key pair...");
  uECC_set_rng(&RNG);
  const struct uECC_Curve_t* curve = uECC_secp256r1();
  yield();

  if (uECC_make_key(pk, sk, curve)) {
    Serial.println("Successfully generated key pair!");
    Serial.print("Private: ");
    printHex(sk, 32);
    Serial.print("Public: ");
    printHex(pk, 64);
    yield();

    File skFile = LittleFS.open("/private.key", "w");
    if (skFile) { skFile.write(sk, 32); skFile.close(); }

    File pkFile = LittleFS.open("/public.key", "w");
    if (pkFile) { pkFile.write(pk, 64); pkFile.close(); }

    Serial.println("Keys saved");
  } else {
    Serial.println("Failed to generate key pair!");
  }
}

void setupDeviceKey() {
  uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
  uint8_t mid[]  = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};

  memcpy(key_der, head, 7);
  memcpy(key_der + 7, sk, 32);
  memcpy(key_der + 39, mid, 18);
  memcpy(key_der + 57, pk, 64);
  deviceKey = new BearSSL::PrivateKey(key_der, 121);
}

// Synch Helper
void setClock() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  Serial.print(F("Waiting for NTP time sync: "));
  now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(500);
    Serial.print(F("."));
    yield();
    now = time(nullptr);
  }
  Serial.println();

  gmtime_r(&now, &timeinfo);
  Serial.print(F("Current time: "));
  Serial.print(asctime(&timeinfo));
}

int requestCert() {
  Serial.print("Public IP: ");
  Serial.println(publicIP);
  Serial.print("MAC address: ");
  Serial.println(WiFi.macAddress());

  // Format public key as hex string
  char pkbuffer[131];
  sprintf(pkbuffer, "04");
  for (int i = 0; i < 64; i++) {
    sprintf(pkbuffer + 2 + (i * 2), "%02x", pk[i]);
  }

  Serial.printf("Requesting certificate from %s...\n", signUrl);

  JsonDocument doc;
  doc["IP"] = publicIP;
  doc["MAC"] = WiFi.macAddress();
  doc["PublicKey"] = pkbuffer;
  String jsonPayload;
  serializeJson(doc, jsonPayload);

  // Device Auth Checkpoint
  int responsecode = 0;

  while (responsecode != 202) {
    secureclient.stop();
    delay(100);
    if (https.begin(secureclient, signUrl)) {
      Serial.println("Sending device data...");
      https.addHeader("Content-Type", "application/json");
      responsecode = https.POST(jsonPayload);
      Serial.println(responsecode);

      Serial.printf("Error sending data: %d - %s\n",
                    responsecode, https.errorToString(responsecode).c_str());
      https.end();
    } else {
      Serial.println("HTTP connection failed!");
    }
    delay(10000);
  }

  // Device Authenticated
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
      Serial.println("Certificate signed successfully!");
      writeFile("/client.crt", clientCert.c_str());
      writeFile("/expiration.txt", String(expiration).c_str());
    }
    Serial.printf("Error sending data: %d - %s\n",
                  responsecode, https.errorToString(responsecode).c_str());
    https.end();
  }

  return 0;
}

bool certExpiresWithinDay() {
  time_t expire_time = (time_t)expiration;
  time_t current_time = time(nullptr);

  double remaining = difftime(expire_time, current_time);
  Serial.printf("Cert expires in %.0f seconds\n", remaining);

  return remaining < 86400;
}

void renewCertificate() {
  Serial.println("Renewing client certificate...");

  String url = String(renewUrl) + WiFi.macAddress() + "/";

  if (!https.begin(secureclient, url)) {
    Serial.println("Failed to begin renewal connection");
    return;
  }

  https.addHeader("Content-Type", "application/x-pem-file");
  const char* headerKeys[] = {"X-Cert-Expires-At"};
  https.collectHeaders(headerKeys, 1);
  int httpCode = https.POST(clientCert);

  if (httpCode == 200) {
    String newCert = https.getString();
    expiration = https.header("X-Cert-Expires-At").toInt();
    writeFile("/client.crt", newCert.c_str());
    writeFile("/expiration.txt", String(expiration).c_str());
    clientCert = newCert;
    clientCertList = new BearSSL::X509List(clientCert.c_str());
    unsigned allowed_usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    unsigned cert_issuer_key_type = BR_KEYTYPE_RSA;
    secureclient.setClientECCert(clientCertList, deviceKey, allowed_usages, cert_issuer_key_type);
    Serial.println("Certificate renewed successfully");
  } else {
    Serial.printf("Certificate renewal failed: %d\n", httpCode);
  }

  https.end();
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  while(!Serial);

  // 1. Mount LittleFS
  if (!LittleFS.begin()) {
    Serial.println("An Error has occurred while mounting LittleFS");
    return;
  }
  Serial.println("LittleFS Mounted");

  // Remove previously generated keys and cert if needed
  Serial.print("Normal Operation (0), Reset (1): ");

  while (Serial.available() == 0) {
  }

  int mode = Serial.parseInt();

  if (mode == RESET) {
    LittleFS.remove("/private.key");
    LittleFS.remove("/public.key");
    LittleFS.remove("/client.crt");
    LittleFS.remove("/expiration.txt");
    Serial.println("Board credentials reset");
  }

  // 2. Generate key pair if keys do not exist
  if (!LittleFS.exists("/private.key") || !LittleFS.exists("/public.key")) {
    generateKeyPair();
  } else {
    Serial.println("Loading existing keys from flash...");
    File skFile = LittleFS.open("/private.key", "r");
    skFile.read(sk, 32);
    skFile.close();

    File pkFile = LittleFS.open("/public.key", "r");
    pkFile.read(pk, 64);
    pkFile.close();
  }

  // 3. Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  // 4. Sync Time for Cert Validation
  setClock();

  // 5. Load root CA cert
  caCert = readFile("/root-ca.crt");
  if (caCert == "") {
    Serial.println("CRITICAL ERROR: Could not load root CA certificate!");
    while(1) delay(1000);
  }

  trustRoot = new BearSSL::X509List(caCert.c_str());
  secureclient.setBufferSizes(1024, 1024);
  secureclient.setTrustAnchors(trustRoot);

  // 6. Get public IP
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

  // 7. Request client cert if not found
  if (!LittleFS.exists("/client.crt") || !LittleFS.exists("/expiration.txt")) requestCert();

  // 8. Load client cert and expiration
  clientCert = readFile("/client.crt");
  expiration = readFile("/expiration.txt").toInt();

  if (clientCert == "") {
    Serial.println("CRITICAL ERROR: Could not load certificate!");
    while(1) delay(1000);
  }

  // 9. Setup device key and apply certs to client
  setupDeviceKey();
  clientCertList = new BearSSL::X509List(clientCert.c_str());
  unsigned allowed_usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
  unsigned cert_issuer_key_type = BR_KEYTYPE_RSA;
  secureclient.setClientECCert(clientCertList, deviceKey, allowed_usages, cert_issuer_key_type);
}

void loop() {
  // if (certExpiresWithinDay()) {
  //   renewCertificate();
  // }

  Serial.print("Connecting to server... ");
  if (https.begin(secureclient, serverUrl)) {
    https.addHeader("Content-Type", "application/json");

    // Prepare JSON Data
    doc["temp"] = random(15, 21);

    now = time(nullptr);
    timeinfo = *localtime(&now);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);

    doc["time"] = timeStr;
    doc["MAC"] = WiFi.macAddress();

    serializeJson(doc, data);

    int httpResponseCode = https.POST(data);

    if (httpResponseCode > 0) {
      Serial.printf("Success: %d\n", httpResponseCode);
      Serial.println(https.getString());
    } else {
      Serial.printf("Error: %s\n", https.errorToString(httpResponseCode).c_str());
    }
    https.end();
    delay(3000);
  }
  delay(2000);
}