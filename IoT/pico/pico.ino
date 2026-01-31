// Network
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

// File system
#include <LittleFS.h>

// Message formatting
#include <ArduinoJson.h>

// Synchronization
#include <time.h>

// Security packages 
#include <uECC.h>

// Wifi credentials
// const char* ssid     = "test";
// const char* password = "passtest";

// const char* ssid = "Dennis";
const char* ssid = ">";
const char* password = "ddddd123";

// Server Info
const char* server_ip = "192.168.124.240";
const int idport = 8000;
const int commsport = 8443;

WiFiClient client;
WiFiClientSecure secureclient;
HTTPClient http;

// Globals to hold certificate data in memory
uint8_t sk[32];
uint8_t pk[64];
String caCert;
String clientCert;
uint8_t key_der[121]; 

BearSSL::X509List* trustRoot = nullptr;
BearSSL::X509List* clientCertList = nullptr;
BearSSL::PrivateKey* deviceKey = nullptr;

struct tm timeinfo;

// File System Helpers
  // byte-array for keys
int readFile(const char* path, uint8_t* destination, size_t len) {
  Serial.printf("Reading file: %s\n", path);
  File file = LittleFS.open(path, "r");
  if (!file) {
    Serial.println("  - Failed to open file for reading");
    return -1;
  }

  size_t actualSize = file.size();
  if (actualSize < len) {
    Serial.println("  - File is smaller than expected buffer");
    file.close();
    return -1;
  }
  file.read(destination, len);

  file.close();
  Serial.printf("  - Read %d bytes\n", actualSize);
  return 0;
}

  // String for certs
String readStringFile(const char* path) {
  Serial.printf("Reading file: %s\n", path);
  File file = LittleFS.open(path, "r");
  if (!file) {
    Serial.println("  - Failed to open file for reading");
    return "";
  }

  String content = file.readString();
  file.close();

  Serial.printf("  - Read %d bytes\n", content.length());
  return content;
}

int writeFile(const char* path, const uint8_t* content, int len) {
  File file = LittleFS.open(path, "w");
  if (!file) {
    Serial.printf("Failed to open %s for writing\n", path);
    return -1;
  }
  file.write(content, len);
  file.close();

  Serial.printf("File saved: %s\n", path);
  return 0;
}

// --- Helper: Print Hex ---
void printHex(uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

// --- RNG for micro-ecc ---
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

// Generates key pair if keys and client cert are not found
void generateKeyPair() {
  if (LittleFS.exists("/private.key") && LittleFS.exists("/public.key") && LittleFS.exists("/client.key")) {
    Serial.println("Keys and client cert exist");
    return;
  }

  Serial.println("Creating ecc key pair");
  uECC_set_rng(&RNG);
  Serial.println("RNG set");

  const struct uECC_Curve_t* curve = uECC_secp256r1();

  // Determine key sizes
  // secp256r1: Private key = 32 bytes, Public key = 64 bytes
  if (uECC_make_key(pk, sk, curve)) {
    Serial.println("Successfully generated key pair!");
    Serial.print("Private: ");
    printHex(sk, 32);
    Serial.print("Public: ");
    printHex(pk, 64);

    writeFile("/private.key", sk, 32);
    writeFile("/public.key", pk, 64);
  } else {
    Serial.println("Failed to generate keys!");
    while(1) delay(1000);
  }
}

// Synch Helper
void setClock() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  Serial.print("Waiting for NTP time sync: ");
  time_t nowSecs = time(nullptr);
  while (nowSecs < 8 * 3600 * 2) {
    delay(500);
    Serial.print(".");
    nowSecs = time(nullptr);
  }
  Serial.println();

  gmtime_r(&nowSecs, &timeinfo);
  Serial.print("Current time: ");
  Serial.print(asctime(&timeinfo));
}

// Request client cert if not existing
void requestCert() {
  // Reload key if they aren't in memory (e.g. after reboot)
  readFile("/public.key", pk, 64);
  
  IPAddress ip = WiFi.localIP();

  Serial.print("IP address: ");
  Serial.println(ip);
  Serial.print("MAC address: ");
  Serial.println(WiFi.macAddress());
  
  Serial.println("Connected to id server...");
  
  // Convert Raw Public Key to Hex String
  char pkbuffer[131];
  sprintf(pkbuffer, "04"); // Uncompressed point indicator
  for (int i = 0; i < 64; i++) {
    sprintf(pkbuffer + 2 + (i * 2), "%02x", pk[i]);
  }

  JsonDocument doc;
  doc["IP"] = ip.toString();
  doc["MAC"] = WiFi.macAddress();
  doc["PublicKey"] = pkbuffer;
  String jsonPayload;
  serializeJson(doc, jsonPayload);

  // Send Connect to csr server
  int responsecode = 0;
  while (responsecode != 202) {
    if(client.connect(server_ip, idport)) {
        http.begin(client, server_ip, idport, "/receive-device-data/", false); // false = HTTP
        http.addHeader("Content-Type", "application/json");
        responsecode = http.POST(jsonPayload);
        Serial.printf("POST Response: %d\n", responsecode);
        http.end();
        client.stop();
    } else {
        Serial.println("Connection to ID server failed, retrying...");
    }
    delay(2000);
  }

  // Poll for Certificate (Loop until 200 OK)
  responsecode = 0;
  while (responsecode != 200) {
    delay(5000); 
    Serial.println("Waiting for certificate...");
    
    if(client.connect(server_ip, idport)) {
        String url = "/download-cert/" + WiFi.macAddress() + "/";
        http.begin(client, server_ip, idport, url, false);
        responsecode = http.GET();
        
        if (responsecode == 200) {
            clientCert = http.getString();
            if (writeFile("/client.crt", (const uint8_t*)clientCert.c_str(), clientCert.length()) == 0) {
                Serial.println("Certificate downloaded and saved.");
            }
        } else {
            Serial.printf("Cert not ready yet (Code %d)\n", responsecode);
        }
        http.end();
        client.stop();
    }
  }
}

// --- Memory Cleanup ---
void clearCerts() {
  if (trustRoot) { delete trustRoot; trustRoot = nullptr; }
  if (clientCertList) { delete clientCertList; clientCertList = nullptr; }
  if (deviceKey) { delete deviceKey; deviceKey = nullptr; }
}

void setup() {
  Serial.begin(115200);
  while(!Serial);
  
  // 1. Mount File System
  if(!LittleFS.begin()) {
    Serial.println("LittleFS Mount Failed. Did you select a Flash Size with FS?");
    return;
  }

  // Remove previously generated keys and cert if needed
  LittleFS.remove("/private.key");
  LittleFS.remove("/public.key");
  LittleFS.remove("/client.crt");


  // 2. Generate keys if not found or initial boot
  generateKeyPair();

  // 3. Connect to WiFi
  Serial.printf("Connecting to %s ", ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
  }
  Serial.println("Connected");

  // 4. Sync Time (Required for TLS validation)
  setClock();

  // 5. Check/Request Cert
  if (!LittleFS.exists("/client.crt")) requestCert();

  // 6. Load Certificates into Memory
  caCert = readStringFile("/root-ca.crt");
  clientCert = readStringFile("/client.crt");
  readFile("/private.key", sk, 32);
  readFile("/public.key", pk, 64);

  if (caCert == "" || clientCert == "") {
    Serial.println("CRITICAL: Client cert missing.");
    while(1) delay(1000);
  }

  // 7. Construct DER Private Key for BearSSL
  // BearSSL expects a formatted ASN.1 structure, not just the raw scalar.
  // This header sequence wraps the raw key into a standard format.
  uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
  uint8_t mid[]  = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};
  
  memset(key_der, 0, 121);
  memcpy(key_der, head, 7);
  memcpy(key_der + 7, sk, 32);
  memcpy(key_der + 39, mid, 18);
  memcpy(key_der + 57, pk, 64);

  // 8. Configure BearSSL Client
  clearCerts();
  
  trustRoot = new BearSSL::X509List(caCert.c_str());
  clientCertList = new BearSSL::X509List(clientCert.c_str());
  deviceKey = new BearSSL::PrivateKey(key_der, 121);

  unsigned allowed_usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN; 
  unsigned cert_issuer_key_type = BR_KEYTYPE_RSA; 
  secureclient.setTrustAnchors(trustRoot);
  secureclient.setClientECCert(clientCertList, deviceKey, allowed_usages, cert_issuer_key_type);

  Serial.print("Checking sk alignment: ");
  for (int i = 0; i < 32; i++) {
      if (sk[i] < 16) Serial.print("0");
      Serial.print(sk[i], HEX);
  }
  Serial.println();
  
  Serial.println("Pico W initialized and ready for mTLS.");
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    // secureclient is already configured with the certs in setup()
    
    // Connect to the secure data server
    Serial.print("Connecting to Data Server... ");
    // Note: Use IPAddress object or string. Comm port 8443 usually implies SSL.
    if (secureclient.connect(server_ip, commsport)) {
      Serial.println("Connected!");

      // Prepare JSON Data
      JsonDocument doc;
      doc["temp"] = random(1500, 2101) / 100.0;
      doc["device"] = "PicoW";
      
      String payload;
      serializeJson(doc, payload);

      // Send HTTP POST
      http.begin(secureclient, String("https://") + server_ip + ":" + commsport + "/data");
      http.addHeader("Content-Type", "application/json");
      
      int httpCode = http.POST(payload);
      
      if (httpCode > 0) {
        Serial.printf("Server Response: %d\n", httpCode);
        String response = http.getString();
        Serial.println(response);
      } else {
        Serial.printf("HTTP Error: %s\n", http.errorToString(httpCode).c_str());
      }
      
      http.end();
      secureclient.stop();
    } else {
      Serial.println("Connection Failed.");
      char err[100];
      secureclient.getLastSSLError(err, 100);
      Serial.printf("SSL Error: %s\n", err);
    }
  } else {
    Serial.println("WiFi Disconnected");
  }
  
  delay(10000); // Wait 10 seconds before next push
}