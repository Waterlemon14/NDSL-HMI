// Network
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

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
// const char* ssid = ">";
// const char* password = "ddddd123";

const char* ssid     = "ndsgwigi";
const char* password = "H1b2idinF2";

// Server Info
const char* server = "10.147.36.131";
IPAddress host(10,147,36,131);
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

  Serial.printf("  - Read %d bytes\n", actualSize);
  
  file.read(destination, len);
  file.close();
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

// Generates key pair if keys and client cert are not found
void generateKeyPair() {
  if (LittleFS.exists("/private.key") && LittleFS.exists("/public.key") && LittleFS.exists("/client.key")) {
    Serial.println("Keys and client cert exist");
    return;
  }

  // Generate private-public key pair
  Serial.println("Creating ecc key pair");
  uECC_set_rng(&RNG);
  Serial.println("RNG set");

  const struct uECC_Curve_t* curve = uECC_secp256r1();

  yield();
  ESP.wdtFeed();

  if (uECC_make_key(pk, sk, curve)) {
    Serial.println("Successfully generated key pair!");
    Serial.print("Private: ");
    printHex(sk, 32);
    Serial.print("Public: ");
    printHex(pk, 64);

    yield();
    ESP.wdtFeed();

    writeFile("/private.key", sk, 32);
    writeFile("/public.key", pk, 64);
  } else {
    Serial.println("Failed to generate key pair!");
    while(1) delay(1000);
  }
}

// Synch Helper
void setClock() {
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

  gmtime_r(&nowSecs, &timeinfo);
  Serial.print(F("Current time: "));
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

  // Connect to csr server
  if (client.connect(host, idport)) {
    Serial.println("Connected to id server");
  } else {
    Serial.println("Failed to connect to id server");
    uint8_t state = client.status(); 
    Serial.print("Connection failed. TCP State: ");
    Serial.println(state);
    while(1) delay(1000); // Halt;
  }

  Serial.println("Requesting certificate...");
  
  int responsecode = 0;
  while (responsecode != 202){
    delay(1000);
    Serial.println("Sending device data...");
    http.begin(client, server, idport, "/receive-device-data/");
    http.addHeader("Content-Type", "application/json");
    responsecode = http.POST(jsonPayload);
    Serial.println(responsecode);
    http.end();
  }

  responsecode = 0;
  while (responsecode != 200){
    delay(10000);
    Serial.println("Waiting for certificate...");
    http.begin(client, server, idport, "/download-cert/" + WiFi.macAddress() + "/");
    responsecode = http.GET();
    if (responsecode == 200){
      clientCert = http.getString();
      if (writeFile("/client.crt", (const uint8_t*)clientCert.c_str(), clientCert.length()) == 0) {
          Serial.println("Certificate saved successfully");
      } else {
          Serial.println("Failed to save certificate");
          while(1) delay(1000); // Halt;
      }
    }
    http.end();
  }

  if (client.connected()) {
    client.stop();
    Serial.println("Closed connection to idserver");
  }
}

void clearCerts() {
  if (trustRoot) { 
    delete trustRoot; 
    trustRoot = nullptr; 
  }
  if (clientCertList) { 
    delete clientCertList; 
    clientCertList = nullptr; 
  }
  if (deviceKey) { 
    delete deviceKey; 
    deviceKey = nullptr; 
  }
}

void setup() {
  Serial.begin(115200);
  while(!Serial);

  // 1. Mount LittleFS
  if(!LittleFS.begin()) {
    Serial.println("LittleFS Mount Failed. Did you select a Flash Size with FS?");
    return;
  }

  // Debugging lines
  Serial.println(ESP.getResetReason());
  delay(1000);

  // Remove previously generated keys and cert if needed
  LittleFS.remove("/private.key");
  LittleFS.remove("/public.key");
  LittleFS.remove("/client.crt");

  // 2. Generate keys if not found or initial boot
  generateKeyPair();

  // 3. Connect to WiFi
  Serial.printf("Connecting to %s", ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
  }
  Serial.println("Connected");

  // 4. Sync Time for Cert Validation
  setClock();

  // 5. Request client cert if not found or initial boot
  if (!LittleFS.exists("/client.crt")) requestCert();

  // 6. Load Certs and keys
  caCert = readStringFile("/root-ca.crt");
  clientCert = readStringFile("/client.crt");
  readFile("/private.key", sk, 32);
  readFile("/public.key", pk, 64);

  if (caCert == "" || clientCert == "") {
    Serial.println("CRITICAL ERROR: Could not load one or more certificate files!");
    while(1) delay(1000); // Halt
  }
  
  // 7. Apply Certs to Client
  uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
  uint8_t mid[]  = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};

  memcpy(key_der, head, 7);
  memcpy(key_der + 7, sk, 32);
  memcpy(key_der + 39, mid, 18);
  memcpy(key_der + 57, pk, 64);

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

  Serial.println("ESP8266 initialized and ready for mTLS.");
}

void loop() {
  // put your main code here, to run repeatedly:
  if (WiFi.status() == WL_CONNECTED) {
    secureclient.setBufferSizes(1024, 1024);
    if (secureclient.connect(host, commsport)) {
      Serial.println("Connected to data server");
      Serial.printf("Heap before http connection: %d\n", ESP.getFreeHeap());
      secureclient.setInsecure();

      HTTPClient http;
      if (http.begin(secureclient, "https://10.147.36.131:8443/data")) {
        http.addHeader("Content-Type", "application/json");

        StaticJsonDocument<200> doc;
        time_t now = time(nullptr);
        struct tm* timeinfo = localtime(&now);
        char buffer[20]; 
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        double temp = random(1500, 2101) / 100.0;
        doc["temp"] = temp;
        doc["time"] = buffer;
        
        String data;
        serializeJson(doc, data);

        int httpResponseCode = http.POST(data);

        if (httpResponseCode > 0) {
          String response = http.getString();
          Serial.println(httpResponseCode);
          Serial.println(response);
        } else {
          Serial.print("Error on sending POST: ");
          Serial.println(http.errorToString(httpResponseCode).c_str());
        }

        http.end();
      } else {
        Serial.println("Http connection failed!");
      }

      
      // if (http.begin(secureclient, "https://192.168.0.212:8443/ping")) {
      //   int httpCode = http.GET(); 
      //   if (httpCode > 0) {
      //     String payload = http.getString();
      //     Serial.printf("mTLS Handshake Success! Response: %s\n", payload.c_str());
      //   } else {
      //     // If this fails with -1, the handshake itself is failing (Cert/Key issue)
      //     Serial.printf("Handshake Failed: %s\n", http.errorToString(httpCode).c_str());
      //   }
      //   http.end();
      // } else {
      //   Serial.println("Http connection failed!");
      // }
      
      // if (secureclient.connect(host, 8001)) {
      //   Serial.println("mTLS Connection Successful!");
      //   secureclient.print("GET /hello HTTP/1.1\r\nHost: ");
      //   secureclient.print(server);
      //   secureclient.print("\r\nConnection: close\r\n\r\n");
        
      //   while (secureclient.connected() || secureclient.available()) {
      //     if (secureclient.available()) Serial.write(secureclient.read());
      //   }
      //   secureclient.stop();
      // } else {
      //   Serial.print("Connection failed. Error: ");
      //   Serial.println(secureclient.getLastSSLError());
      // }

      secureclient.stop();
      Serial.println("\nConnection closed");
    } else {
      Serial.print("Connection failed! ");
      int errCode = secureclient.getLastSSLError();
      Serial.printf("mTLS Error: %d\n", errCode);
    }
    delay(10000);
  } else {
    Serial.println("WiFi disconnected");
    delay(10000);
  }
}

static int RNG(uint8_t* dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }

      if (count == 0) {
        val = (val << 1) | (init & 0x01);
      } else {
        val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}


void printHex(uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");  // Leading zero for single hex digits
    Serial.print(data[i], HEX);
  }
  Serial.println();
}