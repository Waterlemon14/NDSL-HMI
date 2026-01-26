#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <uECC.h>
#include <LittleFS.h>

#include <ArduinoJson.h>
#include <time.h>

const char* ssid = "test";
const char* password = "passtest";

const char* server = "10.141.173.223";
IPAddress host(10,141,173,223);
const int idport = 8000;
const int commsport = 8443;

WiFiClient client;
WiFiClientSecure secureclient;
HTTPClient http;
IPAddress ip;

uint8_t sk[32];
uint8_t pk[64];
String caCert;
String clientCert;
uint8_t key_der[121];

BearSSL::X509List* trustRoot = nullptr;
BearSSL::X509List* clientCertList = nullptr;
BearSSL::PrivateKey* deviceKey = nullptr;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  LittleFS.begin();
  Serial.println(ESP.getResetReason());
  delay(1000);

  // Remove previously generated keys and cert
  LittleFS.remove("/private.key");
  LittleFS.remove("/public.key");
  LittleFS.remove("/client.crt");
  
  // Check for generated key pair & certificate
  if (LittleFS.exists("/private.key") && LittleFS.exists("/public.key")) {
    Serial.println("Loading existing keys from flash...");
    File skFile = LittleFS.open("/private.key", "r");
    skFile.read(sk, 32);
    skFile.close();

    File pkFile = LittleFS.open("/public.key", "r");
    pkFile.read(pk, 64);
    pkFile.close();
  } else {
    // Generate private-public key pair
    Serial.print("Creating ecc key pair");
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

  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected");

  ip = WiFi.localIP();

  Serial.print("IP address: ");
  Serial.println(ip);
  Serial.print("MAC address: ");
  Serial.println(WiFi.macAddress());

  // Connect to csr server
  if (client.connect(host, idport)) {
    Serial.println("Connected to id server");
  } else {
    Serial.println("Failed to connect to id server");
    uint8_t state = client.status(); 
    Serial.print("Connection failed. TCP State: ");
    Serial.println(state);
  }

  // Check for certificate, request if not present
  if (!LittleFS.exists("/client.crt")){
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
  } else {
    File certFile = LittleFS.open("/client.crt", "r");
    if (certFile) {
      clientCert = certFile.readString();
      certFile.close();
      Serial.println("Client certificate loaded");
    }
  }

  if (LittleFS.exists("/root-ca.crt")){
    Serial.println("Loading CA certificate...");
    File caFile = LittleFS.open("/root-ca.crt", "r");
    if (caFile) {
      caCert = caFile.readString();
      caFile.close();
      Serial.println("CA certificate loaded");
    }

    if (client.connected()) {
      client.stop();
      Serial.println("Closed connection to idserver");
    }

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

    
    uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
    uint8_t mid[]  = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};

    memcpy(key_der, head, 7);
    memcpy(key_der + 7, sk, 32);
    memcpy(key_der + 39, mid, 18);
    memcpy(key_der + 57, pk, 64);
    deviceKey = new BearSSL::PrivateKey(key_der, 121);

    trustRoot = new BearSSL::X509List(caCert.c_str());
    clientCertList = new BearSSL::X509List(clientCert.c_str());
    // deviceKey = new BearSSL::PrivateKey(sk, 32);
    unsigned allowed_usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    unsigned cert_issuer_key_type = BR_KEYTYPE_RSA;
    secureclient.setTrustAnchors(trustRoot);
    secureclient.setClientECCert(clientCertList, deviceKey, allowed_usages, cert_issuer_key_type);

    Serial.print("CA Cert Length: ");
    Serial.println(caCert.length());
    Serial.print("Client Cert Length: ");
    Serial.println(clientCert.length());
    Serial.print("Checking sk alignment: ");
    for (int i = 0; i < 32; i++) {
        if (sk[i] < 16) Serial.print("0");
        Serial.print(sk[i], HEX);
    }
    Serial.println();
  } else {
    Serial.println("No CA certificate found");
  }
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
      if (http.begin(secureclient, "https://10.141.173.223:8443/data")) {
        http.addHeader("Content-Type", "application/json");

        StaticJsonDocument<200> doc;
        time_t now = time(nullptr);
        struct tm* timeinfo = localtime(&now);
        char buffer[20]; 
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        int temp = random(15, 21);
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