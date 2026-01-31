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

// Wifi credentials
// const char* ssid     = "test";
// const char* password = "passtest";

// const char* ssid     = ">";
// const char* password = "ddddd123";

const char* ssid     = "ndsgwifi";
const char* password = "H1b2idinF2@";

// Servers
const char* serverUrl = "https://10.147.36.131:8443/data";
const char* signUrl = "http://10.147.36.131:8000/receive-device-data/";
const char* certDownloadUrl = "http://10.147.36.131:8000/download-cert/";

WiFiClientSecure client;
HTTPClient https;
HTTPClient http;

// Globals to hold certificate data in memory
String ca_cert_str;
String client_cert_str;
String client_key_str;

float temp;
struct tm timeinfo;
time_t now;

// File System Helpers
String readFile(const char* path) {
  Serial.printf("Reading file: %s\n", path);

  File file = SPIFFS.open(path, "r");
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
  File file = SPIFFS.open(path, "w");
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

// Generates CSR if key and client cert are not found
void generateCSR() {
  if (SPIFFS.exists("/client.key") && SPIFFS.exists("/client.crt")) {
    Serial.println("Key and client cert exist");
    return;
  }

  mbedtls_pk_context key;
  mbedtls_x509write_csr csr;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  unsigned char output_buf[2048];
  const char *pers = "csr_gen_ecc";

  mbedtls_pk_init(&key);
  mbedtls_x509write_csr_init(&csr);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  // 1. Seed Random Number Generator
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

  // 2. Generate ECC Key (secp256r1 / NIST P-256)
  Serial.println("Generating ECC key...");
  int ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (ret != 0) {
    Serial.printf("mbedtls_pk_setup failed: -0x%04x\n", -ret);
    return;
  }
  ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("ECC Key gen failed: -0x%04x\n", -ret);
    return;
  }

  // 3. Save Private Key
  unsigned char key_buf[1600];
  mbedtls_pk_write_key_pem(&key, key_buf, sizeof(key_buf));
  writeFile("/client.key", (char*)key_buf);

  // 4. Set CSR Parameters
  mbedtls_x509write_csr_set_key(&csr, &key);
  mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_subject_name(&csr, "C=CA, ST=., L=., O=., OU=., CN=localhost");

  // 5. Save CSR
  memset(output_buf, 0, sizeof(output_buf));
  ret = mbedtls_x509write_csr_pem(&csr, output_buf, sizeof(output_buf), mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret == 0) {
    writeFile("/client.csr", (char*)output_buf);
  } else {
    Serial.printf("CSR PEM generation failed: -0x%04x\n", -ret);
  }

  // Cleanup
  mbedtls_pk_free(&key);
  mbedtls_x509write_csr_free(&csr);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
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
  IPAddress ip = WiFi.localIP();

  Serial.print("IP address: ");
  Serial.println(ip);
  Serial.print("MAC address: ");
  Serial.println(WiFi.macAddress());

  // 1. Read the CSR file
  String csr = readFile("/client.csr");
  if (csr == "") {
    Serial.println("Failed to read CSR from SPIFFS");
    return -1;
  }

  Serial.printf("Requesting certificate from %s...\n", signUrl);

  JsonDocument doc;
  doc["IP"] = ip.toString();
  doc["MAC"] = WiFi.macAddress();
  doc["CSR"] = csr;
  String jsonPayload;
  serializeJson(doc, jsonPayload);

  int responsecode = 0;
  while (responsecode != 202){
    delay(1000);
    Serial.println("Sending device data...");
    http.begin(signUrl);
    http.addHeader("Content-Type", "application/json");
    responsecode = http.POST(jsonPayload);
    Serial.println(responsecode);
    http.end();
    Serial.printf("Error sending CSR: %d - %s\n", 
                  responsecode, http.errorToString(responsecode).c_str());
  }

  responsecode = 0;
  while (responsecode != 200){
    delay(10000);
    Serial.println("Waiting for certificate...");
    http.begin(certDownloadUrl + WiFi.macAddress() + "/");
    responsecode = http.GET();
    if (responsecode == 200){
      String signedCert = http.getString();
      Serial.println("Certificate signed successfully!");
      writeFile("/client.crt", signedCert.c_str());
    }
    http.end();
    Serial.printf("Error sending CSR: %d - %s\n", 
                  responsecode, http.errorToString(responsecode).c_str());
  }

  return 0;
}

void setup() {
  Serial.begin(115200);
  while(!Serial);

  // 1. Mount SPIFFS
  if (!SPIFFS.begin(true)) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }

  // Remove previously generated keys and cert if needed
  SPIFFS.remove("/client.key");
  SPIFFS.remove("/client.csr");
  SPIFFS.remove("/client.crt");

  // 2. Generate CSR
  generateCSR();

  // 3. Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  // 4. Sync Time for Cert Validation
  setClock();

  // 5. Request client cert if not found or initial boot
  if (!SPIFFS.exists("/client.crt")) requestCert();
  
  // 6. Load Certs and keys
  ca_cert_str     = readFile("/root-ca.crt");
  client_cert_str = readFile("/client.crt");
  client_key_str  = readFile("/client.key");
  
  if (ca_cert_str == "" || client_cert_str == "" || client_key_str == "") {
    Serial.println("CRITICAL ERROR: Could not load one or more certificate files!");
    while(1) delay(1000); // Halt
  }

  // 7. Apply Certs to Client
  client.setCACert(ca_cert_str.c_str());
  client.setCertificate(client_cert_str.c_str());
  client.setPrivateKey(client_key_str.c_str());
}

void loop() {
  Serial.print("Connecting to server... ");
  if (https.begin(client, serverUrl)) {
    while(true) {
      https.addHeader("Content-Type", "application/json");

      JsonDocument doc;
      doc["temp"] = random(1500, 2101) / 100.0;

      now = time(nullptr);
      timeinfo = *localtime(&now);
      char timeStr[20]; 
      strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
      double temp = random(1500, 2101) / 100.0;
      doc["temp"] = temp;
      doc["time"] = timeStr;

      // temp = 20.0 + (float)(esp_random() % 1000) / 100.0;

      // now = time(nullptr);
      // timeinfo = localtime(&now);

      // char timeStr[30]; 
      // strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);

      // doc["temp"] = temp;
      // doc["time"] = buffer;

      // char timeStr[30];
      // strftime(timeStr, sizeof(timeStr), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);

      String data;
      serializeJson(doc, data);
      
      // Create JSON Payload
      // String jsonPayload = "{\"temp\": " + String(temp) + ", \"time\": \"" + String(timeStr) + "\"}";
      
      // int httpResponseCode = https.POST(jsonPayload);
      int httpResponseCode = https.POST(data);

      if (httpResponseCode > 0) {
        Serial.printf("Success: %d\n", httpResponseCode);
        Serial.println(https.getString());
      } else {
        Serial.printf("Error: %s\n", https.errorToString(httpResponseCode).c_str());
      }
      delay(5000);
    }
    https.end();
  }

  // delay(2000);
}