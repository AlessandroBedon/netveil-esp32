#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

// ── Config ───────────────────────────────────────────────
const char* ssid       = "_SOFTWARE";
const char* password   = "D@nt3lTsoftw";
const char* SERVER_URL = "http://192.168.4.249:5000/api/update";

#define MAX_DEVICES  200
#define REPORT_MS   5000   // cada 5s envía al Flask
#define CHANNEL_MS  2000   // cada 2s cambia de canal

// ── Estado ───────────────────────────────────────────────
uint8_t mac_list[MAX_DEVICES][6];
int     device_count = 0;
int     deauth_count = 0;
int     canal        = 1;

unsigned long lastReport = 0;
unsigned long lastChange = 0;

// ── Helpers MAC ──────────────────────────────────────────
bool isBroadcastOrMulticast(uint8_t* mac) {
  return (mac[0] & 0x01) || (mac[0] == 0xFF && mac[1] == 0xFF);
}

bool isAllZeros(uint8_t* mac) {
  for (int i = 0; i < 6; i++) if (mac[i] != 0) return false;
  return true;
}

bool macExists(uint8_t* mac) {
  for (int i = 0; i < device_count; i++) {
    if (memcmp(mac_list[i], mac, 6) == 0) return true;
  }
  return false;
}

void addMac(uint8_t* mac) {
  if (device_count >= MAX_DEVICES) return;
  memcpy(mac_list[device_count], mac, 6);
  device_count++;
}

String macToString(uint8_t* mac) {
  char buf[18];
  snprintf(buf, sizeof(buf),
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// ── Sniffer ──────────────────────────────────────────────
void IRAM_ATTR sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t* pkt     = (wifi_promiscuous_pkt_t*)buf;
  uint8_t*                payload = pkt->payload;

  uint8_t* mac = payload + 10;

  if (isAllZeros(mac) || isBroadcastOrMulticast(mac)) return;

  if (!macExists(mac)) addMac(mac);

  // Deauth: 0xC0, Disassoc: 0xA0
  if (payload[0] == 0xC0 || payload[0] == 0xA0) {
    deauth_count++;
  }
}

// ── WiFi reconexión ──────────────────────────────────────
void connectWiFi() {
  esp_wifi_set_promiscuous(false);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.print("[WiFi] Conectando");
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(500); Serial.print("."); tries++;
  }
  if (WiFi.status() == WL_CONNECTED)
    Serial.printf("\n[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());
  else
    Serial.println("\n[WiFi] Sin conexión");
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(canal, WIFI_SECOND_CHAN_NONE);
}

// ── Envío al Flask ───────────────────────────────────────
void sendToFlask() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi(); return;
  }

  esp_wifi_set_promiscuous(false);

  StaticJsonDocument<2048> doc;
  doc["dispositivos"] = device_count;
  doc["intentos"]     = deauth_count;
  doc["canal"]        = canal;

  JsonArray macs = doc.createNestedArray("macs");
  for (int i = 0; i < device_count; i++) macs.add(macToString(mac_list[i]));
  doc.createNestedArray("ips_sospechosas");

  String body;
  serializeJson(doc, body);

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(3000);
  int code = http.POST(body);

  if (code == 200)
    Serial.printf("[Flask] OK — dispositivos=%d deauth=%d canal=%d\n", device_count, deauth_count, canal);
  else
    Serial.printf("[Flask] Error %d: %s\n", code, http.errorToString(code).c_str());

  http.end();

  // Reset
  device_count = 0;
  deauth_count = 0;
  memset(mac_list, 0, sizeof(mac_list));

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(canal, WIFI_SECOND_CHAN_NONE);
}

// ── Setup ────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n[NETVEIL] Iniciando...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.print("[WiFi] Conectando");
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(500); Serial.print("."); tries++;
  }
  if (WiFi.status() == WL_CONNECTED)
    Serial.printf("\n[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());
  else
    Serial.println("\n[WiFi] Sin conexión");

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(canal, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);

  Serial.printf("[Sniffer] Activo en canal %d\n", canal);
  lastReport = millis();
  lastChange = millis();
}

// ── Loop ─────────────────────────────────────────────────
void loop() {
  unsigned long now = millis();

  // Rotar canal cada 2s
  if (now - lastChange >= CHANNEL_MS) {
    lastChange = now;
    canal = (canal % 13) + 1;
    esp_wifi_set_channel(canal, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[CH] %d\n", canal);
  }

  // Reporte al Flask cada 5s
  if (now - lastReport >= REPORT_MS) {
    lastReport = now;
    sendToFlask();
  }

  delay(10);
}
