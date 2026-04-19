#include <Arduino.h>
#include <NetworkClient.h>
#if !defined(CONFIG_IDF_TARGET_ESP32P4)
#include <WiFi.h>
#endif
#include <ETH.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <time.h>
#include <esp_task_wdt.h>
#include <esp_idf_version.h>
#include <esp_system.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>
#include <mbedtls/md.h>

#include "config.h"

#if OTA_ENABLED
#include <HTTPUpdate.h>
#endif

#if MQTT_USE_TLS
#include <WiFiClientSecure.h>
#endif

#define ENABLE_WS_LOG 0
#if ENABLE_WS_LOG
#include <WebSocketsClient.h>
#endif

// ═══════════════════════════════════════════════
//  Device identity
// ═══════════════════════════════════════════════

char deviceId[24];
char deviceMac[18];
char deviceMacNoColon[13];
char deviceQrCode[48];
char topicBootstrapAssign[96];
char mqttUser[48];
char mqttPass[64];
char cmdAuthKey[33];
char bootstrapClaimNonce[17];
bool isProvisioned = false;
unsigned long lastBootstrapRegisterAt = 0;

bool publishRaw(const char *topic, const char *payload, bool retain);

void getMacString() {
  uint8_t mac[6];
  esp_efuse_mac_get_default(mac);
  snprintf(deviceMac, sizeof(deviceMac),
           "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void getMacNoColon(char *out, size_t len) {
  uint8_t mac[6];
  esp_efuse_mac_get_default(mac);
  snprintf(out, len, "%02X%02X%02X%02X%02X%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void macToDeviceId(char *out, size_t len) {
  uint8_t mac[6];
  esp_efuse_mac_get_default(mac);
  snprintf(out, len, "croc-%02X%02X%02X%02X%02X%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Serial priority order:
//   1. NVS key "serial"   — burned at factory flashing time (RECOMMENDED for
//                           production: SN-<16 base32> uploaded to the server's
//                           factory_devices table).
//   2. NVS key "dev_id"   — assigned by a successful bootstrap claim.
//   3. DEVICE_ID_MANUAL   — dev/lab builds with DEVICE_ID_AUTO=0.
//   4. mac-derived fallback "croc-<mac>" — ONLY for pre-factory development.
//
// This means a stolen firmware binary on its own cannot impersonate a real
// device, because its NVS `serial` slot would be empty and the server will
// refuse to admit it into pending_claims (ENFORCE_FACTORY_REGISTRATION=1).
void buildDeviceId() {
  getMacString();
  getMacNoColon(deviceMacNoColon, sizeof(deviceMacNoColon));
#if DEVICE_ID_AUTO
  Preferences p;
  p.begin(NVS_NAMESPACE, true);
  String factorySerial = p.getString("serial", "");
  String assigned = p.getString("dev_id", "");
  p.end();
  if (factorySerial.length() > 0 && factorySerial.length() < sizeof(deviceId)) {
    strlcpy(deviceId, factorySerial.c_str(), sizeof(deviceId));
  } else if (assigned.length() > 0) {
    strlcpy(deviceId, assigned.c_str(), sizeof(deviceId));
  } else {
    macToDeviceId(deviceId, sizeof(deviceId));
  }
#else
  strlcpy(deviceId, DEVICE_ID_MANUAL, sizeof(deviceId));
#endif
}

// ═══════════════════════════════════════════════
//  Wi-Fi multi-AP (WiFiMulti): primary + optional WIFI_SSID_2..4 from config.h
// ═══════════════════════════════════════════════

#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
#include <WiFiMulti.h>

static WiFiMulti g_wifiMulti;
static bool g_wifiMultiApsRegistered = false;
// Count of APs registered into WiFiMulti (NVS remote Wi‑Fi + compile-time slots).
// Used by NETIF_MODE_AUTO so we still call WiFiMulti when only NVS credentials exist.
static uint8_t g_wifiMultiApCount = 0;

static void g_wifiMultiRegisterAps() {
  if (g_wifiMultiApsRegistered) return;
  g_wifiMultiApsRegistered = true;
  g_wifiMultiApCount = 0;
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  {
    Preferences pr;
    if (pr.begin(NVS_NAMESPACE, true)) {
      String rs = pr.getString("wifi_sta_ssid", "");
      String rp = pr.getString("wifi_sta_pass", "");
      pr.end();
      if (rs.length() > 0) {
        g_wifiMulti.addAP(rs.c_str(), rp.c_str());
        g_wifiMultiApCount++;
      }
    }
  }
#endif
  if (strlen(WIFI_SSID) > 0) {
    g_wifiMulti.addAP(WIFI_SSID, WIFI_PASSWORD);
    g_wifiMultiApCount++;
  }
  if (strlen(WIFI_SSID_2) > 0) {
    g_wifiMulti.addAP(WIFI_SSID_2, WIFI_PASSWORD_2);
    g_wifiMultiApCount++;
  }
  if (strlen(WIFI_SSID_3) > 0) {
    g_wifiMulti.addAP(WIFI_SSID_3, WIFI_PASSWORD_3);
    g_wifiMultiApCount++;
  }
  if (strlen(WIFI_SSID_4) > 0) {
    g_wifiMulti.addAP(WIFI_SSID_4, WIFI_PASSWORD_4);
    g_wifiMultiApCount++;
  }
}

// One non-blocking step: register APs, run WiFiMulti for a slice, return true if STA is up.
static bool g_wifiMultiTrySliceJoin() {
  g_wifiMultiRegisterAps();
  if (g_wifiMultiApCount == 0) return false;
  twdtFeedMaybe();
  if (g_wifiMulti.run(WIFI_MULTI_RUN_SLICE_MS) == WL_CONNECTED) return true;
  return WiFi.status() == WL_CONNECTED;
}

// Blocks up to timeoutMs calling WiFiMulti::run in slices (join best registered AP).
static bool g_wifiMultiConnectBlocking(unsigned long timeoutMs) {
  unsigned long t0 = millis();
  while (millis() - t0 < timeoutMs) {
    twdtFeedMaybe();
    if (g_wifiMultiTrySliceJoin()) return true;
  }
  return WiFi.status() == WL_CONNECTED;
}

// Try ESP32 STA reconnect + WiFiMulti slices before wiping credentials with
// disconnect(true). Reduces disconnect storms on marginal RF / DHCP renew.
static bool g_wifiSoftReconnect(unsigned long dwellMs) {
  g_wifiMultiRegisterAps();
  if (g_wifiMultiApCount == 0) return false;
  WiFi.reconnect();
  unsigned long t0 = millis();
  while (millis() - t0 < dwellMs) {
    twdtFeedMaybe();
    if (WiFi.status() == WL_CONNECTED) return true;
    if (g_wifiMultiTrySliceJoin()) return true;
    delay(50);
  }
  return WiFi.status() == WL_CONNECTED;
}
#endif

// ═══════════════════════════════════════════════
//  NetIf abstraction
// ═══════════════════════════════════════════════

class NetIf {
 public:
  virtual ~NetIf() {}
  virtual void begin() = 0;
  virtual bool connected() = 0;
  virtual bool reconnect() = 0;
  virtual String localIP() = 0;
  virtual int rssi() = 0;
  virtual const char *type() = 0;
};

#if NETIF_MODE == NETIF_MODE_WIFI
class WiFiNetIf : public NetIf {
 public:
  void begin() override {
#if defined(CONFIG_IDF_TARGET_ESP32P4)
    // P4 Arduino core has no Wi-Fi radio.
#else
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(false);
    g_wifiMultiConnectBlocking(WIFI_CONNECT_WAIT_MS);
#endif
  }
  bool connected() override { return WiFi.status() == WL_CONNECTED; }
  bool reconnect() override {
#if defined(CONFIG_IDF_TARGET_ESP32P4)
    return false;
#else
    if (connected()) return true;
    if (g_wifiSoftReconnect(3500)) return true;
    WiFi.disconnect(true, true);
    delay(80);
    g_wifiMultiConnectBlocking(WIFI_CONNECT_WAIT_MS);
    return connected();
#endif
  }
  String localIP() override {
    return connected() ? WiFi.localIP().toString() : "0.0.0.0";
  }
  int rssi() override { return connected() ? WiFi.RSSI() : -127; }
  const char *type() override { return "wifi"; }
};
#elif NETIF_MODE == NETIF_MODE_AUTO
// AUTO: bring up both Ethernet and Wi-Fi; prefer whichever is currently linked.
// Link switching is transparent to the MQTT client because the underlying
// socket layer (NetworkClient / WiFiClientSecure) is interface-agnostic.
class AutoNetIf : public NetIf {
 public:
  void begin() override {
  #if BOARD_HAS_ETH
    ETH.begin(ETH_PHY_TYPE, ETH_PHY_ADDR, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_POWER_PIN, ETH_CLK_MODE);
  #endif
  #if !defined(CONFIG_IDF_TARGET_ESP32P4)
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(false);
    g_wifiMultiRegisterAps();
    // Join STA when there is any credential: compile-time and/or remote wifi_config (NVS).
    if (g_wifiMultiApCount > 0) {
      g_wifiMultiConnectBlocking(WIFI_CONNECT_WAIT_MS);
    }
  #endif
  }
  bool connected() override {
  #if BOARD_HAS_ETH
    if (ETH.linkUp()) { _active = "ethernet"; return true; }
  #endif
  #if !defined(CONFIG_IDF_TARGET_ESP32P4)
    if (WiFi.status() == WL_CONNECTED) { _active = "wifi"; return true; }
  #endif
    _active = "none";
    return false;
  }
  bool reconnect() override {
    if (connected()) return true;
  #if BOARD_HAS_ETH
    if (!ETH.linkUp()) {
      ETH.stop();
      delay(50);
      ETH.begin(ETH_PHY_TYPE, ETH_PHY_ADDR, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_POWER_PIN, ETH_CLK_MODE);
    }
  #endif
  #if !defined(CONFIG_IDF_TARGET_ESP32P4)
    if (WiFi.status() != WL_CONNECTED) {
      if (!g_wifiSoftReconnect(3500)) {
        WiFi.disconnect(true, true);
        delay(80);
        g_wifiMultiRegisterAps();
        if (g_wifiMultiApCount > 0) {
          g_wifiMultiConnectBlocking(WIFI_CONNECT_WAIT_MS);
        }
      }
    }
  #endif
    return connected();
  }
  String localIP() override {
  #if BOARD_HAS_ETH
    if (strcmp(_active, "ethernet") == 0) return ETH.localIP().toString();
  #endif
  #if !defined(CONFIG_IDF_TARGET_ESP32P4)
    if (strcmp(_active, "wifi") == 0) return WiFi.localIP().toString();
  #endif
    return String("0.0.0.0");
  }
  int rssi() override {
  #if !defined(CONFIG_IDF_TARGET_ESP32P4)
    if (strcmp(_active, "wifi") == 0) return WiFi.RSSI();
  #endif
    return 0;  // wired link: treat as "perfect" so signal_weak never fires
  }
  const char *type() override { return _active; }
 private:
  const char *_active = "none";
};
#else
class EthernetNetIf : public NetIf {
 public:
  void begin() override {
    ETH.begin(ETH_PHY_TYPE, ETH_PHY_ADDR, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_POWER_PIN, ETH_CLK_MODE);
  }
  bool connected() override { return ETH.linkUp(); }
  bool reconnect() override {
    if (connected()) return true;
    ETH.stop();
    delay(50);
    ETH.begin(ETH_PHY_TYPE, ETH_PHY_ADDR, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_POWER_PIN, ETH_CLK_MODE);
    return false;
  }
  String localIP() override {
    return connected() ? ETH.localIP().toString() : "0.0.0.0";
  }
  int rssi() override { return -127; }
  const char *type() override { return "ethernet"; }
};
#endif

// ═══════════════════════════════════════════════
//  Globals
// ═══════════════════════════════════════════════

#if NETIF_MODE == NETIF_MODE_WIFI
WiFiNetIf wifiIf;
NetIf *netIf = &wifiIf;
#elif NETIF_MODE == NETIF_MODE_AUTO
AutoNetIf autoIf;
NetIf *netIf = &autoIf;
#else
EthernetNetIf ethIf;
NetIf *netIf = &ethIf;
#endif

#if MQTT_USE_TLS
WiFiClientSecure netClient;
#else
#if NETIF_MODE == NETIF_MODE_WIFI
WiFiClient netClient;
#else
NetworkClient netClient;
#endif
#endif
PubSubClient mqttClient(netClient);

#if ENABLE_WS_LOG
WebSocketsClient wsClient;
#endif

Preferences prefs;

struct OfflineMessage {
  char topic[96];
  char payload[1152];
  bool retain;
};

OfflineMessage offlineQueue[OFFLINE_QUEUE_MAX];
size_t offlineHead = 0;
size_t offlineTail = 0;
size_t offlineCount = 0;

char topicHeartbeat[96];
char topicStatus[96];
char topicEvent[96];
char topicCmd[96];
char topicAck[96];

char deviceZone[32];

unsigned long lastHeartbeatAt = 0;
unsigned long lastStatusAt = 0;
unsigned long lastThroughputResetAt = 0;
unsigned long lastWiFiAttemptAt = 0;
unsigned long lastMQTTAttemptAt = 0;
unsigned long wifiBackoffMs = WIFI_RECONNECT_BASE_MS;
unsigned long mqttBackoffMs = MQTT_RECONNECT_BASE_MS;
unsigned long bootAtMs = 0;

unsigned long sirenStartAt = 0;
unsigned long sirenDurationMs = 0;
bool sirenActive = false;
unsigned long lastAlarmAt = 0;

unsigned long lastTriggerReadAt = 0;
bool triggerPrevLevel = true;

char lastError[48] = "none";
bool ntpSynced = false;
unsigned long lastNtpCheckAt = 0;

uint32_t txBytesWindow = 0;
uint32_t rxBytesWindow = 0;
float txBps = 0.0f;
float rxBps = 0.0f;

uint32_t rtHeartbeatMs = HEARTBEAT_INTERVAL_MS;
uint32_t rtStatusMs    = STATUS_INTERVAL_MS;
uint32_t rtSirenMs     = SIREN_ON_MS;
int      rtRssiThresh  = RSSI_WEAK_THRESHOLD;
float    rtVbatThresh   = VBAT_LOW_THRESHOLD;

unsigned long lastNvsSaveAt = 0;
bool nvsDirty = false;

uint32_t bootCount = 0;
const char *resetReasonStr = "unknown";

bool ntpInitDone = false;
bool otaPendingValidation = false;
unsigned long otaPendingSinceMs = 0;
unsigned long scheduledRebootEpoch = 0;
bool scheduledRebootArmed = false;
bool securityConfigValid = true;
#if MQTT_USE_TLS
uint8_t tlsCaSlot = 0;  // 0 primary, 1 secondary
#endif

// ═══════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════

void logLine(const char *msg) {
  Serial.println(msg);
#if ENABLE_WS_LOG
  wsClient.sendTXT(msg);
#endif
}

void logLine(const String &msg) { logLine(msg.c_str()); }

unsigned long epochNow() {
  time_t now;
  time(&now);
  return (now > 1700000000) ? (unsigned long)now : 0;
}

unsigned long tsNow() {
  unsigned long e = epochNow();
  return e ? e : millis();
}

const char *decodeResetReason(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_POWERON:  return "power_on";
    case ESP_RST_EXT:      return "external";
    case ESP_RST_SW:       return "software";
    case ESP_RST_PANIC:    return "panic";
    case ESP_RST_INT_WDT:  return "int_wdt";
    case ESP_RST_TASK_WDT: return "task_wdt";
    case ESP_RST_WDT:      return "wdt";
    case ESP_RST_DEEPSLEEP: return "deep_sleep";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_SDIO:     return "sdio";
    default:               return "unknown";
  }
}

const char *chipTargetName() {
#if defined(CONFIG_IDF_TARGET_ESP32P4)
  return "esp32p4";
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
  return "esp32c6";
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
  return "esp32c3";
#elif defined(CONFIG_IDF_TARGET_ESP32C2)
  return "esp32c2";
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  return "esp32s3";
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
  return "esp32s2";
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
  return "esp32h2";
#else
  return "esp32";
#endif
}

bool secureEquals(const char *a, const char *b) {
  size_t la = strlen(a);
  size_t lb = strlen(b);
  if (la != lb) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < la; i++) diff |= (uint8_t)(a[i] ^ b[i]);
  return diff == 0;
}

bool isHexStr(const char *s, size_t len) {
  if (strlen(s) != len) return false;
  for (size_t i = 0; i < len; i++) {
    char c = s[i];
    bool isHex = ((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'));
    if (!isHex) return false;
  }
  return true;
}

bool containsInsecureMarker(const char *s) {
  if (strstr(s, "CHANGE_ME")) return true;
  if (strstr(s, "YOUR_")) return true;
  if (strstr(s, "your.vps.domain")) return true;
  return false;
}

bool isValidHexKey16(const char *s) {
  return isHexStr(s, 16);
}

#if MQTT_USE_TLS
bool hasPrimaryCa() {
  return strlen(MQTT_CA_CERT_PRIMARY_PEM) >= 64;
}

bool hasSecondaryCa() {
  return strlen(MQTT_CA_CERT_SECONDARY_PEM) >= 64;
}

bool applyTlsCaSlot(uint8_t slot) {
  const char *pem = (slot == 0) ? MQTT_CA_CERT_PRIMARY_PEM : MQTT_CA_CERT_SECONDARY_PEM;
  if (strlen(pem) < 64) return false;
  netClient.setCACert(pem);
  tlsCaSlot = slot;
  return true;
}
#endif

bool validateProductionSecurityConfig() {
#if PROD_ENFORCE
  if (!isValidHexKey16(CMD_AUTH_KEY)) return false;
  if (containsInsecureMarker(CMD_AUTH_KEY)) return false;
  if (strlen(BOOTSTRAP_BIND_KEY) < 16) return false;
  if (containsInsecureMarker(BOOTSTRAP_BIND_KEY)) return false;
  if (strlen(OTA_TOKEN) < 16) return false;
  if (containsInsecureMarker(OTA_TOKEN)) return false;
  if (strlen(MQTT_USERNAME) < 4 || strlen(MQTT_PASSWORD) < 12) return false;
  if (containsInsecureMarker(MQTT_USERNAME) || containsInsecureMarker(MQTT_PASSWORD)) return false;
  if (strlen(BOOTSTRAP_MQTT_USERNAME) < 4 || strlen(BOOTSTRAP_MQTT_PASSWORD) < 12) return false;
  if (containsInsecureMarker(BOOTSTRAP_MQTT_USERNAME) || containsInsecureMarker(BOOTSTRAP_MQTT_PASSWORD)) return false;
  if (containsInsecureMarker(OTA_ALLOWED_HOST)) return false;
#if MQTT_USE_TLS
  if (!hasPrimaryCa()) return false;
#else
  return false;
#endif
#endif
  return true;
}

String stripQuery(const char *url) {
  String s(url);
  int q = s.indexOf('?');
  return (q >= 0) ? s.substring(0, q) : s;
}

bool isAllowedOtaUrl(const char *url) {
  String u(url);
  if (!(u.startsWith("http://") || u.startsWith("https://"))) return false;
  if (strlen(OTA_ALLOWED_HOST) == 0) return true;

  String hostHttp  = String("http://") + OTA_ALLOWED_HOST + "/";
  String hostHttps = String("https://") + OTA_ALLOWED_HOST + "/";
  return u.startsWith(hostHttp) || u.startsWith(hostHttps);
}

void generateBootstrapNonce() {
  uint32_t a = esp_random();
  uint32_t b = esp_random();
  snprintf(bootstrapClaimNonce, sizeof(bootstrapClaimNonce), "%08lX%08lX",
           (unsigned long)a, (unsigned long)b);
}

void applyDefaultQrCode() {
  snprintf(deviceQrCode, sizeof(deviceQrCode), "%s-%s", QR_DEFAULT_PREFIX, deviceMacNoColon);
}

void loadProvisioningRuntime() {
  prefs.begin(NVS_NAMESPACE, true);
  isProvisioned = prefs.getBool("prov", false);

  String q = prefs.getString("qr_code", "");
  if (q.length() > 0 && q.length() < sizeof(deviceQrCode)) {
    strlcpy(deviceQrCode, q.c_str(), sizeof(deviceQrCode));
  } else {
    applyDefaultQrCode();
  }

  String user = prefs.getString("mqtt_u", "");
  String pass = prefs.getString("mqtt_p", "");
  String key = prefs.getString("cmd_key", "");
  prefs.end();

  if (isProvisioned && user.length() > 0 && pass.length() > 0) {
    strlcpy(mqttUser, user.c_str(), sizeof(mqttUser));
    strlcpy(mqttPass, pass.c_str(), sizeof(mqttPass));
  } else {
    strlcpy(mqttUser, BOOTSTRAP_MQTT_USERNAME, sizeof(mqttUser));
    strlcpy(mqttPass, BOOTSTRAP_MQTT_PASSWORD, sizeof(mqttPass));
  }

  if (isProvisioned && isHexStr(key.c_str(), 16)) {
    strlcpy(cmdAuthKey, key.c_str(), sizeof(cmdAuthKey));
  } else {
    strlcpy(cmdAuthKey, CMD_AUTH_KEY, sizeof(cmdAuthKey));
  }
}

bool saveProvisioningFromClaim(JsonVariant doc) {
  const char *macHex = doc["mac_nocolon"] | "";
  const char *nonce = doc["claim_nonce"] | "";
  const char *bindKey = doc["bind_key"] | "";
  const char *newId = doc["device_id"] | "";
  const char *newZone = doc["zone"] | "";
  const char *newQr = doc["qr_code"] | "";
  const char *newUser = doc["mqtt_username"] | "";
  const char *newPass = doc["mqtt_password"] | "";
  const char *newCmdKey = doc["cmd_key"] | "";

  if (!secureEquals(bindKey, BOOTSTRAP_BIND_KEY)) return false;
  if (!secureEquals(macHex, deviceMacNoColon)) return false;
  if (!secureEquals(nonce, bootstrapClaimNonce)) return false;
  if (strlen(newId) == 0 || strlen(newId) >= sizeof(deviceId)) return false;
  if (strlen(newUser) == 0 || strlen(newUser) >= sizeof(mqttUser)) return false;
  if (strlen(newPass) == 0 || strlen(newPass) >= sizeof(mqttPass)) return false;
  if (!isHexStr(newCmdKey, 16)) return false;
  if (strlen(newZone) >= sizeof(deviceZone)) return false;
  if (strlen(newQr) >= sizeof(deviceQrCode)) return false;

  prefs.begin(NVS_NAMESPACE, false);
  prefs.putBool("prov", true);
  prefs.putString("dev_id", newId);
  prefs.putString("mqtt_u", newUser);
  prefs.putString("mqtt_p", newPass);
  prefs.putString("cmd_key", newCmdKey);
  if (strlen(newZone) > 0) prefs.putString("zone", newZone);
  if (strlen(newQr) > 0) prefs.putString("qr_code", newQr);
  prefs.end();
  return true;
}

void publishBootstrapRegister() {
  StaticJsonDocument<384> doc;
  doc["type"] = "bootstrap.register";
  doc["device_id"] = deviceId;
  // Explicit serial (mirrors device_id when factory-burned). Server uses this
  // to cross-check against factory_devices so a rogue MAC can't masquerade.
  doc["serial"] = deviceId;
  doc["mac"] = deviceMac;
  doc["mac_nocolon"] = deviceMacNoColon;
  doc["qr_code"] = deviceQrCode;
  doc["fw"] = FW_VERSION;
  doc["chip_target"] = chipTargetName();
  doc["board_profile"] = BOARD_PROFILE_NAME;
  doc["claim_nonce"] = bootstrapClaimNonce;
  doc["ts"] = tsNow();

  char buf[384];
  serializeJson(doc, buf, sizeof(buf));
  publishRaw(TOPIC_BOOTSTRAP_REGISTER, buf, false);
}

void buildAlarmSignature(const char *sourceId, const char *sourceZone, unsigned long ts,
                         uint32_t nonce, char *outHex, size_t outHexLen) {
  if (outHexLen < 17) {
    if (outHexLen > 0) outHex[0] = '\0';
    return;
  }

  char msg[192];
  snprintf(msg, sizeof(msg), "alarm|%s|%s|%lu|%lu", sourceId, sourceZone, ts, (unsigned long)nonce);

  unsigned char digest[32];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) {
    outHex[0] = '\0';
    return;
  }
  mbedtls_md_hmac(md, (const unsigned char *)cmdAuthKey, strlen(cmdAuthKey),
                  (const unsigned char *)msg, strlen(msg), digest);

  for (int i = 0; i < 8; i++) {
    snprintf(outHex + i * 2, outHexLen - (i * 2), "%02x", digest[i]);
  }
  outHex[16] = '\0';
}

// ═══════════════════════════════════════════════
//  NVS persistent parameters (write-wear protected)
// ═══════════════════════════════════════════════

void loadParams() {
  prefs.begin(NVS_NAMESPACE, true);
  rtHeartbeatMs = prefs.getUInt("hb_ms",   HEARTBEAT_INTERVAL_MS);
  rtStatusMs    = prefs.getUInt("st_ms",   STATUS_INTERVAL_MS);
  rtSirenMs     = prefs.getUInt("sir_ms",  SIREN_ON_MS);
  rtRssiThresh  = prefs.getInt("rssi_t",   RSSI_WEAK_THRESHOLD);
  rtVbatThresh  = prefs.getFloat("vbat_t", VBAT_LOW_THRESHOLD);
  strlcpy(deviceZone,
          prefs.getString("zone", DEVICE_ZONE).c_str(),
          sizeof(deviceZone));
  bootCount = prefs.getUInt("boot_cnt", 0);
  prefs.end();

  bootCount++;
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putUInt("boot_cnt", bootCount);
  prefs.end();
}

void persistScheduledRebootIfNeeded() {
  prefs.begin(NVS_NAMESPACE, false);
  if (scheduledRebootArmed && scheduledRebootEpoch > 1700000000UL) {
    prefs.putBool("rb_arm", true);
    prefs.putUInt("rb_ep", scheduledRebootEpoch);
  } else {
    prefs.putBool("rb_arm", false);
    prefs.remove("rb_ep");
  }
  prefs.end();
}

void loadScheduledRebootState() {
  prefs.begin(NVS_NAMESPACE, true);
  bool armed = prefs.getBool("rb_arm", false);
  unsigned long epoch = prefs.getUInt("rb_ep", 0);
  prefs.end();

  // NVS may hold a "deadline" saved as millis() from an old pre-NTP delay_s — clear it.
  if (armed && epoch > 0 && epoch < 1700000000UL) {
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    logLine("[sched] cleared bogus reboot epoch (was pre-ntp millis; resched after NTP)");
    return;
  }

  unsigned long nowEpoch = epochNow();
  if (armed && epoch > 1700000000UL && nowEpoch > 1700000000UL && epoch > nowEpoch) {
    scheduledRebootArmed = true;
    scheduledRebootEpoch = epoch;
    {
      char _sl[80];
      snprintf(_sl, sizeof(_sl), "[sched] restored reboot at epoch=%lu",
               (unsigned long)scheduledRebootEpoch);
      logLine(_sl);
    }
  } else {
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
  }
}

void requestRestartWithAck(const char *cmd, const char *detail) {
  publishAck(cmd, true, detail);
  flushNvsIfNeeded();
  delay(150);
  ESP.restart();
}

void setOtaPendingState(const char *targetFw, const char *campaignId) {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putBool("ota_pend", true);
  prefs.putUInt("ota_fail", 0);
  prefs.putString("ota_tgt", targetFw);
  prefs.putString("ota_cid", campaignId ? campaignId : "");
  prefs.end();
}

void clearOtaPendingState() {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putBool("ota_pend", false);
  prefs.putUInt("ota_fail", 0);
  prefs.remove("ota_tgt");
  prefs.remove("ota_cid");
  prefs.end();
}

void processOtaBootState() {
  prefs.begin(NVS_NAMESPACE, false);
  bool pending = prefs.getBool("ota_pend", false);
  if (!pending) {
    prefs.end();
    return;
  }

  uint32_t fails = prefs.getUInt("ota_fail", 0) + 1;
  prefs.putUInt("ota_fail", fails);
  String target = prefs.getString("ota_tgt", "");
  prefs.end();

  {
    char _ol[160];
    snprintf(_ol, sizeof(_ol), "[ota] pending validation fw=%s boot_try=%lu",
             target.c_str(), (unsigned long)fails);
    logLine(_ol);
  }

  if (fails >= OTA_MAX_BOOT_FAILS) {
    logLine("[ota] rollback threshold reached");
    esp_ota_mark_app_invalid_rollback_and_reboot();
    return;
  }

  otaPendingValidation = true;
  otaPendingSinceMs = millis();
}

void confirmOtaIfHealthy() {
  if (!otaPendingValidation) return;
  if (millis() - otaPendingSinceMs < OTA_HEALTH_CONFIRM_MS) return;

  esp_err_t rc = esp_ota_mark_app_valid_cancel_rollback();
  if (rc != ESP_OK && rc != ESP_ERR_NOT_FOUND) {
    strlcpy(lastError, "ota_valid_fail", sizeof(lastError));
    {
      char _vl[64];
      snprintf(_vl, sizeof(_vl), "[ota] validate failed rc=%d", (int)rc);
      logLine(_vl);
    }
    return;
  }

  // Read campaign id BEFORE we wipe the pending state so we can tell the
  // server which rollout this success belongs to.
  prefs.begin(NVS_NAMESPACE, true);
  String cid = prefs.getString("ota_cid", "");
  String tgt = prefs.getString("ota_tgt", "");
  prefs.end();

  clearOtaPendingState();
  otaPendingValidation = false;
  logLine("[ota] validated");
  publishOtaResult(cid.c_str(), tgt.c_str(), true, "post-reboot validated");
  publishHeartbeatEvent("ota_success");
}

void commitNvsSave() {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putUInt("hb_ms",   rtHeartbeatMs);
  prefs.putUInt("st_ms",   rtStatusMs);
  prefs.putUInt("sir_ms",  rtSirenMs);
  prefs.putInt("rssi_t",   rtRssiThresh);
  prefs.putFloat("vbat_t", rtVbatThresh);
  prefs.putString("zone",  deviceZone);
  prefs.end();
  nvsDirty = false;
  lastNvsSaveAt = millis();
  logLine("[nvs] saved");
}

void markNvsDirty() {
  nvsDirty = true;
}

void flushNvsIfNeeded() {
  if (!nvsDirty) return;
  if (millis() - lastNvsSaveAt < NVS_SAVE_COOLDOWN_MS) return;
  commitNvsSave();
}

// ═══════════════════════════════════════════════
//  Offline queue
// ═══════════════════════════════════════════════

void enqueueOffline(const char *topic, const char *payload, bool retain) {
  if (strlen(topic) >= sizeof(offlineQueue[0].topic) ||
      strlen(payload) >= sizeof(offlineQueue[0].payload)) {
    strlcpy(lastError, "offline_oversize", sizeof(lastError));
    return;
  }
  if (offlineCount >= OFFLINE_QUEUE_MAX) {
    logLine("[offline] queue full; dropping oldest message");
    offlineHead = (offlineHead + 1) % OFFLINE_QUEUE_MAX;
    offlineCount--;
  }
  OfflineMessage &slot = offlineQueue[offlineTail];
  strlcpy(slot.topic, topic, sizeof(slot.topic));
  strlcpy(slot.payload, payload, sizeof(slot.payload));
  slot.retain = retain;
  offlineTail = (offlineTail + 1) % OFFLINE_QUEUE_MAX;
  offlineCount++;
}

bool publishRaw(const char *topic, const char *payload, bool retain = false) {
  if (!mqttClient.connected()) {
    enqueueOffline(topic, payload, retain);
    return false;
  }
  bool ok = mqttClient.publish(topic, payload, retain);
  if (ok) {
    txBytesWindow += strlen(payload);
  } else {
    strlcpy(lastError, "mqtt_pub_fail", sizeof(lastError));
    enqueueOffline(topic, payload, retain);
  }
  return ok;
}

void flushOfflineQueue() {
  if (offlineCount == 0) return;
  unsigned int flushed = 0;
  while (mqttClient.connected() && offlineCount > 0 && flushed < 3) {
    OfflineMessage &m = offlineQueue[offlineHead];
    if (!mqttClient.publish(m.topic, m.payload, m.retain)) {
      strlcpy(lastError, "flush_fail", sizeof(lastError));
      return;
    }
    txBytesWindow += strlen(m.payload);
    offlineHead = (offlineHead + 1) % OFFLINE_QUEUE_MAX;
    offlineCount--;
    flushed++;
  }
}

// ═══════════════════════════════════════════════
//  Sensors
// ═══════════════════════════════════════════════

float readBatteryVoltage() {
#if VBAT_SENSOR_ENABLED
  uint32_t sum = 0;
  for (int i = 0; i < ADC_OVERSAMPLE; i++) sum += analogRead(VBAT_ADC_PIN);
  float avg = (float)sum / ADC_OVERSAMPLE;
  return (avg / ADC_MAX) * ADC_VREF * VBAT_DIVIDER_RATIO;
#else
  return -1.0f;
#endif
}

const char *resolvePowerState(float vbat) {
#if VBAT_SENSOR_ENABLED
  return (vbat < rtVbatThresh) ? "power_low" : "normal";
#else
  (void)vbat;
  return "unsupported";
#endif
}

const char *resolveDisconnectReason(float vbat, int rssi) {
#if VBAT_SENSOR_ENABLED
  if (vbat < rtVbatThresh)  return "power_low";
#else
  (void)vbat;
#endif
  if (!netIf->connected())  return "network_lost";
  if (rssi < rtRssiThresh)  return "signal_weak";
  return "none";
}

// ═══════════════════════════════════════════════
//  Siren
// ═══════════════════════════════════════════════

void activateSiren(uint32_t durationMs) {
  bool wasActive = sirenActive;
  digitalWrite(SIREN_GPIO, HIGH);
  sirenActive = true;
  sirenStartAt = millis();
  sirenDurationMs = durationMs;
  {
    char line[96];
    snprintf(line, sizeof(line), "[siren] on gpio=%d dur_ms=%lu",
             SIREN_GPIO, (unsigned long)durationMs);
    logLine(line);
  }
  if (!wasActive) publishHeartbeatEvent("siren_on");
}

void deactivateSiren() {
  bool wasActive = sirenActive;
  digitalWrite(SIREN_GPIO, LOW);
  sirenActive = false;
  sirenDurationMs = 0;
  if (wasActive) publishHeartbeatEvent("siren_off");
}

bool sirenExpired() {
  return sirenActive && (millis() - sirenStartAt >= sirenDurationMs);
}

bool alarmInCooldown() {
  return (millis() - lastAlarmAt) < ALARM_COOLDOWN_MS;
}

// ═══════════════════════════════════════════════
//  MQTT publishing
// ═══════════════════════════════════════════════

void publishAck(const char *cmd, bool ok, const char *detail) {
  StaticJsonDocument<256> doc;
  doc["device_id"] = deviceId;
  doc["cmd"]       = cmd;
  doc["ok"]        = ok;
  doc["detail"]    = detail;
  doc["ts"]        = tsNow();

  char buf[256];
  serializeJson(doc, buf, sizeof(buf));
  publishRaw(topicAck, buf, false);
}

// Dedicated OTA result event. Carries campaign_id + target fw so the API can
// drive the campaign state machine and know whether a rollback is needed.
void publishOtaResult(const char *campaignId,
                      const char *targetFw,
                      bool ok,
                      const char *detail) {
  StaticJsonDocument<384> doc;
  doc["type"]        = "ota.result";
  doc["device_id"]   = deviceId;
  doc["campaign_id"] = campaignId ? campaignId : "";
  doc["target_fw"]   = targetFw   ? targetFw   : "";
  doc["current_fw"]  = FW_VERSION;
  doc["ok"]          = ok;
  doc["detail"]      = detail ? detail : "";
  doc["ts"]          = tsNow();

  char buf[384];
  serializeJson(doc, buf, sizeof(buf));
  publishRaw(topicAck, buf, false);
}

// Emit heartbeat ONLY if enough time has elapsed since the last one. This is
// the throttled entrypoint that event sites (alarm, siren, reconnect, OTA
// finish, boot) should call — it keeps EVENT-mode fleets from melting the
// broker if a noisy GPIO starts flapping.
void publishHeartbeatEvent(const char *reason) {
  unsigned long now = millis();
  if (lastHeartbeatAt != 0 && now - lastHeartbeatAt < HEARTBEAT_MIN_INTERVAL_MS) {
    return;
  }
  lastHeartbeatAt = now;
  (void)reason;  // reserved for future tagged telemetry
  publishHeartbeat();
}

void publishHeartbeat() {
  StaticJsonDocument<640> doc;
  doc["device_id"]     = deviceId;
  doc["mac"]           = deviceMac;
  doc["qr_code"]       = deviceQrCode;
  doc["fw"]            = FW_VERSION;
  doc["chip_target"]   = chipTargetName();
  doc["board_profile"] = BOARD_PROFILE_NAME;
  doc["sdk"]           = ESP.getSdkVersion();
#if MQTT_USE_TLS
  doc["tls_ca_slot"]   = tlsCaSlot;
#endif
  doc["zone"]          = deviceZone;
  doc["provisioned"]   = isProvisioned;
  doc["online"]        = true;
  doc["uptime_s"]      = (millis() - bootAtMs) / 1000UL;
  doc["free_heap"]     = ESP.getFreeHeap();
  doc["min_free_heap"] = ESP.getMinFreeHeap();
  doc["ntp_synced"]    = ntpSynced;
  doc["boot_count"]    = bootCount;
  doc["reset_reason"]  = resetReasonStr;
  doc["ts"]            = tsNow();

  char buf[640];
  serializeJson(doc, buf, sizeof(buf));
  publishRaw(topicHeartbeat, buf, false);
}

void publishStatus() {
  float vbat = readBatteryVoltage();
  int   rssi = netIf->rssi();

  StaticJsonDocument<1024> doc;
  doc["device_id"]          = deviceId;
  doc["mac"]                = deviceMac;
  doc["qr_code"]            = deviceQrCode;
  doc["fw"]                 = FW_VERSION;
  doc["chip_target"]        = chipTargetName();
  doc["board_profile"]      = BOARD_PROFILE_NAME;
  doc["sdk"]                = ESP.getSdkVersion();
#if MQTT_USE_TLS
  doc["tls_ca_slot"]        = tlsCaSlot;
#endif
  doc["zone"]               = deviceZone;
  doc["provisioned"]        = isProvisioned;
  doc["ts"]                 = tsNow();
  doc["online"]             = mqttClient.connected();
  doc["uptime_s"]           = (millis() - bootAtMs) / 1000UL;
  doc["free_heap"]          = ESP.getFreeHeap();
  doc["min_free_heap"]      = ESP.getMinFreeHeap();
  doc["ntp_synced"]         = ntpSynced;
  doc["boot_count"]         = bootCount;
  doc["reset_reason"]       = resetReasonStr;
  doc["net_type"]           = netIf->type();
#if !defined(CONFIG_IDF_TARGET_ESP32P4)
  if (strcmp(netIf->type(), "wifi") == 0) {
    if (WiFi.status() == WL_CONNECTED) {
      doc["wifi_ssid"] = WiFi.SSID();
      doc["wifi_channel"] = WiFi.channel();
    } else {
      doc["wifi_ssid"] = "";
      doc["wifi_channel"] = 0;
    }
  }
#endif
  doc["ip"]                 = netIf->localIP();
  doc["rssi"]               = rssi;
  doc["vbat"]               = vbat;
  doc["power_state"]        = resolvePowerState(vbat);
  doc["disconnect_reason"]  = resolveDisconnectReason(vbat, rssi);
  doc["tx_bps"]             = txBps;
  doc["rx_bps"]             = rxBps;
  doc["offline_queue"]      = (int)offlineCount;
  doc["siren_active"]       = sirenActive;
  doc["scheduled_reboot"]   = scheduledRebootArmed;
  doc["scheduled_reboot_ts"]= scheduledRebootEpoch;
  doc["last_error"]         = lastError;

  char buf[1024];
  serializeJson(doc, buf, sizeof(buf));
  publishRaw(topicStatus, buf, true);
}

void publishAlarmEvent(bool localTrigger) {
  // NOTE: server-side fan-out model.
  // Device publishes the alarm only on its own /event topic. The API verifies
  // ownership (owner_admin) and dispatches siren_on commands to all sibling
  // devices in the same tenant. This guarantees strict cross-admin isolation
  // that no shared MQTT credential setup could provide.
  StaticJsonDocument<320> doc;
  doc["type"]           = "alarm.trigger";
  doc["source_id"]      = deviceId;
  doc["source_zone"]    = deviceZone;
  doc["local_trigger"]  = localTrigger;
  doc["trigger_kind"]   = localTrigger ? "remote_button" : "network";
  unsigned long nowTs   = tsNow();
  uint32_t nonce        = esp_random();
  char sig[17];
  buildAlarmSignature(deviceId, deviceZone, nowTs, nonce, sig, sizeof(sig));
  doc["ts"]             = nowTs;
  doc["nonce"]          = nonce;
  doc["sig"]            = sig;

  char buf[320];
  size_t w = serializeJson(doc, buf, sizeof(buf));
  if (w == 0 || w >= sizeof(buf)) {
    logLine("[trigger] ERROR: alarm JSON serialize truncated; not sent");
    return;
  }
  if (!publishRaw(topicEvent, buf, false)) {
    logLine("[trigger] alarm.trigger queued (MQTT offline or publish failed)");
  }
  lastAlarmAt = millis();
}

// ═══════════════════════════════════════════════
//  OTA (WDT-safe)
// ═══════════════════════════════════════════════

#if OTA_ENABLED
void performOTA(const char *url, const char *targetFw, const char *campaignId) {
  {
    String uq = stripQuery(url);
    char _of[192];
    snprintf(_of, sizeof(_of), "[ota] from: %s", uq.c_str());
    logLine(_of);
  }
  publishAck("ota", true, "ota starting");
  publishHeartbeatEvent("ota_start");

  setOtaPendingState(targetFw, campaignId);
  esp_task_wdt_delete(NULL);

  NetworkClient otaClient;
  httpUpdate.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  t_httpUpdate_return ret = httpUpdate.update(otaClient, url);

  esp_task_wdt_add(NULL);

  switch (ret) {
    case HTTP_UPDATE_FAILED: {
      String err = httpUpdate.getLastErrorString();
      {
        char _fe[256];
        snprintf(_fe, sizeof(_fe), "[ota] FAILED: %s", err.c_str());
        logLine(_fe);
      }
      publishAck("ota", false, err.c_str());
      publishOtaResult(campaignId, targetFw, false, err.c_str());
      clearOtaPendingState();
      break;
    }
    case HTTP_UPDATE_NO_UPDATES:
      clearOtaPendingState();
      publishAck("ota", false, "no update");
      publishOtaResult(campaignId, targetFw, false, "no update");
      break;
    case HTTP_UPDATE_OK:
      // Success is announced after reboot by confirmOtaIfHealthy().
      break;
  }
}
#endif

// ═══════════════════════════════════════════════
//  Parameter validation
// ═══════════════════════════════════════════════

template<typename T>
T clampParam(T val, T lo, T hi) { return (val < lo) ? lo : (val > hi) ? hi : val; }

// ═══════════════════════════════════════════════
//  Command execution
// ═══════════════════════════════════════════════

void executeCommand(const char *cmd, JsonVariant params) {
  const char *resolvedCmd = cmd;
  if (strcmp(cmd, "set_params") == 0) resolvedCmd = "set_param";
  if (strcmp(cmd, "info") == 0) resolvedCmd = "get_info";
  if (strcmp(cmd, "reboot_now") == 0) resolvedCmd = "reboot";
  if (strcmp(cmd, "ota_update") == 0) resolvedCmd = "ota";
  if (strcmp(cmd, "red_alert") == 0) resolvedCmd = "siren_on";
  if (strcmp(cmd, "cancel_alert") == 0) resolvedCmd = "siren_off";
  if (strcmp(cmd, "self_check") == 0) resolvedCmd = "self_test";

  if (strcmp(resolvedCmd, "siren_on") == 0) {
    uint32_t dur = params["duration_ms"] | rtSirenMs;
    dur = clampParam(dur, (uint32_t)PARAM_SIREN_MIN_MS, (uint32_t)PARAM_SIREN_MAX_MS);
    activateSiren(dur);
    publishAck(resolvedCmd, true, "siren on");
    return;
  }

  if (strcmp(resolvedCmd, "siren_off") == 0) {
    deactivateSiren();
    publishAck(resolvedCmd, true, "siren off");
    return;
  }

  if (strcmp(resolvedCmd, "reboot") == 0) {
    requestRestartWithAck(resolvedCmd, "rebooting");
    return;
  }

  if (strcmp(resolvedCmd, "self_test") == 0) {
    float vbat = readBatteryVoltage();
    bool netOk = netIf->connected();
    bool mqttOk = mqttClient.connected();
    bool heapOk = ESP.getFreeHeap() > 10000;
    bool overallOk = netOk && mqttOk && heapOk;
    publishStatus();
    char detail[160];
    snprintf(detail, sizeof(detail), "self_test %s net=%d mqtt=%d heap=%d vbat=%.2f",
             overallOk ? "ok" : "fail", netOk ? 1 : 0, mqttOk ? 1 : 0, heapOk ? 1 : 0, vbat);
    publishAck(resolvedCmd, overallOk, detail);
    return;
  }

  if (strcmp(resolvedCmd, "set_param") == 0) {
    if (params.containsKey("heartbeat_ms"))
      rtHeartbeatMs = clampParam(params["heartbeat_ms"].as<uint32_t>(),
                                 (uint32_t)PARAM_HB_MIN_MS, (uint32_t)PARAM_HB_MAX_MS);
    if (params.containsKey("status_ms"))
      rtStatusMs = clampParam(params["status_ms"].as<uint32_t>(),
                              (uint32_t)PARAM_ST_MIN_MS, (uint32_t)PARAM_ST_MAX_MS);
    if (params.containsKey("siren_ms"))
      rtSirenMs = clampParam(params["siren_ms"].as<uint32_t>(),
                             (uint32_t)PARAM_SIREN_MIN_MS, (uint32_t)PARAM_SIREN_MAX_MS);
    if (params.containsKey("rssi_threshold"))
      rtRssiThresh = clampParam(params["rssi_threshold"].as<int>(),
                                (int)PARAM_RSSI_MIN, (int)PARAM_RSSI_MAX);
    if (params.containsKey("vbat_threshold"))
      rtVbatThresh = clampParam(params["vbat_threshold"].as<float>(),
                                (float)PARAM_VBAT_MIN, (float)PARAM_VBAT_MAX);
    if (params.containsKey("zone")) {
      const char *z = params["zone"] | "";
      if (strlen(z) > 0 && strlen(z) < sizeof(deviceZone))
        strlcpy(deviceZone, z, sizeof(deviceZone));
    }

    markNvsDirty();
    publishAck(resolvedCmd, true, "params set (pending save)");
    return;
  }

  if (strcmp(resolvedCmd, "set_qr") == 0) {
    const char *qr = params["qr_code"] | "";
    if (strlen(qr) == 0 || strlen(qr) >= sizeof(deviceQrCode)) {
      publishAck(resolvedCmd, false, "invalid qr_code");
      return;
    }
    prefs.begin(NVS_NAMESPACE, false);
    prefs.putString("qr_code", qr);
    prefs.end();
    strlcpy(deviceQrCode, qr, sizeof(deviceQrCode));
    publishAck(resolvedCmd, true, "qr updated");
    return;
  }

  if (strcmp(resolvedCmd, "schedule_reboot") == 0) {
    uint32_t delayS = params["delay_s"] | 0;
    unsigned long atTs = params["at_ts"] | 0;
    unsigned long nowTs = tsNow();
    // delay_s must use real Unix time; before NTP, tsNow() is millis() and would
    // store a bogus "epoch" that fires immediately after NTP sync (SW_CPU_RESET loop).
    if (delayS > 0) {
      if (epochNow() <= 1700000000UL) {
        publishAck(resolvedCmd, false, "ntp not synced; wait for NTP then use delay_s or use at_ts");
        return;
      }
      scheduledRebootEpoch = nowTs + delayS;
      scheduledRebootArmed = true;
      persistScheduledRebootIfNeeded();
      publishAck(resolvedCmd, true, "scheduled by delay_s");
      return;
    }
    if (epochNow() > 1700000000UL && atTs > nowTs + 5) {
      scheduledRebootEpoch = atTs;
      scheduledRebootArmed = true;
      persistScheduledRebootIfNeeded();
      publishAck(resolvedCmd, true, "scheduled by at_ts");
      return;
    }
    publishAck(resolvedCmd, false, "invalid schedule or ntp not synced");
    return;
  }

  if (strcmp(resolvedCmd, "cancel_scheduled_reboot") == 0) {
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    publishAck(resolvedCmd, true, "schedule cancelled");
    return;
  }

  if (strcmp(resolvedCmd, "assign_id") == 0) {
    const char *newId = params["new_id"] | "";
    if (strlen(newId) == 0 || strlen(newId) >= sizeof(deviceId)) {
      publishAck(resolvedCmd, false, "invalid new_id");
      return;
    }
    prefs.begin(NVS_NAMESPACE, false);
    prefs.putString("dev_id", newId);
    prefs.end();
    {
      char _il[96];
      snprintf(_il, sizeof(_il), "[id] assigned: %s", newId);
      logLine(_il);
    }
    requestRestartWithAck(resolvedCmd, newId);
    return;
  }

  if (strcmp(resolvedCmd, "reset_id") == 0) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("dev_id");
    prefs.end();
    requestRestartWithAck(resolvedCmd, "id reset to MAC");
    return;
  }

  if (strcmp(resolvedCmd, "factory_reset") == 0) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.clear();
    prefs.end();
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    requestRestartWithAck(resolvedCmd, "factory reset");
    return;
  }

#if OTA_ENABLED
  if (strcmp(resolvedCmd, "ota") == 0) {
    const char *url = params["url"] | "";
    if (strlen(url) == 0) {
      publishAck(resolvedCmd, false, "missing url");
      return;
    }
    if (!isAllowedOtaUrl(url)) {
      publishAck(resolvedCmd, false, "bad host or scheme");
      return;
    }
    char fullUrl[256];
    if (strchr(url, '?')) {
      snprintf(fullUrl, sizeof(fullUrl), "%s&token=%s", url, OTA_TOKEN);
    } else {
      snprintf(fullUrl, sizeof(fullUrl), "%s?token=%s", url, OTA_TOKEN);
    }
    const char *targetFw    = params["fw"] | "unknown";
    const char *campaignId  = params["campaign_id"] | "";
    performOTA(fullUrl, targetFw, campaignId);
    return;
  }
#endif

#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  if (strcmp(resolvedCmd, "wifi_config") == 0) {
    const char *ssid = params["ssid"] | "";
    const char *pass = params["password"] | "";
    size_t sl = strlen(ssid);
    if (sl == 0 || sl > 32) {
      publishAck(resolvedCmd, false, "invalid ssid");
      return;
    }
    if (strlen(pass) > 64) {
      publishAck(resolvedCmd, false, "password too long");
      return;
    }
    prefs.begin(NVS_NAMESPACE, false);
    prefs.putString("wifi_sta_ssid", ssid);
    prefs.putString("wifi_sta_pass", pass);
    prefs.end();
    if (mqttClient.connected()) {
      mqttClient.disconnect();
      delay(50);
    }
    requestRestartWithAck(resolvedCmd, "wifi_config saved");
    return;
  }

  if (strcmp(resolvedCmd, "wifi_clear") == 0) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("wifi_sta_ssid");
    prefs.remove("wifi_sta_pass");
    prefs.end();
    if (mqttClient.connected()) {
      mqttClient.disconnect();
      delay(50);
    }
    requestRestartWithAck(resolvedCmd, "wifi_cleared");
    return;
  }
#endif

  if (strcmp(resolvedCmd, "get_info") == 0) {
    publishStatus();
    publishAck(resolvedCmd, true, "status published");
    return;
  }

  if (strcmp(resolvedCmd, "get_cmd_table") == 0) {
    publishCommandTable();
    publishAck(resolvedCmd, true, "command table published");
    return;
  }

  // Server-initiated liveness probe. Triggered automatically by the API when
  // a device has been silent for ~12h; in EVENT mode the device otherwise
  // never emits a heartbeat. Reply with a heartbeat + status snapshot so the
  // server can re-sync presence/throughput/vbat/etc in a single round-trip.
  if (strcmp(resolvedCmd, "ping") == 0) {
    publishHeartbeat();
    publishStatus();
    publishAck(resolvedCmd, true, "pong");
    return;
  }

  publishAck(resolvedCmd, false, "unknown command");
}

// ═══════════════════════════════════════════════
//  Zone matching
// ═══════════════════════════════════════════════

bool zoneMatch(const char *sourceZone) {
  if (strcmp(deviceZone, "all") == 0) return true;
  if (strcmp(sourceZone, "all") == 0) return true;
  return strcmp(deviceZone, sourceZone) == 0;
}

// ═══════════════════════════════════════════════
//  Command authentication (64-bit key, constant-time compare)
// ═══════════════════════════════════════════════

bool verifyKey(const char *provided) {
  const char *expected = cmdAuthKey;
  if (!isHexStr(expected, 16) || !isHexStr(provided, 16)) return false;
  return secureEquals(expected, provided);
}

void publishCommandTable() {
  StaticJsonDocument<768> doc;
  doc["device_id"] = deviceId;
  doc["proto_min"] = CMD_PROTO_MIN;
  doc["proto_max"] = CMD_PROTO_MAX;
  JsonArray arr = doc.createNestedArray("commands");
  arr.add("siren_on");
  arr.add("siren_off");
  arr.add("self_test");
  arr.add("reboot");
  arr.add("schedule_reboot");
  arr.add("cancel_scheduled_reboot");
  arr.add("set_param");
  arr.add("set_qr");
  arr.add("assign_id");
  arr.add("reset_id");
  arr.add("factory_reset");
#if OTA_ENABLED
  arr.add("ota");
#endif
  arr.add("get_info");
  arr.add("get_cmd_table");
  arr.add("ping");
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  arr.add("wifi_config");
  arr.add("wifi_clear");
#endif
  doc["aliases"] = "set_params->set_param,info->get_info,reboot_now->reboot,ota_update->ota,red_alert->siren_on,cancel_alert->siren_off,self_check->self_test";
  doc["ts"] = tsNow();

  char buf[768];
  serializeJson(doc, buf, sizeof(buf));
  publishRaw(topicAck, buf, false);
}

// ═══════════════════════════════════════════════
//  MQTT callback
// ═══════════════════════════════════════════════

void onMqttMessage(char *topic, byte *payload, unsigned int length) {
  rxBytesWindow += length;

  char body[MQTT_RX_BUFFER_BYTES];
  unsigned int copyLen = (length < sizeof(body) - 1) ? length : sizeof(body) - 1;
  memcpy(body, payload, copyLen);
  body[copyLen] = '\0';

  StaticJsonDocument<MQTT_JSON_DOC_BYTES> doc;
  if (deserializeJson(doc, body)) {
    strlcpy(lastError, "json_fail", sizeof(lastError));
    return;
  }

  if (strcmp(topic, topicBootstrapAssign) == 0) {
    if (isProvisioned) return;
    if (!saveProvisioningFromClaim(doc.as<JsonVariant>())) {
      strlcpy(lastError, "claim_invalid", sizeof(lastError));
      logLine("[claim] rejected");
      return;
    }
    logLine("[claim] accepted, rebooting");
    requestRestartWithAck("claim", "claim accepted");
    return;
  }

  if (strcmp(topic, topicCmd) == 0) {
    if (!isProvisioned) {
      logLine("[mqtt] cmd ignored: not provisioned");
      return;
    }
    int proto = doc["proto"] | 1;
    if (proto < CMD_PROTO_MIN || proto > CMD_PROTO_MAX) {
      strlcpy(lastError, "proto_unsupported", sizeof(lastError));
      publishAck("proto", false, "unsupported protocol");
      return;
    }

    const char *key = doc["key"] | "";
    if (!verifyKey(key)) {
      strlcpy(lastError, "auth_fail", sizeof(lastError));
      logLine("[auth] bad key rejected");
      return;
    }

    const char *target = doc["target_id"] | "self";
    bool forMe   = (strcmp(target, deviceId) == 0);
    bool forAll  = (strcmp(target, "all") == 0);
    bool isSelf  = (strcmp(target, "self") == 0);
    bool forZone = (strcmp(target, deviceZone) == 0) && (strcmp(deviceZone, "all") != 0);
    char macId[24];
    macToDeviceId(macId, sizeof(macId));
    bool forMac  = (strcmp(target, macId) == 0);
    if (!forMe && !forAll && !isSelf && !forZone && !forMac) {
      char line[192];
      snprintf(line, sizeof(line),
               "[mqtt] cmd ignored: target_id mismatch (target=%s me=%s zone=%s macId=%s)",
               target, deviceId, deviceZone, macId);
      logLine(line);
      return;
    }
    executeCommand(doc["cmd"] | "", doc["params"]);
    return;
  }

}

// ═══════════════════════════════════════════════
//  Topics
// ═══════════════════════════════════════════════

void buildTopics() {
  snprintf(topicHeartbeat, sizeof(topicHeartbeat), "%s/%s/heartbeat", TOPIC_ROOT, deviceId);
  snprintf(topicStatus,    sizeof(topicStatus),    "%s/%s/status",    TOPIC_ROOT, deviceId);
  snprintf(topicEvent,     sizeof(topicEvent),     "%s/%s/event",     TOPIC_ROOT, deviceId);
  snprintf(topicCmd,       sizeof(topicCmd),        "%s/%s/cmd",      TOPIC_ROOT, deviceId);
  snprintf(topicAck,       sizeof(topicAck),        "%s/%s/ack",      TOPIC_ROOT, deviceId);
  snprintf(topicBootstrapAssign, sizeof(topicBootstrapAssign), "%s/%s",
           TOPIC_BOOTSTRAP_ASSIGN_PREFIX, deviceMacNoColon);
}

// ═══════════════════════════════════════════════
//  Connection management
// ═══════════════════════════════════════════════

void ensureWiFi() {
  if (netIf->connected()) {
    wifiBackoffMs = WIFI_RECONNECT_BASE_MS;
    return;
  }

  // Light path: drive WiFiMulti association between heavy reconnect() attempts so
  // STA can come back without waiting for the full exponential backoff window.
  static unsigned long s_lastWifiSliceAt = 0;
  unsigned long now = millis();
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  if (now - s_lastWifiSliceAt >= (unsigned long)WIFI_MULTI_RUN_SLICE_MS) {
    s_lastWifiSliceAt = now;
    if (g_wifiMultiTrySliceJoin()) {
      String lip = netIf->localIP();
      char _nl[80];
      snprintf(_nl, sizeof(_nl), "[net] ip=%s", lip.c_str());
      logLine(_nl);
      wifiBackoffMs = WIFI_RECONNECT_BASE_MS;
      return;
    }
  }
#endif

  if (now - lastWiFiAttemptAt < wifiBackoffMs) return;
  lastWiFiAttemptAt = now;
  logLine("[net] reconnecting...");
  netIf->reconnect();
  if (netIf->connected()) {
    wifiBackoffMs = WIFI_RECONNECT_BASE_MS;
    String lip2 = netIf->localIP();
    char _n2[80];
    snprintf(_n2, sizeof(_n2), "[net] ip=%s", lip2.c_str());
    logLine(_n2);
  } else {
    wifiBackoffMs = min(wifiBackoffMs * 2UL, (unsigned long)RECONNECT_MAX_MS);
  }
}

void ensureMqtt() {
  if (!netIf->connected()) {
    if (mqttClient.connected()) mqttClient.disconnect();
    return;
  }
  if (mqttClient.connected()) {
    mqttBackoffMs = MQTT_RECONNECT_BASE_MS;
    return;
  }
  unsigned long now = millis();
  if (now - lastMQTTAttemptAt < mqttBackoffMs) return;
  lastMQTTAttemptAt = now;

  StaticJsonDocument<256> willDoc;
  willDoc["device_id"]          = deviceId;
  willDoc["mac"]                = deviceMac;
  willDoc["online"]             = false;
  willDoc["zone"]               = deviceZone;
  willDoc["disconnect_reason"]  = "network_lost";
  willDoc["ts"]                 = tsNow();
  char willBuf[256];
  serializeJson(willDoc, willBuf, sizeof(willBuf));

  mqttClient.setSocketTimeout(10);
  twdtFeedMaybe();
  bool ok = mqttClient.connect(
      deviceId, mqttUser, mqttPass,
      topicStatus, 1, true, willBuf,
      MQTT_CLEAN_SESSION);
  twdtFeedMaybe();

  if (!ok) {
    strlcpy(lastError, "mqtt_conn_fail", sizeof(lastError));
    {
      char _mf[48];
      snprintf(_mf, sizeof(_mf), "[mqtt] fail rc=%d", mqttClient.state());
      logLine(_mf);
    }
#if MQTT_USE_TLS
    if (tlsCaSlot == 0 && hasSecondaryCa()) {
      if (applyTlsCaSlot(1)) {
        logLine("[tls] fallback to secondary CA");
        mqttBackoffMs = MQTT_RECONNECT_BASE_MS;
        return;
      }
    } else if (tlsCaSlot == 1 && hasPrimaryCa()) {
      if (applyTlsCaSlot(0)) {
        logLine("[tls] fallback to primary CA");
        mqttBackoffMs = MQTT_RECONNECT_BASE_MS;
        return;
      }
    }
#endif
    mqttBackoffMs = min(mqttBackoffMs * 2UL, (unsigned long)RECONNECT_MAX_MS);
    return;
  }

  logLine("[mqtt] connected");
  if (isProvisioned) {
    mqttClient.subscribe(topicCmd, 1);
    // NOTE: no global alarm topic; server fans out siren_on via our /cmd topic.
  } else {
    mqttClient.subscribe(topicBootstrapAssign, 1);
    publishBootstrapRegister();
  }

  if (!ntpInitDone && netIf->connected()) {
    configTime(NTP_GMT_OFFSET_S, NTP_DAYLIGHT_OFFSET_S, NTP_SERVER);
    ntpInitDone = true;
  }

  publishStatus();
  // Announce presence on (re)connect so the server flips us back to online
  // without having to wait for the next event or 12h probe.
  publishHeartbeatEvent("mqtt_connected");
}

// ═══════════════════════════════════════════════
//  NTP
// ═══════════════════════════════════════════════

void checkNTPSync() {
  unsigned long now = millis();
  if (ntpSynced && (now - lastNtpCheckAt < NTP_RESYNC_INTERVAL_MS)) return;
  lastNtpCheckAt = now;

  unsigned long e = epochNow();
  if (e > 0) {
    if (!ntpSynced) {
      char _nt[56];
      snprintf(_nt, sizeof(_nt), "[ntp] synced epoch=%lu", (unsigned long)e);
      logLine(_nt);
    }
    ntpSynced = true;
  } else {
    if (ntpSynced) {
      ntpSynced = false;
      logLine("[ntp] lost sync");
    }
  }
}

// ═══════════════════════════════════════════════
//  Input handling
// ═══════════════════════════════════════════════

void handleTriggerInput() {
  unsigned long now = millis();
  if (now - lastTriggerReadAt < DEBOUNCE_MS) return;
  lastTriggerReadAt = now;

  bool level = (digitalRead(TRIGGER_GPIO) == HIGH);
  bool fallingEdge = (triggerPrevLevel && !level);
  triggerPrevLevel = level;
  if (!fallingEdge) return;
  if (alarmInCooldown()) {
    return;
  }

  logLine("[trigger] alarm");
  publishAlarmEvent(true);
  publishHeartbeatEvent("alarm");
  if (TRIGGER_SELF_SIREN) activateSiren(rtSirenMs);
}

// ═══════════════════════════════════════════════
//  Throughput
// ═══════════════════════════════════════════════

void updateThroughput() {
  unsigned long now = millis();
  unsigned long elapsed = now - lastThroughputResetAt;
  if (elapsed < THROUGHPUT_WINDOW_MS) return;
  float sec = elapsed / 1000.0f;
  txBps = txBytesWindow / sec;
  rxBps = rxBytesWindow / sec;
  txBytesWindow = 0;
  rxBytesWindow = 0;
  lastThroughputResetAt = now;
}

// ═══════════════════════════════════════════════
//  Task watchdog (TWDT): subscribe before any long WiFi/MQTT blocking work.
//  Arduino-ESP32 often inits TWDT first — prefer reconfigure to avoid duplicate init logs.
// ═══════════════════════════════════════════════

static bool gTwdtLoopSubscribed = false;

static void setupTaskWatchdogEarly() {
#if ESP_IDF_VERSION_MAJOR >= 5
  esp_task_wdt_config_t wdt_cfg = {
      .timeout_ms = (uint32_t)WDT_TIMEOUT_S * 1000u,
      .idle_core_mask = 0,
      .trigger_panic = true,
  };
  esp_err_t e = ESP_FAIL;
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
  e = esp_task_wdt_reconfigure(&wdt_cfg);
#endif
  if (e != ESP_OK) {
    e = esp_task_wdt_init(&wdt_cfg);
  }
  (void)e;
#else
  (void)esp_task_wdt_init(WDT_TIMEOUT_S, true);
#endif
  esp_err_t a = esp_task_wdt_add(NULL);
  // Core may have already subscribed the loop task.
  gTwdtLoopSubscribed = (a == ESP_OK || a == ESP_ERR_INVALID_STATE);
}

static inline void twdtFeedMaybe() {
  if (gTwdtLoopSubscribed) {
    esp_task_wdt_reset();
  }
}

// ═══════════════════════════════════════════════
//  setup / loop
// ═══════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(100);
  setupTaskWatchdogEarly();

  resetReasonStr = decodeResetReason(esp_reset_reason());
  buildDeviceId();

  pinMode(SIREN_GPIO, OUTPUT);
  pinMode(STATUS_LED_GPIO, OUTPUT);
  pinMode(TRIGGER_GPIO, INPUT_PULLUP);
  digitalWrite(SIREN_GPIO, LOW);
  digitalWrite(STATUS_LED_GPIO, LOW);
  // Sync edge-detector baseline to actual pin (assumes NO switch to GND + pull-up: idle HIGH).
  delay(10);
  triggerPrevLevel = (digitalRead(TRIGGER_GPIO) == HIGH);
  {
    char tline[96];
    snprintf(tline, sizeof(tline), "[boot] trigger_gpio=%d idle=%s",
             TRIGGER_GPIO, triggerPrevLevel ? "HIGH" : "LOW");
    logLine(tline);
  }

#if VBAT_SENSOR_ENABLED
  analogReadResolution(12);
  analogSetPinAttenuation(VBAT_ADC_PIN, VBAT_ADC_ATTENUATION);
#endif

  loadParams();
  loadProvisioningRuntime();
  loadScheduledRebootState();
  generateBootstrapNonce();
  processOtaBootState();
  buildTopics();

#if MQTT_USE_TLS
  applyTlsCaSlot(0);
#endif
  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  mqttClient.setCallback(onMqttMessage);
  mqttClient.setBufferSize(MQTT_RX_BUFFER_BYTES);
  mqttClient.setKeepAlive(MQTT_KEEPALIVE_SECONDS);

#if ENABLE_WS_LOG
  wsClient.begin(MQTT_HOST, 8080, "/ws");
  wsClient.setReconnectInterval(3000);
#endif

  netIf->begin();
  bootAtMs = millis();
  lastThroughputResetAt = bootAtMs;

  logLine("[boot] Croc-Sentinel " FW_VERSION);
  // Avoid chained String allocations right after WiFi init (can fragment heap and
  // trigger intermittent SW_CPU_RESET on some boards).
  {
    char line[320];
    snprintf(line, sizeof(line),
             "[boot] id=%s mac=%s mac_nocolon=%s zone=%s rst=%s boot#%lu",
             deviceId, deviceMac, deviceMacNoColon, deviceZone, resetReasonStr,
             (unsigned long)bootCount);
    logLine(line);
    snprintf(line, sizeof(line), "[boot] board_profile=%s", BOARD_PROFILE_NAME);
    logLine(line);
    snprintf(line, sizeof(line), "[boot] provisioned=%s mqtt_user=%s qr=%s",
             isProvisioned ? "yes" : "no", mqttUser, deviceQrCode);
    logLine(line);
  }

  securityConfigValid = validateProductionSecurityConfig();
  if (!securityConfigValid) {
    logLine("[secure] invalid production security configuration; startup blocked");
    while (true) {
      twdtFeedMaybe();
      digitalWrite(STATUS_LED_GPIO, HIGH);
      delay(120);
      digitalWrite(STATUS_LED_GPIO, LOW);
      delay(120);
    }
  }

  // Give Wi-Fi extra time after begin(); must call WiFiMulti::run (not just
  // delay) or association never progresses when the first blocking connect times out.
  unsigned long waitStart = millis();
  while (!netIf->connected() && millis() - waitStart < WIFI_CONNECT_WAIT_MS) {
    twdtFeedMaybe();
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
    if (g_wifiMultiTrySliceJoin()) break;
#else
    delay(WIFI_MULTI_RUN_SLICE_MS);
#endif
    Serial.print('.');
  }
  Serial.println();

  if (netIf->connected()) {
    String lipb = netIf->localIP();
    char _nb[80];
    snprintf(_nb, sizeof(_nb), "[net] ip=%s", lipb.c_str());
    logLine(_nb);
    configTime(NTP_GMT_OFFSET_S, NTP_DAYLIGHT_OFFSET_S, NTP_SERVER);
    ntpInitDone = true;
  }
}

void loop() {
  twdtFeedMaybe();

  unsigned long now = millis();

  // Run MQTT before Wi-Fi may block for seconds; avoids broker keepalive
  // timeouts while STA is re-associating.
  if (netIf->connected() && mqttClient.connected()) {
    mqttClient.loop();
  }

  ensureWiFi();
  ensureMqtt();

  if (mqttClient.connected()) {
    mqttClient.loop();
    flushOfflineQueue();
    if (!isProvisioned && now - lastBootstrapRegisterAt >= BOOTSTRAP_REGISTER_INTERVAL_MS) {
      lastBootstrapRegisterAt = now;
      publishBootstrapRegister();
    }
  }

#if ENABLE_WS_LOG
  wsClient.loop();
#endif

  checkNTPSync();

  // Heartbeat policy — see config.h. EVENT mode leaves this loop silent and
  // only reacts to state changes (see publishHeartbeatEvent). HYBRID sends a
  // slow keepalive to stop the server from having to probe.
#if HEARTBEAT_MODE == HEARTBEAT_MODE_PERIODIC
  if (now - lastHeartbeatAt >= rtHeartbeatMs) {
    lastHeartbeatAt = now;
    publishHeartbeat();
  }
#elif HEARTBEAT_MODE == HEARTBEAT_MODE_HYBRID
  if (now - lastHeartbeatAt >= HEARTBEAT_IDLE_KEEPALIVE_MS) {
    lastHeartbeatAt = now;
    publishHeartbeat();
  }
#endif

  updateThroughput();

  if (now - lastStatusAt >= rtStatusMs) {
    lastStatusAt = now;
    publishStatus();
  }

  handleTriggerInput();
  flushNvsIfNeeded();
  confirmOtaIfHealthy();

  // Only fire on a real Unix deadline; sub-1.7e9 values are legacy millis mistakes.
  if (scheduledRebootArmed && scheduledRebootEpoch >= 1700000000UL && tsNow() >= scheduledRebootEpoch) {
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    requestRestartWithAck("schedule_reboot", "reboot due");
  } else if (scheduledRebootArmed && scheduledRebootEpoch > 0 && scheduledRebootEpoch < 1700000000UL &&
             epochNow() > 1700000000UL) {
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    logLine("[sched] cleared bogus reboot epoch at runtime");
  }

  if (sirenExpired()) deactivateSiren();

  bool mqttOk = mqttClient.connected();
  digitalWrite(STATUS_LED_GPIO, mqttOk ? HIGH : (((now / 250) & 1) ? HIGH : LOW));
}
