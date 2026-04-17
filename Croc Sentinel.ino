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
#include <esp_system.h>
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

void buildDeviceId() {
  getMacString();
  getMacNoColon(deviceMacNoColon, sizeof(deviceMacNoColon));
#if DEVICE_ID_AUTO
  Preferences p;
  p.begin(NVS_NAMESPACE, true);
  String assigned = p.getString("dev_id", "");
  p.end();
  if (assigned.length() > 0) {
    strlcpy(deviceId, assigned.c_str(), sizeof(deviceId));
  } else {
    macToDeviceId(deviceId, sizeof(deviceId));
  }
#else
  strlcpy(deviceId, DEVICE_ID_MANUAL, sizeof(deviceId));
#endif
}

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
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }
  bool connected() override { return WiFi.status() == WL_CONNECTED; }
  bool reconnect() override {
    if (connected()) return true;
    WiFi.disconnect(false, true);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    return false;
  }
  String localIP() override {
    return connected() ? WiFi.localIP().toString() : "0.0.0.0";
  }
  int rssi() override { return connected() ? WiFi.RSSI() : -127; }
  const char *type() override { return "wifi"; }
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

  unsigned long nowEpoch = epochNow();
  if (armed && epoch > 1700000000UL && nowEpoch > 1700000000UL && epoch > nowEpoch) {
    scheduledRebootArmed = true;
    scheduledRebootEpoch = epoch;
    logLine(String("[sched] restored reboot at epoch=") + scheduledRebootEpoch);
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

void setOtaPendingState(const char *targetFw) {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putBool("ota_pend", true);
  prefs.putUInt("ota_fail", 0);
  prefs.putString("ota_tgt", targetFw);
  prefs.end();
}

void clearOtaPendingState() {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putBool("ota_pend", false);
  prefs.putUInt("ota_fail", 0);
  prefs.remove("ota_tgt");
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

  logLine(String("[ota] pending validation fw=") + target + " boot_try=" + fails);

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
    logLine(String("[ota] validate failed rc=") + (int)rc);
    return;
  }

  clearOtaPendingState();
  otaPendingValidation = false;
  logLine("[ota] validated");
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
  digitalWrite(SIREN_GPIO, HIGH);
  sirenActive = true;
  sirenStartAt = millis();
  sirenDurationMs = durationMs;
}

void deactivateSiren() {
  digitalWrite(SIREN_GPIO, LOW);
  sirenActive = false;
  sirenDurationMs = 0;
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
  StaticJsonDocument<320> doc;
  doc["type"]           = "alarm.trigger";
  doc["source_id"]      = deviceId;
  doc["source_zone"]    = deviceZone;
  doc["local_trigger"]  = localTrigger;
  unsigned long nowTs   = tsNow();
  uint32_t nonce        = esp_random();
  char sig[17];
  buildAlarmSignature(deviceId, deviceZone, nowTs, nonce, sig, sizeof(sig));
  doc["ts"]             = nowTs;
  doc["nonce"]          = nonce;
  doc["sig"]            = sig;

  char buf[320];
  serializeJson(doc, buf, sizeof(buf));

  publishRaw(topicEvent, buf, false);
  publishRaw(TOPIC_BROADCAST_ALARM, buf, false);
  lastAlarmAt = millis();
}

// ═══════════════════════════════════════════════
//  OTA (WDT-safe)
// ═══════════════════════════════════════════════

#if OTA_ENABLED
void performOTA(const char *url, const char *targetFw) {
  logLine(String("[ota] from: ") + stripQuery(url));
  publishAck("ota", true, "ota starting");

  setOtaPendingState(targetFw);
  esp_task_wdt_delete(NULL);

  NetworkClient otaClient;
  httpUpdate.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  t_httpUpdate_return ret = httpUpdate.update(otaClient, url);

  esp_task_wdt_add(NULL);

  switch (ret) {
    case HTTP_UPDATE_FAILED:
      clearOtaPendingState();
      logLine(String("[ota] FAILED: ") + httpUpdate.getLastErrorString());
      publishAck("ota", false, httpUpdate.getLastErrorString().c_str());
      break;
    case HTTP_UPDATE_NO_UPDATES:
      clearOtaPendingState();
      publishAck("ota", false, "no update");
      break;
    case HTTP_UPDATE_OK:
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
    if (delayS > 0) {
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
    logLine(String("[id] assigned: ") + newId);
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
    const char *targetFw = params["fw"] | "unknown";
    performOTA(fullUrl, targetFw);
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
    if (!isProvisioned) return;
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
    if (!forMe && !forAll && !isSelf && !forZone && !forMac) return;
    executeCommand(doc["cmd"] | "", doc["params"]);
    return;
  }

  if (strcmp(topic, TOPIC_BROADCAST_ALARM) == 0) {
    const char *source     = doc["source_id"] | "";
    const char *sourceZone = doc["source_zone"] | "all";
    unsigned long ts       = doc["ts"] | 0;
    uint32_t nonce         = doc["nonce"] | 0;
    const char *sig        = doc["sig"] | "";

    if (strlen(source) == 0 || !isHexStr(sig, 16)) return;
    char expectedSig[17];
    buildAlarmSignature(source, sourceZone, ts, nonce, expectedSig, sizeof(expectedSig));
    if (!secureEquals(sig, expectedSig)) {
      strlcpy(lastError, "alarm_sig_fail", sizeof(lastError));
      return;
    }

    if (strcmp(source, deviceId) == 0 && !TRIGGER_SELF_SIREN) return;
    if (!zoneMatch(sourceZone)) return;
    if (alarmInCooldown()) return;

    activateSiren(rtSirenMs);
    lastAlarmAt = millis();
    logLine(String("[alarm] from ") + source + " z=" + sourceZone);
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
  unsigned long now = millis();
  if (now - lastWiFiAttemptAt < wifiBackoffMs) return;
  lastWiFiAttemptAt = now;
  netIf->reconnect();
  logLine("[net] reconnecting...");
  wifiBackoffMs = min(wifiBackoffMs * 2UL, (unsigned long)RECONNECT_MAX_MS);
}

void ensureMqtt() {
  if (!netIf->connected()) return;
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
  bool ok = mqttClient.connect(
      deviceId, mqttUser, mqttPass,
      topicStatus, 1, true, willBuf,
      MQTT_CLEAN_SESSION);

  if (!ok) {
    strlcpy(lastError, "mqtt_conn_fail", sizeof(lastError));
    logLine(String("[mqtt] fail rc=") + mqttClient.state());
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
    mqttClient.subscribe(TOPIC_BROADCAST_ALARM, 1);
  } else {
    mqttClient.subscribe(topicBootstrapAssign, 1);
    publishBootstrapRegister();
  }

  if (!ntpInitDone && netIf->connected()) {
    configTime(NTP_GMT_OFFSET_S, NTP_DAYLIGHT_OFFSET_S, NTP_SERVER);
    ntpInitDone = true;
  }

  publishStatus();
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
    if (!ntpSynced) logLine(String("[ntp] synced epoch=") + e);
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
  if (alarmInCooldown()) return;

  logLine("[trigger] alarm");
  publishAlarmEvent(true);
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
//  setup / loop
// ═══════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(100);

  resetReasonStr = decodeResetReason(esp_reset_reason());
  buildDeviceId();

  pinMode(SIREN_GPIO, OUTPUT);
  pinMode(STATUS_LED_GPIO, OUTPUT);
  pinMode(TRIGGER_GPIO, INPUT_PULLUP);
  digitalWrite(SIREN_GPIO, LOW);
  digitalWrite(STATUS_LED_GPIO, LOW);

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
  mqttClient.setKeepAlive(20);

#if ENABLE_WS_LOG
  wsClient.begin(MQTT_HOST, 8080, "/ws");
  wsClient.setReconnectInterval(3000);
#endif

  netIf->begin();
  bootAtMs = millis();
  lastThroughputResetAt = bootAtMs;

  logLine("[boot] Croc-Sentinel " FW_VERSION);
  logLine(String("[boot] id=") + deviceId + " mac=" + deviceMac
          + " zone=" + deviceZone + " rst=" + resetReasonStr
          + " boot#" + bootCount);
  logLine(String("[boot] board_profile=") + BOARD_PROFILE_NAME);
  logLine(String("[boot] provisioned=") + (isProvisioned ? "yes" : "no")
          + " mqtt_user=" + mqttUser + " qr=" + deviceQrCode);

  securityConfigValid = validateProductionSecurityConfig();
  if (!securityConfigValid) {
    logLine("[secure] invalid production security configuration; startup blocked");
    while (true) {
      digitalWrite(STATUS_LED_GPIO, HIGH);
      delay(120);
      digitalWrite(STATUS_LED_GPIO, LOW);
      delay(120);
    }
  }

  unsigned long waitStart = millis();
  while (!netIf->connected() && millis() - waitStart < WIFI_CONNECT_WAIT_MS) {
    delay(200);
    Serial.print('.');
  }
  Serial.println();

  if (netIf->connected()) {
    logLine(String("[net] ip=") + netIf->localIP());
    configTime(NTP_GMT_OFFSET_S, NTP_DAYLIGHT_OFFSET_S, NTP_SERVER);
    ntpInitDone = true;
  }

  esp_task_wdt_init(WDT_TIMEOUT_S, true);
  esp_task_wdt_add(NULL);
}

void loop() {
  esp_task_wdt_reset();

  unsigned long now = millis();

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

  if (now - lastHeartbeatAt >= rtHeartbeatMs) {
    lastHeartbeatAt = now;
    publishHeartbeat();
  }

  updateThroughput();

  if (now - lastStatusAt >= rtStatusMs) {
    lastStatusAt = now;
    publishStatus();
  }

  handleTriggerInput();
  flushNvsIfNeeded();
  confirmOtaIfHealthy();

  if (scheduledRebootArmed && tsNow() >= scheduledRebootEpoch) {
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    requestRestartWithAck("schedule_reboot", "reboot due");
  }

  if (sirenExpired()) deactivateSiren();

  bool mqttOk = mqttClient.connected();
  digitalWrite(STATUS_LED_GPIO, mqttOk ? HIGH : (((now / 250) & 1) ? HIGH : LOW));
}
