#include <Arduino.h>
#include <NetworkClient.h>
#if !defined(CONFIG_IDF_TARGET_ESP32P4)
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
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
char accessorySn[40];
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
//                           factory_devices table). If "serial" is set, it wins
//                           over "dev_id"; the server's claim device_id should match.
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

#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
// Double external-reset tap: RTC slow memory survives chip EN/RST resets while VDD stays up.
// Not a time window — two consecutive ESP_RST_EXT boots increment a counter; at 2 we open AP.
// Cleared on power-on, brownout, or any non-EXT reset reason.
#define CROC_DBL_EXT_MAGIC 0x43725044u
RTC_DATA_ATTR static uint32_t s_crocDblExtMagic = 0;
RTC_DATA_ATTR static uint8_t s_crocDblExtCount = 0;
static bool g_doubleExtRstProvision = false;

static void crocDoubleExtResetTapUpdate(esp_reset_reason_t rr) {
  g_doubleExtRstProvision = false;
  if (rr == ESP_RST_POWERON || rr == ESP_RST_BROWNOUT) {
    s_crocDblExtMagic = 0;
    s_crocDblExtCount = 0;
    return;
  }
  if (rr != ESP_RST_EXT) {
    s_crocDblExtMagic = 0;
    s_crocDblExtCount = 0;
    return;
  }
  if (s_crocDblExtMagic != CROC_DBL_EXT_MAGIC) {
    s_crocDblExtMagic = CROC_DBL_EXT_MAGIC;
    s_crocDblExtCount = 1;
    return;
  }
  s_crocDblExtCount++;
  if (s_crocDblExtCount >= 2) {
    g_doubleExtRstProvision = true;
    s_crocDblExtMagic = 0;
    s_crocDblExtCount = 0;
  }
}
#endif

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
  g_wifiMultiRegisterAps();
  if (g_wifiMultiApCount == 0) return false;
  unsigned long t0 = millis();
  while (millis() - t0 < timeoutMs) {
    twdtFeedMaybe();
    if (g_wifiMultiTrySliceJoin()) return true;
    delay(20);
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

#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
static DNSServer g_provDns;
static WebServer g_provHttp(80);
static bool g_provActive = false;
static bool g_provUnlocked = false;
static char g_provAccessorySn[40] = {0};
static unsigned long g_lastProvStartMs = 0;
static unsigned long g_lastProvStopMs = 0;
static bool g_provWifiSavedOk = false;
static bool g_resetByExternal = false;

static bool isAccessorySnAllowedLocal(const String &snInput) {
  String sn = snInput;
  sn.trim();
  if ((int)sn.length() < ACCESSORY_SN_MIN_LEN) return false;
  const char *allow = ACCESSORY_SN_ALLOWLIST;
  bool allowlistOk = false;
  if (allow && strlen(allow) > 0) {
    String list = String(allow);
    int start = 0;
    while (start <= list.length()) {
      int comma = list.indexOf(',', start);
      String token = (comma >= 0) ? list.substring(start, comma) : list.substring(start);
      token.trim();
      if (token.length() > 0 && token.equalsIgnoreCase(sn)) {
        allowlistOk = true;
        break;
      }
      if (comma < 0) break;
      start = comma + 1;
    }
  } else {
    allowlistOk = true;
  }
#if ACCESSORY_SN_REQUIRE_MATCH_DEVICE_SERIAL
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return false;
  String serial = p.getString("serial", "");
  p.end();
  if (!serial.length()) return false;
  if (!serial.equalsIgnoreCase(sn)) return false;
#endif
  return allowlistOk;
}

static String provEsc(const String &s) {
  String o;
  o.reserve(s.length() + 16);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '&') o += F("&amp;");
    else if (c == '<') o += F("&lt;");
    else if (c == '>') o += F("&gt;");
    else if (c == '"') o += F("&quot;");
    else o += c;
  }
  return o;
}

static String provPageGate(const String &msg) {
  String html = F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                  "<title>Croc Setup</title></head><body style='font-family:Arial;padding:20px;max-width:560px;margin:auto'>"
                  "<h2>Accessory SN verification</h2><p>Enter accessory SN to unlock Wi-Fi setup.</p>");
  if (msg.length()) {
    html += F("<p style='color:#b00020'>");
    html += provEsc(msg);
    html += F("</p>");
  }
  html += F("<form method='post' action='/unlock' onsubmit=\"var b=this.querySelector('button');b.disabled=true;b.textContent='Verifying…';\">"
            "<label>Accessory SN<br><input name='acc_sn' required maxlength='39' style='width:100%;padding:10px;margin-top:6px'></label>"
            "<button type='submit' style='margin-top:12px;padding:10px 14px'>Verify / 验证</button></form>"
            "</body></html>");
  return html;
}

static String provPageWifi(const String &msg) {
  String html = F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                  "<title>Croc Wi-Fi Setup</title></head><body style='font-family:Arial;padding:20px;max-width:560px;margin:auto'>"
                  "<h2>Wi-Fi setup</h2><p>Accessory verified. Enter target Wi-Fi credentials.</p>");
  if (msg.length()) {
    html += F("<p style='color:#0b7a58'>");
    html += provEsc(msg);
    html += F("</p>");
  }
  html += F("<form method='post' action='/save' onsubmit=\"var b=this.querySelector('button');b.disabled=true;b.textContent='Saving, rebooting…';\">"
            "<label>SSID<br><input name='ssid' required maxlength='32' style='width:100%;padding:10px;margin-top:6px'></label><br><br>"
            "<label>Password<br><input name='password' maxlength='64' style='width:100%;padding:10px;margin-top:6px'></label><br>"
            "<p style='color:#666;font-size:15px'>After save the page will show <b>Saved</b>, then the device reboots. 保存后会显示 <b>Saved</b> 并重启；若仍无法连上 Wi-Fi，请按板载 <b>RST</b> 重启后再进配网热点。</p>"
            "<button type='submit' style='margin-top:12px;padding:10px 14px'>Save and reboot</button></form>"
            "</body></html>");
  return html;
}

static void provisioningPortalStop() {
  if (!g_provActive) return;
  g_provHttp.stop();
  g_provDns.stop();
  WiFi.softAPdisconnect(true);
  g_provActive = false;
  g_provUnlocked = false;
  memset(g_provAccessorySn, 0, sizeof(g_provAccessorySn));
  g_lastProvStopMs = millis();
}

static void provisioningPortalStart() {
  if (!WIFI_PROVISION_PORTAL_ENABLED || g_provActive) return;
  g_provWifiSavedOk = false;
  char apName[40];
  snprintf(apName, sizeof(apName), "%s-%c%c%c%c",
           WIFI_PROVISION_AP_PREFIX,
           deviceMacNoColon[8], deviceMacNoColon[9], deviceMacNoColon[10], deviceMacNoColon[11]);
  WiFi.mode(WIFI_AP_STA);
  /* Explicit AP LAN — some phones fail to resolve captive portal unless AP IP is stable. */
  {
    IPAddress apIp(192, 168, 4, 1);
    IPAddress gw(192, 168, 4, 1);
    IPAddress nm(255, 255, 255, 0);
    if (!WiFi.softAPConfig(apIp, gw, nm)) {
      logLine("[wifi] softAPConfig returned false (continuing)");
    }
  }
  if (!WiFi.softAP(apName)) {
    logLine(String("[wifi] softAP failed for ") + apName);
    return;
  }
  {
    char _apip[48];
    snprintf(_apip, sizeof(_apip), "[wifi] provisioning AP IP=%s ch=%d",
             WiFi.softAPIP().toString().c_str(), WiFi.channel());
    logLine(_apip);
  }
  g_provDns.start(53, "*", WiFi.softAPIP());
  g_provHttp.on("/", HTTP_GET, []() {
    if (!g_provUnlocked) g_provHttp.send(200, "text/html", provPageGate(""));
    else g_provHttp.send(200, "text/html", provPageWifi(""));
  });
  g_provHttp.on("/unlock", HTTP_POST, []() {
    String sn = g_provHttp.arg("acc_sn");
    if (!isAccessorySnAllowedLocal(sn)) {
      g_provHttp.send(403, "text/html", provPageGate("Accessory SN verification failed."));
      return;
    }
    g_provUnlocked = true;
    strlcpy(g_provAccessorySn, sn.c_str(), sizeof(g_provAccessorySn));
    g_provHttp.send(200, "text/html", provPageWifi("Verified."));
  });
  g_provHttp.on("/save", HTTP_POST, []() {
    if (!g_provUnlocked) {
      g_provHttp.send(403, "text/html", provPageGate("Accessory SN verification required."));
      return;
    }
    String ssid = g_provHttp.arg("ssid");
    String pass = g_provHttp.arg("password");
    ssid.trim();
    if (ssid.length() == 0 || ssid.length() > 32 || pass.length() > 64) {
      g_provHttp.send(400, "text/html", provPageWifi("Invalid SSID or password length."));
      return;
    }
    Preferences p;
    p.begin(NVS_NAMESPACE, false);
    p.putString("wifi_sta_ssid", ssid);
    p.putString("wifi_sta_pass", pass);
    if (strlen(g_provAccessorySn) > 0) p.putString("acc_sn", g_provAccessorySn);
    p.end();
    g_provWifiSavedOk = true;
    g_provHttp.send(200, "text/html", "<html><body style='font-family:Arial;padding:20px'><h3>Saved / 已保存</h3><p>Rebooting. If Wi-Fi still fails, press board <b>RST</b> then connect to setup AP again. 设备正在重启；若仍无法连上 Wi-Fi，请按板载 RST 再开热点。</p></body></html>");
    delay(500);
    ESP.restart();
  });
  g_provHttp.begin();
  g_provActive = true;
  g_lastProvStartMs = millis();
  logLine(String("[wifi] provisioning portal started ap=") + apName);
}

static void provisioningPortalLoop() {
  if (!g_provActive) return;
  if (WIFI_PROVISION_WINDOW_MS > 0 &&
      (millis() - g_lastProvStartMs) >= (unsigned long)WIFI_PROVISION_WINDOW_MS) {
    logLine("[wifi] provisioning window elapsed; closing AP");
    provisioningPortalStop();
    if (!g_provWifiSavedOk) {
      logLine("[wifi] no Wi-Fi save in window; rebooting");
      delay(150);
      ESP.restart();
    }
    return;
  }
  g_provDns.processNextRequest();
  g_provHttp.handleClient();
}

static bool provisioningPortalManualBootAllowed() {
  if (!WIFI_PROVISION_PORTAL_ENABLED) return false;
#if WIFI_PROVISION_REQUIRE_DOUBLE_RST
  return g_doubleExtRstProvision;
#else
  return g_resetByExternal || g_doubleExtRstProvision;
#endif
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

unsigned long lastTriggerDirectReadAt = 0;
unsigned long lastTriggerRemoteReadAt = 0;
unsigned long lastTriggerSilentReadAt = 0;
bool triggerDirectPrevLevel = true;
bool triggerRemotePrevLevel = true;
bool triggerSilentPrevLevel = true;
bool triggerSilentPressed = false;
unsigned long triggerSilentPressAt = 0;
#ifndef REMOTE_SILENT_LONG_PRESS_MS
#define REMOTE_SILENT_LONG_PRESS_MS 1200UL
#endif

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

// /cmd: copy in MQTT callback, parse + executeCommand() on main loop only.
static char sPendingCmdBody[MQTT_RX_BUFFER_BYTES];
static size_t sPendingCmdLen = 0;
static volatile bool sPendingCmdArm = false;
static unsigned long s_mqttCmdGraceUntilMs = 0;
static volatile bool s_mqttPostConnectPublish = false;

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

  /* Also accept http(s)://<authority>/... where authority is exactly
   * OTA_ALLOWED_HOST (e.g. host, or host:port). Legacy prefix
   * http://OTA_ALLOWED_HOST/  alone rejected URLs like
   * http://1.2.3.4:18999/fw/... when OTA_ALLOWED_HOST was "1.2.3.4:18999". */
  int scheme = u.startsWith("https://") ? 8 : 7;
  int pathStart = u.indexOf('/', scheme);
  if (pathStart > scheme) {
    String auth = u.substring(scheme, pathStart);
    if (auth == String(OTA_ALLOWED_HOST)) {
      return true;
    }
  }
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
  String acc = prefs.getString("acc_sn", "");
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
  if (acc.length() > 0 && acc.length() < sizeof(accessorySn)) {
    strlcpy(accessorySn, acc.c_str(), sizeof(accessorySn));
  } else {
    accessorySn[0] = '\0';
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
  if (strlen(accessorySn) > 0) doc["accessory_sn"] = accessorySn;
  doc["accessory_sn_local_verified"] = (strlen(accessorySn) > 0);
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
  {
    char line[128];
    snprintf(line, sizeof(line), "[rst] cmd=%s %s", cmd, detail ? detail : "");
    logLine(line);
  }
  publishAck(cmd, true, detail);
  // Give PubSubClient a brief window to flush ACK before restart.
  // This avoids API-side timeouts for commands that reboot immediately.
  if (mqttClient.connected()) {
    unsigned long until = millis() + 220;
    while ((long)(until - millis()) > 0) {
      mqttClient.loop();
      delay(10);
    }
  }
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
  digitalWrite(SIREN_GPIO, SIREN_ON);
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
  digitalWrite(SIREN_GPIO, SIREN_OFF);
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

void publishAlarmEvent(const char *triggerKind, bool localSiren) {
  // Server-only fan-out. The device never MQTT-subscribes to group topics; it only
  // publishes JSON on its own /event. Sibling linkage uses the API DB field
  // device_state.notification_group (not stored on the MCU). Empty string there
  // means no cross-device fan-out. Siblings: same owner_admin + same non-empty group
  // (+ zone), excluding revoked IDs.
  // Mapping:
  // panic_button → local siren optional (TRIGGER_SELF_SIREN) + sibling siren_on.
  // remote_loud_button → sibling siren_on only.
  // remote_silent_button(short) → sibling alarm_signal.
  // remote_pause_button(long remote_silent) → local + sibling siren_off.
  StaticJsonDocument<320> doc;
  doc["type"]           = "alarm.trigger";
  doc["source_id"]      = deviceId;
  doc["source_zone"]    = deviceZone;
  doc["local_trigger"]  = localSiren;
  doc["trigger_kind"]   = (triggerKind && strlen(triggerKind) > 0) ? triggerKind : (localSiren ? "panic_button" : "network");
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

// Deferred commands after wifi_config: stored in NVS, run one per loop() when MQTT is up.
static bool wifiChainCmdAllowed(const char *c) {
  if (!c || !*c) return false;
  return strcmp(c, "get_info") == 0 || strcmp(c, "ping") == 0 ||
         strcmp(c, "self_test") == 0 || strcmp(c, "set_param") == 0;
}

static void processPendingWifiChain();

// Wipe everything written by claim/bootstrap/wifi_config + runtime tuneables, but
// keep factory "serial" in NVS (if burned) for factory_devices re-use.
static void performUnclaimNvsPurge() {
  static const char *kUnclaim[] = {
    "prov", "dev_id", "mqtt_u", "mqtt_p", "cmd_key", "qr_code", "zone", "acc_sn",
    "wifi_sta_ssid", "wifi_sta_pass", "wifi_chain",
    "ota_pend", "ota_fail", "ota_tgt", "ota_cid",
    "rb_arm", "rb_ep",
    "boot_cnt", "hb_ms", "st_ms", "sir_ms", "rssi_t", "vbat_t",
  };
  prefs.begin(NVS_NAMESPACE, false);
  for (size_t i = 0; i < sizeof(kUnclaim) / sizeof(kUnclaim[0]); i++) {
    prefs.remove(kUnclaim[i]);
  }
  prefs.end();
  logLine("[nvs] unclaim_reset: provision + WiFi cleared (serial key not touched)");
}

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

  // Silent linkage command: receives a linked silent alert from server fanout.
  // Intentionally does not sound siren; only refreshes state/telemetry.
  if (strcmp(resolvedCmd, "alarm_signal") == 0) {
    publishHeartbeatEvent("alarm_signal");
    publishStatus();
    publishAck(resolvedCmd, true, "alarm signal received");
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

  if (strcmp(resolvedCmd, "unclaim_reset") == 0) {
    performUnclaimNvsPurge();
    scheduledRebootArmed = false;
    scheduledRebootEpoch = 0;
    persistScheduledRebootIfNeeded();
    requestRestartWithAck(resolvedCmd, "unclaim_reset");
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
    {
      JsonVariant chv = params["chain"];
      if (!chv.isNull() && chv.is<JsonArray>()) {
        JsonArray cha = chv.as<JsonArray>();
        StaticJsonDocument<1024> out;
        JsonArray oa = out.to<JsonArray>();
        for (JsonVariant v : cha) {
          JsonObject it = v.as<JsonObject>();
          if (it.isNull()) continue;
          const char *c = it["cmd"] | "";
          if (!wifiChainCmdAllowed(c)) continue;
          JsonObject no = oa.createNestedObject();
          no["cmd"] = c;
          JsonObject srcp = it["params"].as<JsonObject>();
          JsonObject dstp = no.createNestedObject("params");
          if (!srcp.isNull()) {
            for (JsonPair kv : srcp) {
              dstp[kv.key()] = kv.value();
            }
          }
          if (oa.size() >= 4) break;
        }
        if (oa.size() > 0) {
          String qj;
          serializeJson(out, qj);
          prefs.putString("wifi_chain", qj);
          logLine("[wifi] deferred cmd chain saved to NVS");
        } else {
          prefs.remove("wifi_chain");
        }
      } else {
        prefs.remove("wifi_chain");
      }
    }
    prefs.end();
    requestRestartWithAck(resolvedCmd, "wifi_config saved");
    return;
  }

  if (strcmp(resolvedCmd, "wifi_clear") == 0) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("wifi_sta_ssid");
    prefs.remove("wifi_sta_pass");
    prefs.end();
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

static void processPendingWifiChain() {
  if (!mqttClient.connected() || !isProvisioned) return;
  if (millis() < s_mqttCmdGraceUntilMs) return;

  prefs.begin(NVS_NAMESPACE, true);
  String chain = prefs.getString("wifi_chain", "");
  prefs.end();
  if (chain.length() == 0) return;

  StaticJsonDocument<1000> doc;
  DeserializationError err = deserializeJson(doc, chain);
  if (err || !doc.is<JsonArray>()) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("wifi_chain");
    prefs.end();
    logLine("[wifi_chain] invalid JSON, cleared");
    return;
  }
  JsonArray arr = doc.as<JsonArray>();
  if (arr.size() == 0) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("wifi_chain");
    prefs.end();
    return;
  }

  JsonObject first = arr[0].as<JsonObject>();
  const char *cmd = first["cmd"] | "";
  if (!wifiChainCmdAllowed(cmd)) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("wifi_chain");
    prefs.end();
    logLine("[wifi_chain] disallowed cmd, cleared queue");
    return;
  }

  arr.remove(0);
  if (arr.size() > 0) {
    String out;
    serializeJson(doc, out);
    prefs.begin(NVS_NAMESPACE, false);
    prefs.putString("wifi_chain", out);
    prefs.end();
  } else {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.remove("wifi_chain");
    prefs.end();
  }

  JsonObject pobj = first["params"].as<JsonObject>();
  static StaticJsonDocument<384> pexec;
  pexec.clear();
  if (!pobj.isNull()) {
    for (JsonPair kv : pobj) {
      pexec[kv.key()] = kv.value();
    }
  }
  logLine("[wifi_chain] running deferred cmd");
  executeCommand(cmd, pexec.as<JsonVariant>());
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

// Runs on loop() stack — never call from onMqttMessage (retained /cmd + nested publish).
static void handleCmdFromBody(const char *body) {
  StaticJsonDocument<MQTT_JSON_DOC_BYTES> doc;
  if (deserializeJson(doc, body)) {
    strlcpy(lastError, "json_fail", sizeof(lastError));
    return;
  }
  if (!isProvisioned) {
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
}

static void processPendingMqttCommand() {
  if (!sPendingCmdArm) return;
  sPendingCmdArm = false;

  if (millis() < s_mqttCmdGraceUntilMs) {
    static unsigned long s_lastGraceLogMs = 0;
    unsigned long m = millis();
    if (m - s_lastGraceLogMs > 3000UL) {
      s_lastGraceLogMs = m;
      logLine("[mqtt] cmd dropped (post-connect grace)");
    }
    return;
  }

  char local[MQTT_RX_BUFFER_BYTES];
  memcpy(local, sPendingCmdBody, sPendingCmdLen + 1u);
  local[sPendingCmdLen] = '\0';
  handleCmdFromBody(local);
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
  arr.add("alarm_signal");
  arr.add("reboot");
  arr.add("schedule_reboot");
  arr.add("cancel_scheduled_reboot");
  arr.add("set_param");
  arr.add("set_qr");
  arr.add("assign_id");
  arr.add("reset_id");
  arr.add("factory_reset");
  arr.add("unclaim_reset");
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

  if (strcmp(topic, topicCmd) == 0) {
    if (!isProvisioned) {
      return;
    }
    if (ESP.getFreeHeap() < (uint32_t)MIN_FREE_HEAP_ACCEPT_CMD_BYTES) {
      return;
    }
    if (sPendingCmdArm) {
      return;
    }
    memcpy(sPendingCmdBody, body, copyLen + 1u);
    sPendingCmdLen = copyLen;
    sPendingCmdArm = true;
    return;
  }

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

// Set true after we have ever seen a linked STA (or Ethernet in AUTO). Used so
// the first join attempt is not debounced, while brief post-link dropouts are.
static bool s_netHadLink = false;
// Monotonic millis when we first observed link down after s_netHadLink became true.
static unsigned long s_linkDownSinceMs = 0;

void ensureWiFi() {
  unsigned long now = millis();

  if (netIf->connected()) {
    s_netHadLink = true;
    s_linkDownSinceMs = 0;
    wifiBackoffMs = WIFI_RECONNECT_BASE_MS;
    return;
  }

  if (s_netHadLink && s_linkDownSinceMs == 0) {
    s_linkDownSinceMs = now;
  }

  const bool linkDownStable =
      !s_netHadLink ||
      (s_linkDownSinceMs != 0 &&
       (now - s_linkDownSinceMs) >= (unsigned long)WIFI_LINK_DOWN_DEBOUNCE_MS);

#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  g_wifiMultiRegisterAps();
  if (g_wifiMultiApCount == 0) {
    static unsigned long s_lastNoCredLogMs = 0;
    if (now - s_lastNoCredLogMs > 60000UL) {
      s_lastNoCredLogMs = now;
      logLine("[net] no STA credentials (empty WIFI_* in config.h and no NVS wifi_sta_ssid). "
              "Use Dashboard wifi_config or set compile-time SSID.");
    }
    return;
  }
#endif

  // Light path: drive WiFiMulti association between heavy reconnect() attempts so
  // STA can come back without waiting for the full exponential backoff window.
  static unsigned long s_lastWifiSliceAt = 0;
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

  if (!linkDownStable) {
    // Keep driving WiFiMulti slices only; do not call reconnect() (disconnect+join)
    // until the link has been absent long enough — avoids aborting an in-flight join.
    return;
  }

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
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
    // Manual policy: no auto-open AP here; use board RST (external reset) to open portal on boot.
#endif
  }
}

void ensureMqtt() {
  if (!netIf->connected()) {
    // Do not drop an active MQTT session on brief STA flicker; wait for the same
    // debounce window used by ensureWiFi() so a momentary !WL_CONNECTED does not
    // force a full TLS reconnect storm.
    if (s_netHadLink && s_linkDownSinceMs != 0 &&
        (millis() - s_linkDownSinceMs) < (unsigned long)WIFI_LINK_DOWN_DEBOUNCE_MS) {
      return;
    }
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
  s_mqttCmdGraceUntilMs = millis() + (unsigned long)MQTT_POST_CONNECT_CMD_GRACE_MS;
  if (isProvisioned) {
    mqttClient.subscribe(topicCmd, 1);
  } else {
    mqttClient.subscribe(topicBootstrapAssign, 1);
    publishBootstrapRegister();
  }

  if (!ntpInitDone && netIf->connected()) {
    configTime(NTP_GMT_OFFSET_S, NTP_DAYLIGHT_OFFSET_S, NTP_SERVER);
    ntpInitDone = true;
  }

  // Defer large JSON publishes to loop() — avoids stack/DMA pressure in the
  // connect/subscribe path and lets post-connect grace drop stale retained /cmd.
  s_mqttPostConnectPublish = true;
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
  bool fired = false;

  // Panic: local siren FIRST (GPIO), then MQTT so TLS/publish cannot delay the relay.
  // Siblings still go through the API (network delay is unavoidable there).
  if (now - lastTriggerDirectReadAt >= BUTTON_DEBOUNCE_MS) {
    lastTriggerDirectReadAt = now;
    bool level = (digitalRead(PANIC_BUTTON_GPIO) == HIGH);
    bool fallingEdge = (triggerDirectPrevLevel && !level);
    triggerDirectPrevLevel = level;
    if (fallingEdge && !alarmInCooldown()) {
      logLine("[trigger] panic_button");
      if (TRIGGER_SELF_SIREN) activateSiren(rtSirenMs);
      publishAlarmEvent("panic_button", true);
      publishHeartbeatEvent("alarm_panic");
      fired = true;
    }
  }

  // Remote ① silent button:
  // - short press: alarm_signal to siblings only (no local siren here).
  // - long press: pause/stop siren (local + siblings siren_off fan-out via API).
  if (!fired && now - lastTriggerSilentReadAt >= BUTTON_DEBOUNCE_MS) {
    lastTriggerSilentReadAt = now;
    bool level = (digitalRead(REMOTE_SILENT_BUTTON_GPIO) == HIGH);
    bool fallingEdge = (triggerSilentPrevLevel && !level);
    bool risingEdge = (!triggerSilentPrevLevel && level);
    triggerSilentPrevLevel = level;
    if (fallingEdge) {
      triggerSilentPressed = true;
      triggerSilentPressAt = now;
    } else if (risingEdge && triggerSilentPressed) {
      unsigned long heldMs = now - triggerSilentPressAt;
      triggerSilentPressed = false;
      if (heldMs >= REMOTE_SILENT_LONG_PRESS_MS) {
        logLine("[trigger] remote_pause_button");
        deactivateSiren();
        publishAlarmEvent("remote_pause_button", false);
        publishHeartbeatEvent("alarm_remote_pause");
        fired = true;
      } else if (!alarmInCooldown()) {
        logLine("[trigger] remote_silent_button");
        publishAlarmEvent("remote_silent_button", false);
        publishHeartbeatEvent("alarm_remote_silent");
        fired = true;
      }
    }
  }

  // Remote ② loud: siren_on to siblings only (this unit stays quiet by design).
  if (!fired && now - lastTriggerRemoteReadAt >= BUTTON_DEBOUNCE_MS) {
    lastTriggerRemoteReadAt = now;
    bool level = (digitalRead(REMOTE_LOUD_BUTTON_GPIO) == HIGH);
    bool fallingEdge = (triggerRemotePrevLevel && !level);
    triggerRemotePrevLevel = level;
    if (fallingEdge && !alarmInCooldown()) {
      logLine("[trigger] remote_loud_button");
      publishAlarmEvent("remote_loud_button", false);
      publishHeartbeatEvent("alarm_remote_loud");
      fired = true;
    }
  }
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

  {
    esp_reset_reason_t __rr = esp_reset_reason();
    resetReasonStr = decodeResetReason(__rr);
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
    crocDoubleExtResetTapUpdate(__rr);
    g_resetByExternal = (__rr == ESP_RST_EXT);
#if WIFI_PROVISION_RST_INCLUDING_POWERON
    if (__rr == ESP_RST_POWERON) {
      g_resetByExternal = true;
    }
#endif
    if (g_doubleExtRstProvision) {
      logLine("[wifi] double external reset detected: setup AP allowed this boot");
    }
#endif
  }
  buildDeviceId();

  pinMode(SIREN_GPIO, OUTPUT);
  pinMode(STATUS_LED_GPIO, OUTPUT);
  pinMode(PANIC_BUTTON_GPIO, INPUT_PULLUP);
  pinMode(REMOTE_LOUD_BUTTON_GPIO, INPUT_PULLUP);
  pinMode(REMOTE_SILENT_BUTTON_GPIO, INPUT_PULLUP);
  digitalWrite(SIREN_GPIO, SIREN_OFF);
  digitalWrite(STATUS_LED_GPIO, LOW);
  // Sync edge-detector baseline to actual pin (assumes NO switch to GND + pull-up: idle HIGH).
  delay(10);
  triggerDirectPrevLevel = (digitalRead(PANIC_BUTTON_GPIO) == HIGH);
  triggerRemotePrevLevel = (digitalRead(REMOTE_LOUD_BUTTON_GPIO) == HIGH);
  triggerSilentPrevLevel = (digitalRead(REMOTE_SILENT_BUTTON_GPIO) == HIGH);
  triggerSilentPressed = !triggerSilentPrevLevel;
  triggerSilentPressAt = millis();
  {
    char tline[180];
    const char *silentIdle = triggerSilentPrevLevel ? "HIGH" : "LOW";
    snprintf(
      tline,
      sizeof(tline),
      "[boot] panic=%d(%s) rem②_loud=%d(%s) rem①_silent=%d(%s)",
      PANIC_BUTTON_GPIO, triggerDirectPrevLevel ? "HIGH" : "LOW",
      REMOTE_LOUD_BUTTON_GPIO, triggerRemotePrevLevel ? "HIGH" : "LOW",
      REMOTE_SILENT_BUTTON_GPIO, silentIdle
    );
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

  {
    char line[384];
    snprintf(line, sizeof(line),
             "[boot] fw=%s id=%s mac=%s zone=%s rst=%s boot#%lu prov=%s brd=%s",
             FW_VERSION, deviceId, deviceMac, deviceZone, resetReasonStr,
             (unsigned long)bootCount, isProvisioned ? "y" : "n", BOARD_PROFILE_NAME);
    logLine(line);
    snprintf(line, sizeof(line), "[boot] mqtt_user=%s qr=%s", mqttUser, deviceQrCode);
    logLine(line);
    if (strlen(accessorySn) > 0) {
      snprintf(line, sizeof(line), "[boot] accessory_sn=%s", accessorySn);
      logLine(line);
    }
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
#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  g_wifiMultiRegisterAps();
  if (g_wifiMultiApCount == 0) {
#if WIFI_PROVISION_REQUIRE_DOUBLE_RST
    logLine("[net] no STA creds: press board RST twice (while powered) to open setup AP.");
#else
    logLine("[net] no STA creds: press board RST once, or twice for double-tap path.");
#endif
    if (provisioningPortalManualBootAllowed()) {
      logLine("[net] opening setup AP (manual / double-RST)");
      provisioningPortalStart();
    }
  } else {
    unsigned long waitStart = millis();
    while (!netIf->connected() && millis() - waitStart < WIFI_CONNECT_WAIT_MS) {
      twdtFeedMaybe();
      if (g_wifiMultiTrySliceJoin()) break;
      Serial.print('.');
      delay(20);
    }
    Serial.println();
    if (!netIf->connected()) {
      logLine("[net] STA join failed this boot (wrong password, AP missing, or RF); will retry in loop");
    }
  }
  if (g_wifiMultiApCount > 0 && !netIf->connected()) {
    if (provisioningPortalManualBootAllowed()) {
      logLine("[net] opening setup AP (manual / double-RST)");
      provisioningPortalStart();
    } else {
#if WIFI_PROVISION_REQUIRE_DOUBLE_RST
      logLine("[net] no STA link: reconnecting saved Wi-Fi (press RST twice for setup AP).");
#else
      logLine("[net] no STA link: reconnecting saved Wi-Fi (RST once or twice for setup AP).");
#endif
    }
  }
#else
  {
    unsigned long waitStart = millis();
    while (!netIf->connected() && millis() - waitStart < WIFI_CONNECT_WAIT_MS) {
      twdtFeedMaybe();
      delay(WIFI_MULTI_RUN_SLICE_MS);
      Serial.print('.');
    }
    Serial.println();
  }
#endif

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

#if (NETIF_MODE == NETIF_MODE_WIFI || NETIF_MODE == NETIF_MODE_AUTO) && \
    !defined(CONFIG_IDF_TARGET_ESP32P4)
  if (g_provActive) {
    provisioningPortalLoop();
    digitalWrite(STATUS_LED_GPIO, ((now / 400) & 1) ? HIGH : LOW);
    delay(5);
    return;
  }
#endif

  // Physical triggers before ensureWiFi/ensureMqtt/publishStatus so one loop
  // is not stuck behind slow STA or 5s status cadence.
  handleTriggerInput();

  // Run MQTT before Wi-Fi may block for seconds; avoids broker keepalive
  // timeouts while STA is re-associating.
  if (netIf->connected() && mqttClient.connected()) {
    mqttClient.loop();
  }

  ensureWiFi();
  ensureMqtt();

  if (mqttClient.connected()) {
    mqttClient.loop();
    processPendingMqttCommand();
    processPendingWifiChain();
    flushOfflineQueue();
    if (s_mqttPostConnectPublish) {
      s_mqttPostConnectPublish = false;
      publishStatus();
      publishHeartbeatEvent("mqtt_connected");
    }
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

  flushNvsIfNeeded();
  confirmOtaIfHealthy();

  // Only fire on a real Unix deadline; sub-1.7e9 values are legacy millis mistakes.
  // Never compare a Unix deadline to tsNow()'s millis() fallback (pre-NTP).
  if (scheduledRebootArmed && scheduledRebootEpoch >= 1700000000UL && ntpSynced &&
      epochNow() >= scheduledRebootEpoch) {
    logLine("[sched] reboot deadline reached");
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
