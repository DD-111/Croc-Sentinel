#ifndef CONFIG_H
#define CONFIG_H

// Optional board overrides:
// #define FORCE_BOARD_PROFILE_PRODINO_ESP32_ETH
// #define FORCE_BOARD_PROFILE_WAVESHARE_ESP32_P4_ETH

#include "board_select.h"

// ── Firmware version (bump before each OTA release) ──
#define FW_VERSION "2.1.0"
// Production guardrails: set to 1 for strict startup validation.
#define PROD_ENFORCE 1
// Keep command compatibility with previous 2 protocol versions.
#define CMD_PROTO_MIN 1
#define CMD_PROTO_MAX 2

// ── Device ID mode ──
#define DEVICE_ID_AUTO 1
#define DEVICE_ID_MANUAL "esp32-001"

// ── Zone ──
#define DEVICE_ZONE "all"

// ── WiFi ──
#define WIFI_SSID "alan"
#define WIFI_PASSWORD "esa@349525"
#define WIFI_CONNECT_WAIT_MS 8000

// ── Network interface mode ──
// WIFI=1, ETHERNET=2, AUTO=3 (prefer Ethernet on ETH boards, fall back to WiFi).
// AUTO requires BOARD_HAS_ETH; on WiFi-only boards it collapses to WIFI.
#define NETIF_MODE_WIFI 1
#define NETIF_MODE_ETHERNET 2
#define NETIF_MODE_AUTO 3
#ifndef BOARD_HAS_ETH
#define BOARD_HAS_ETH 0
#endif
#ifndef NETIF_MODE
#ifdef BOARD_DEFAULT_NETIF_MODE
#define NETIF_MODE BOARD_DEFAULT_NETIF_MODE
#else
#define NETIF_MODE NETIF_MODE_AUTO
#endif
#endif
// Collapse AUTO to WIFI when the board has no Ethernet PHY.
#if NETIF_MODE == NETIF_MODE_AUTO && !BOARD_HAS_ETH
#undef NETIF_MODE
#define NETIF_MODE NETIF_MODE_WIFI
#endif

// ── MQTT broker / VPS ──
#define MQTT_HOST "76.13.187.100"
#define MQTT_PORT 18962
#define MQTT_USERNAME "sentinel_main"
#define MQTT_PASSWORD "fjLFL6Q6G6n/u6OT4Ptyx/x/eDdLAo5A"
#define MQTT_USE_TLS 1
#define MQTT_CLEAN_SESSION false
// Required when MQTT_USE_TLS=1 and PROD_ENFORCE=1.
// For CA rotation: keep primary old CA, secondary new CA during transition.
#define MQTT_CA_CERT_PRIMARY_PEM "-----BEGIN CERTIFICATE-----
MIIFFzCCAv+gAwIBAgIUfgl4PbZuAFWp6fYkHMGd3moUeBYwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQQ3JvYy1TZW50aW5lbC1DQTAeFw0yNjA0MTcwOTU1MDVa
Fw0zNjA0MTQwOTU1MDVaMBsxGTAXBgNVBAMMEENyb2MtU2VudGluZWwtQ0EwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKOowm7sNkNfmCDzeFoUKDHjHt
dPQHQQXsRe/YfovYeP6T+tpYDlivyV3NFKynXPWTIia1OjoX4YIQoj+4U9rpUOUz
gcdrhgL26Qa9QxXScPCqVChFnuVabmaMFI76zBKAxlXvZ8hrQtpc9RshpZISw+Dz
mFyx+oY0U6OROFJx7Y5IlOl2aPe+HMPCJfMC5xNMmnghgWZQhsG149vOGrE3D2ni
aWG8kcxne3+bppOCxHJUzZVgVxAhlxEQHBGkm1tvXCt8fAnYjO51HdM+ssRjLG3j
XppcFQjKDkZBAomHFBdhvaDxRrdS4qrMyioTatHli400iTM2vWrlO7EyL6yh//aV
ss0no2xram9EO7MWZmPEmZTkZIEf3RghWdrLtg7ynTR2VqGgJmfNCKo759wT72Cc
b8BAm+6Rb4VkEiQzTxn/uMHF/yTGfKAzMgzpVPJr08aoMS5ODZtTwrAGc78E/Zdo
XALG6UVT+jncu/60QlLdTscX7c7gybyHhfGPfZxV4DkAbhDa4/L+Fh14aDrL+wam
4tCzpWXt0nyfGmPidPDXmM39l1fFQ333cbMGHi/rjDycdz+jj0nFFDyhrmhMW592
yI++gghxJrLQgCPxai1l4PxeuVE0c5QWaBd9JgloQvS1ATYSiAQo+2VbOnwM+U1U
GZw3IOwOtGV0/j6d3QIDAQABo1MwUTAdBgNVHQ4EFgQU1Zi6nJ4/QWgsc3aGnC9x
91aFP68wHwYDVR0jBBgwFoAU1Zi6nJ4/QWgsc3aGnC9x91aFP68wDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAI6SgQ+nXhW2dvUOc2FdJeTXGMg+p
Zd+egJfvijgEipxovuKKunW2OsDQhojU7j2IYof8YcwVMZg44nmLf1lVSdLpDjsR
vjvSzRzLUhihSxpi/656vMMmwD989lP24fO6/TDXePmVFt6Kju/cbJYPoEqM9Nbg
4RQhxsZO29ID4uPy93i0DreuDOcgmIfGWls+P0jbSEAhnNLQF0nHDsHuO1m0fSps
U11i45/4NzmIogPIFiKcoqj4n7cNyCIWa0PesPwL9hS/BZpGoP2Agv5NTzdJnGUk
zhaz1a3KoQFiv2gSQ2Fe+CYbFP440Iwtazqg5fDbPa4d07TY1cnH5rZIzxwSuEsy
sQYcdGF/iumIGrn7Y1xff5ZI3A269Dv6zEsqCN2VYy+ckV3rKJkxe309VmrHfewu
aKOCI5LlwCGBsNA0/B+RjZpR2jz+lNYL3NDY8GBJ1epKGJNhycl9ej1/b1x9KJVT
cM/qS/O6YijTOZcbmwllEQYKNkqoRnGPR8CLkuNZd2GBu7mtz4FlT2BYnnGvfnXS
+vz4vbClvrF+D6cFZvUwTu3/3wg+Ip4NHgWYvd71elmRi5+5oPWA+c+Oa/+8fU6y
wwuzYZ8giCmbf++VC+iOG7tVY6qW4j55EVmPfG4bufodjQbvKR7I7UgJ82pdXOmu
wkFdjR+vR+oDBl8=
-----END CERTIFICATE-----"
#define MQTT_CA_CERT_SECONDARY_PEM ""
// Bootstrap credential used before dashboard claim/bind.
#define BOOTSTRAP_MQTT_USERNAME "sentinel_Boot"
#define BOOTSTRAP_MQTT_PASSWORD "UPRgbuI7SifHfKILM1AmPbDCh4FMdL7S"
// Shared bind key for bootstrap claim messages.
#define BOOTSTRAP_BIND_KEY "378c927479fe41de17c8f7ca07f7cbe009ae13d5abe43087"

// ── Ethernet PHY (used when NETIF_MODE == NETIF_MODE_ETHERNET) ──
#ifndef ETH_PHY_TYPE
#ifdef BOARD_ETH_PHY_TYPE
#define ETH_PHY_TYPE BOARD_ETH_PHY_TYPE
#else
#define ETH_PHY_TYPE ETH_PHY_LAN8720
#endif
#endif
#ifndef ETH_PHY_ADDR
#ifdef BOARD_ETH_PHY_ADDR
#define ETH_PHY_ADDR BOARD_ETH_PHY_ADDR
#else
#define ETH_PHY_ADDR 0
#endif
#endif
#ifndef ETH_MDC_PIN
#ifdef BOARD_ETH_MDC_PIN
#define ETH_MDC_PIN BOARD_ETH_MDC_PIN
#else
#define ETH_MDC_PIN 23
#endif
#endif
#ifndef ETH_MDIO_PIN
#ifdef BOARD_ETH_MDIO_PIN
#define ETH_MDIO_PIN BOARD_ETH_MDIO_PIN
#else
#define ETH_MDIO_PIN 18
#endif
#endif
#ifndef ETH_POWER_PIN
#ifdef BOARD_ETH_POWER_PIN
#define ETH_POWER_PIN BOARD_ETH_POWER_PIN
#else
#define ETH_POWER_PIN -1
#endif
#endif
#ifndef ETH_CLK_MODE
#ifdef BOARD_ETH_CLK_MODE
#define ETH_CLK_MODE BOARD_ETH_CLK_MODE
#else
#define ETH_CLK_MODE ETH_CLOCK_GPIO17_OUT
#endif
#endif

// ── Command authentication (64-bit hex key) ──
// ALL commands require this key. Change before deployment.
// Generate: openssl rand -hex 8   (produces 16 hex chars = 64 bits)
#define CMD_AUTH_KEY "A7F3B2E91C04D568"

// ── OTA firmware update ──
#define OTA_ENABLED 1
// Only accept OTA URLs starting with this prefix (your VPS).
// Set to "" to disable domain lock (not recommended in production).
#define OTA_ALLOWED_HOST "your.vps.domain"
// Token appended as query param: http://host/fw/v2.1.bin?token=XXX
// VPS nginx checks this token before serving the .bin file.
#define OTA_TOKEN "CHANGE_ME_OTA_SECRET"
// Mark OTA as healthy after continuous uptime.
#define OTA_HEALTH_CONFIRM_MS 20000UL
// Auto rollback after too many failed boots on new firmware.
#define OTA_MAX_BOOT_FAILS 3

// ── NTP ──
#define NTP_SERVER "pool.ntp.org"
#define NTP_GMT_OFFSET_S 0
#define NTP_DAYLIGHT_OFFSET_S 0
#define NTP_RESYNC_INTERVAL_MS 3600000UL

// ── Topics ──
// NOTE: Cross-device alarm fan-out is done by the API (server-side), so devices
// never subscribe to a global broadcast topic. Tenant isolation is enforced by
// the server (owner_admin). The legacy broadcast topic is left defined only for
// backward compatibility with very old firmware binaries.
#define TOPIC_ROOT "sentinel"
#define TOPIC_BROADCAST_ALARM "sentinel/broadcast/alarm"  // DEPRECATED, unused
#define TOPIC_BOOTSTRAP_REGISTER "sentinel/bootstrap/register"
#define TOPIC_BOOTSTRAP_ASSIGN_PREFIX "sentinel/bootstrap/assign"

// ── GPIO (board profile defaults, override per project if needed) ──
#ifndef SIREN_GPIO
#define SIREN_GPIO BOARD_DEFAULT_SIREN_GPIO
#endif
#ifndef TRIGGER_GPIO
#define TRIGGER_GPIO BOARD_DEFAULT_TRIGGER_GPIO
#endif
#ifndef STATUS_LED_GPIO
#define STATUS_LED_GPIO BOARD_DEFAULT_STATUS_LED_GPIO
#endif

// ── Behaviour ──
#define TRIGGER_SELF_SIREN 0
#define SIREN_ON_MS 8000
#define DEBOUNCE_MS 80
#define ALARM_COOLDOWN_MS 5000

// ── Task intervals (milliseconds) ──
// Heartbeat policy:
//   0 = PERIODIC  (legacy; one heartbeat every HEARTBEAT_INTERVAL_MS)
//   1 = EVENT     (DEFAULT for production fleets; heartbeat goes out only on
//                  state change, alarm, siren on/off, net reconnect, boot,
//                  OTA finish, and in response to a server `ping` probe.
//                  MQTT broker-level keepalive still detects TCP-loss.)
//   2 = HYBRID    (event-triggered but also a slow keepalive every
//                  HEARTBEAT_IDLE_KEEPALIVE_MS, default 15 min)
#define HEARTBEAT_MODE_PERIODIC 0
#define HEARTBEAT_MODE_EVENT 1
#define HEARTBEAT_MODE_HYBRID 2
#ifndef HEARTBEAT_MODE
#define HEARTBEAT_MODE HEARTBEAT_MODE_EVENT
#endif
// Used only when HEARTBEAT_MODE == HEARTBEAT_MODE_PERIODIC.
#define HEARTBEAT_INTERVAL_MS 2000
// Used only when HEARTBEAT_MODE == HEARTBEAT_MODE_HYBRID.
#define HEARTBEAT_IDLE_KEEPALIVE_MS 900000UL   // 15 min
// Minimum gap between two heartbeats regardless of mode — guards against
// event storms (e.g. flaky switch on TRIGGER_GPIO) melting the broker.
#define HEARTBEAT_MIN_INTERVAL_MS 1000
#define STATUS_INTERVAL_MS 5000
#define THROUGHPUT_WINDOW_MS 10000
#define WIFI_RECONNECT_BASE_MS 2000
#define MQTT_RECONNECT_BASE_MS 2000
#define RECONNECT_MAX_MS 60000

// ── Offline event queue ──
#define OFFLINE_QUEUE_MAX 20

// ── Power / signal thresholds ──
#ifndef BOARD_HAS_VBAT_ADC
#define BOARD_HAS_VBAT_ADC 0
#endif
#ifndef VBAT_SENSOR_ENABLED
#define VBAT_SENSOR_ENABLED BOARD_HAS_VBAT_ADC
#endif
#if VBAT_SENSOR_ENABLED
#ifndef VBAT_ADC_PIN
#define VBAT_ADC_PIN BOARD_DEFAULT_VBAT_ADC_PIN
#endif
#ifndef VBAT_ADC_ATTENUATION
#define VBAT_ADC_ATTENUATION BOARD_DEFAULT_ADC_ATTENUATION
#endif
#endif
#define VBAT_LOW_THRESHOLD 3.30f
#define RSSI_WEAK_THRESHOLD -75

// ── ADC calibration ──
#define ADC_MAX 4095.0f
#define ADC_VREF 3.30f
#define VBAT_DIVIDER_RATIO 2.00f
#define ADC_OVERSAMPLE 16

// ── Watchdog timeout (seconds) ──
#define WDT_TIMEOUT_S 30

// ── NVS ──
#define NVS_NAMESPACE "sentinel"

// ── Parameter validation bounds ──
#define PARAM_HB_MIN_MS 500
#define PARAM_HB_MAX_MS 60000
#define PARAM_ST_MIN_MS 1000
#define PARAM_ST_MAX_MS 300000
#define PARAM_SIREN_MIN_MS 500
#define PARAM_SIREN_MAX_MS 120000
#define PARAM_RSSI_MIN -100
#define PARAM_RSSI_MAX -20
#define PARAM_VBAT_MIN 2.0f
#define PARAM_VBAT_MAX 5.0f

// ── NVS write-wear protection ──
#define NVS_SAVE_COOLDOWN_MS 10000

// ── Bootstrap provisioning ──
#define BOOTSTRAP_REGISTER_INTERVAL_MS 10000
#define QR_DEFAULT_PREFIX "CROC"

// ── MQTT JSON buffer sizing ──
#define MQTT_RX_BUFFER_BYTES 2048
#define MQTT_JSON_DOC_BYTES 1536

#endif
