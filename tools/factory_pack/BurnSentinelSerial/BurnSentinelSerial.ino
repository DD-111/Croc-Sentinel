/*
 * Croc Sentinel — factory one-shot: NVS "serial" (namespace from config.h).
 *
 * setup() returns quickly so ESP32 Arduino core / TWDT does not reset during
 * a long paste wait (some cores treat lengthy setup() as stuck).
 *
 * 切勿把主工程 Croc Sentinel.ino 粘贴进本文件。
 */
#include <Arduino.h>
#include <Preferences.h>
#include "config.h"

#ifndef SERIAL_DEFAULT
#define SERIAL_DEFAULT ""
#endif

static const char *kNvsKey = "serial";
static const unsigned long kPasteTimeoutMs = 90000UL;

static bool validSerial(const String &s) {
  if (s.length() < 19 || s.length() >= 24)
    return false;
  if (!s.startsWith("SN-"))
    return false;
  for (unsigned i = 3; i < s.length(); i++) {
    char c = s[i];
    bool ok = (c >= '2' && c <= '7') || (c >= 'A' && c <= 'Z');
    if (c == 'I' || c == 'O' || c == '0' || c == '1')
      ok = false;
    if (!ok)
      return false;
  }
  return true;
}

static bool writeSerialToNvs(const String &sn) {
  if (!validSerial(sn)) {
    Serial.println("[BurnSentinelSerial] ERROR: invalid serial format.");
    return false;
  }
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) {
    Serial.println("[BurnSentinelSerial] ERROR: NVS begin failed.");
    return false;
  }
  if (!p.putString(kNvsKey, sn)) {
    p.end();
    Serial.println("[BurnSentinelSerial] ERROR: putString failed.");
    return false;
  }
  p.end();

  Serial.print("[BurnSentinelSerial] OK NVS ");
  Serial.print(NVS_NAMESPACE);
  Serial.print("/");
  Serial.print(kNvsKey);
  Serial.print(" = ");
  Serial.println(sn);

  p.begin(NVS_NAMESPACE, true);
  String verify = p.getString(kNvsKey, "");
  p.end();
  if (verify != sn) {
    Serial.println("[BurnSentinelSerial] ERROR: read-back mismatch.");
    return false;
  }
  Serial.println("[BurnSentinelSerial] Read-back OK. Flash main firmware.");
  return true;
}

// 0=done success, 1=waiting paste, 2=failed
static uint8_t gState = 0;
static unsigned long gWaitStartedMs = 0;

void setup() {
  Serial.begin(115200);
  delay(800);

  String sn = String(SERIAL_DEFAULT);
  sn.trim();

  if (sn.length() > 0) {
    if (writeSerialToNvs(sn))
      gState = 0;
    else
      gState = 2;
    return;
  }

  Serial.println();
  Serial.println("[BurnSentinelSerial] Paste full serial (e.g. SN-653BSYV4WP6YAEJB) + Enter.");
  Serial.println("[BurnSentinelSerial] Waiting in loop() (not setup) — avoids watchdog reset. 90s timeout.");
  Serial.println("[BurnSentinelSerial] Or set #define SERIAL_DEFAULT \"SN-...\" and re-upload.");
  Serial.setTimeout(200);
  gWaitStartedMs = millis();
  gState = 1;
}

void loop() {
  if (gState == 0) {
    delay(60000);
    return;
  }
  if (gState == 2) {
    delay(10000);
    return;
  }

  // gState == 1: wait for paste
  if (Serial.available()) {
    String sn = Serial.readStringUntil('\n');
    sn.trim();
    if (writeSerialToNvs(sn)) {
      gState = 0;
    } else {
      gState = 2;
    }
    return;
  }
  if (millis() - gWaitStartedMs >= kPasteTimeoutMs) {
    Serial.println("[BurnSentinelSerial] ERROR: timeout, no serial pasted.");
    gState = 2;
    return;
  }
  delay(10);
  yield();
}
