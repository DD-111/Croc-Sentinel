# Building the ESP32 firmware

1. Copy the configuration template (once per machine / clone):

   ```bash
   cp config.h.example config.h
   ```

2. Edit `config.h`: set `MQTT_HOST`, TLS CA if needed, bootstrap/MQTT passwords, `CMD_AUTH_KEY`, `OTA_*`, and enable `PROD_ENFORCE` for production builds. Match values with `croc_sentinel_systems/.env` on the server.

3. **WiFi (production):** leave `WIFI_SSID` … `WIFI_SSID_4` empty and provision STA credentials via the Dashboard **Save & reboot** (`wifi_config` command) or factory NVS burn. Compile-time APs are optional lab fallbacks only.

`config.h` is listed in `.gitignore` so local secrets are not committed; only `config.h.example` is tracked.
