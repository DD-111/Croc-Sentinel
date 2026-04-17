# 设备配置与 OTA 升级说明（固件 / NVS）

## 中文

- **OTA 只更新应用程序分区**（Arduino / ESP-IDF 的 `app0` / `app1` 对滚）。  
- **NVS（`Preferences` 命名空间）与 Wi‑Fi 校准等数据在独立分区**，正常 OTA **不会**像“恢复出厂”那样被清空。
- 因此：**每台设备自己的配置**（例如 NVS 里的 `serial`、`dev_id`、MQTT 凭据、`cmd_key`、区域、OTA 中间态 `ota_cid` 等）在**成功 OTA 后一般会原样保留**。
- **会丢失配置的典型情况**只有：整片 Flash 擦除、换分区表、换 NVS 布局、手动 `erase_flash`、或固件里主动 `nvs_erase_all` / 改命名空间逻辑导致不兼容。

## English

- **OTA replaces only the application image**. NVS lives in a separate flash region, so **per-device settings stored in NVS usually survive an OTA**, including factory `serial`, claimed `dev_id`, MQTT creds, `cmd_key`, zone, and OTA campaign markers.
- **You lose everything** only on full-chip erase, partition-table changes, incompatible NVS schema migrations, or explicit erase code in firmware.

If you need a field to **always** survive major upgrades, keep it in NVS with a versioned key schema and migration logic in `setup()`.
