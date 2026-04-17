# Croc-Sentinel Security Guide

## 1. OTA 固件放哪里

在你的 VPS 上用 nginx 做一个简单的固件下载目录，用 token 保护：

```nginx
# /etc/nginx/sites-enabled/sentinel-ota
server {
    listen 8070;

    location /fw/ {
        # Token check — must match config.h OTA_TOKEN
        if ($arg_token != "CHANGE_ME_OTA_SECRET") {
            return 403;
        }
        alias /opt/sentinel/firmware/;
        autoindex off;
    }
}
```

目录结构：
```
/opt/sentinel/firmware/
├── sentinel-v2.0.0.bin
├── sentinel-v2.1.0.bin    ← 最新版本
└── sentinel-v2.1.0.bin.sha256
```

### 发布新固件的步骤

```bash
# 1. Arduino IDE -> Sketch -> Export Compiled Binary
#    得到与 sketch 同名二进制，例如 Croc Sentinel.ino.esp32.bin

# 2. 上传到 VPS
scp "Croc Sentinel.ino.esp32.bin" root@your.vps:/opt/sentinel/firmware/sentinel-v2.1.0.bin

# 3. 生成校验和（可选，用于人工验证）
sha256sum sentinel-v2.1.0.bin > sentinel-v2.1.0.bin.sha256

# 4. 通过 MQTT 下发 OTA 给所有设备
mosquitto_pub -h your.vps.domain -u mqtt_user -P mqtt_pass \
  -t "sentinel/+/cmd" \
  -m '{"proto":2,"key":"A7F3B2E91C04D568","cmd":"ota","target_id":"all","params":{"url":"http://your.vps.domain:8070/fw/sentinel-v2.1.0.bin","fw":"2.1.0"}}'
```

### OTA 安全三层保护

1. **CMD_AUTH_KEY** — 命令本身需要 64-bit 密钥，否则设备直接拒绝
2. **OTA_ALLOWED_HOST** — 设备只接受你的 VPS 域名的 URL
3. **OTA_TOKEN** — 设备自动附加 token 到 URL，nginx 验证后才提供 .bin

### 命令协议与兼容

- 设备支持 `proto=1` 和 `proto=2`（上下兼容 2 个版本）
- 可发送 `get_cmd_table` 命令查看设备实际支持的命令清单
- 历史别名仍可用：`set_params`/`info`/`reboot_now`/`ota_update`

任何人即使拿到了 MQTT 访问权限，也无法：
- 没有 CMD_AUTH_KEY → 命令被拒绝
- 伪造 URL → 域名不匹配被拒绝
- 直接访问 /fw/ → 没有 token 被 nginx 403

## 2. 防止别人盗走烧录文件（flash 内容）

### 威胁场景

别人拿到你的 ESP32 硬件 → 用 esptool.py 读取 flash → 拿到完整固件 .bin → 反编译/盗用。

### 解决方案：ESP32 Flash Encryption + Secure Boot

```bash
# ---- 以下操作不可逆，先用开发板测试 ----

# 1. 开启 Flash Encryption (Development mode 可测试，Release mode 不可逆)
idf.py menuconfig
# → Security features → Enable flash encryption on boot
# → Security features → Enable Secure Boot V2

# 2. 编译并首次烧录
idf.py build flash

# 3. 第一次启动后 ESP32 会：
#    - 生成 AES-256 密钥写入 eFuse（一次性）
#    - 加密整个 flash
#    - 之后 esptool read_flash 读出来的是密文，无法使用

# 4. 禁用 JTAG（防调试器读取）
espefuse.py burn_efuse JTAG_DISABLE
```

### 如果你用 Arduino IDE（不用 ESP-IDF）

Arduino IDE 不直接支持 flash encryption。两个选项：

**选项 A（推荐）：用 ESP-IDF 做一次初始烧录**
1. 用 ESP-IDF 开启 flash encryption + secure boot
2. 之后 OTA 更新仍然可以用（OTA 固件会自动被加密）

**选项 B（简易版）：esptool 手动加密**
```bash
# 生成密钥
espsecure.py generate_flash_encryption_key my_flash_key.bin

# 烧录密钥到 eFuse
espefuse.py --port COM3 burn_key flash_encryption my_flash_key.bin

# 加密固件
espsecure.py encrypt_flash_data --keyfile my_flash_key.bin \
  --address 0x10000 --output encrypted.bin "Croc Sentinel.ino.bin"

# 烧录加密固件
esptool.py --port COM3 write_flash 0x10000 encrypted.bin
```

### 保护效果

| 攻击方式 | 未保护 | 有 Flash Encryption |
|---|---|---|
| esptool read_flash | 拿到完整明文 | 拿到密文，无法用 |
| JTAG 调试 | 可以读内存 | JTAG 已禁用 |
| 物理拆芯片 | 理论可行 | AES 密钥在 eFuse，无法提取 |

## 4. OTA 回退策略（生产环境建议）

设备已实现“启动健康确认 + 自动回退”：

1. OTA 开始时写入 `ota_pend` 状态
2. 新固件启动后进入“待验证”窗口（`OTA_HEALTH_CONFIRM_MS`）
3. 连续重启失败达到阈值（`OTA_MAX_BOOT_FAILS`）自动回退
4. 运行稳定后自动确认版本有效并清理 pending 状态

说明：
- 重启会清空 RAM，不需要额外手动“刷新内存”
- 广播告警不再明文携带密钥，改为签名字段 `sig`

## 3. 密钥管理

### 部署前必须修改的密钥（config.h）

| 密钥 | 用途 | 生成方法 |
|---|---|---|
| CMD_AUTH_KEY | 命令认证 | `openssl rand -hex 8` |
| OTA_TOKEN | OTA 下载认证 | `openssl rand -hex 16` |
| MQTT_USERNAME | MQTT broker 认证 | 自定义 |
| MQTT_PASSWORD | MQTT broker 认证 | `openssl rand -base64 24` |
| WIFI_PASSWORD | WiFi 接入 | 已有 |

### 密钥存放安全

- config.h 中的密钥会被编译进固件
- 开启 flash encryption 后，即使拿到硬件也无法提取
- 不要将 config.h 推送到公开 git 仓库（加入 .gitignore）
