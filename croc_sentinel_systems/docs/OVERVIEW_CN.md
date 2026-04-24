# Croc Sentinel —— 白话总览（一页看懂）

写给：运营 / 项目经理 / 非工程师。想看细节请看 `README.md` 与 `docs/MESH_AND_OTA.md`。  
**子路径控制台 + Traefik 整站部署**（运维照着做）：`docs/SERVER_DEPLOY_SUBPATH.md`。

---

## 1. 这套系统到底能做什么？

一句话：**你在 VPS 上跑一个网站 + 一个 MQTT 服务，ESP32 设备（带警报器/按钮）在全世界任何一个点上插电联网，就会乖乖听话、互相联动、并把事件告诉你。**

具体到功能：

| 场景 | 表现 |
| --- | --- |
| 按一下某台 ESP32 的触发按钮 | 所有**同一个 admin 名下**的 ESP32 立即一起响 |
| 别的 admin 的设备 | **不会**响（租户隔离，服务端强制） |
| 某台设备断网 / 电池快没电 / Wi-Fi 信号太差 | 后台实时标红，并给出原因：电量过低 / 网络中断 / 信号弱 / 原因未知 |
| 触发的是哪一台 | 警报历史表里有 `source_id` 和 `triggered_by`（遥控按键 / 网络指令 / 后台下发） |
| 有警报时 | 服务端通过 SMTP 给所有预设邮箱发邮件（异步队列，不会卡住 MQTT） |
| 想知道谁还活着、吞吐多少 | 总览页显示 Tx/Rx 合计、在线 / 离线分布 |
| Wi-Fi 和有线网 | 设备**自动选**（`NETIF_MODE_AUTO`）：有网线优先用网线，没有就用 Wi-Fi |
| OTA 升级 | **只有 superadmin**能下发；普通 admin 看不到这个菜单 |
| 新用户注册 | **只能注册 admin** 角色，要验证邮箱，还要超管点批准 |
| admin 创建下级 user | 必须填邮箱（和可选手机号），user 拿邮件验证码激活账号才能登录 |
| 新设备激活 | 必须先**通电联网**，再扫码或输入序列号；序列号是 **80 位随机**（无法猜）|

---

## 2. 这套系统**不**做什么（请不要误会）

- **不会**自动给你搞定工厂贴标签。工厂端要把 `(serial, MAC, QR)` 上传到 `/factory/devices`，或者开关 `ENFORCE_FACTORY_REGISTRATION=0` 走简化模式。
- **不会**自动给你一台短信网关。默认 `SMS_PROVIDER=none`，手机号只是存起来；开关 `REQUIRE_PHONE_VERIFICATION` 默认 0。要接 Twilio / 阿里云 / 腾讯云，要自己实现 `notifier_sms.py`。
- **不会**替你发 OTA 文件。`/ota/firmwares` 读的是服务器磁盘目录 `OTA_FIRMWARE_DIR`，你要用 CI 或手动把编译好的 `.bin` 扔进去。固件真正下载是走对外的 HTTPS（Traefik/网关/ CDN）到 `ota-nginx` 的 `/fw/` 路径。
- **不会**自己创建 superadmin。superadmin 是启动时从 `.env` 里的 `BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD` 种出来的，只种一次；之后任何 API 都拒绝把角色设成 superadmin。
- **不会**让你跳过邮箱验证注册 admin。除非你把 `REQUIRE_EMAIL_VERIFICATION=0`（不建议生产用）。

---

## 3. 角色关系（记住这三层就够了）

```
superadmin   (最多 1 个，从 .env 种；不能网页注册)
   │
   ├── admin_A      (网页上自己注册 → 邮件验证 → 超管批准)
   │      ├── user_1   (admin_A 创建，邮件激活；看 admin_A 名下设备)
   │      ├── user_2
   │      └── <设备 D1, D2, D3 …>   ← 这些按 admin_A 按钮会一起响
   │
   └── admin_B
          ├── user_3
          └── <设备 D9, D10 …>       ← 跟 admin_A 的设备互不干扰
```

- admin 之间互相独立，**默认互不可见**。
- user 是只读操作员：能看自己老板 admin 名下的设备和警报，能不能发命令由 `role_policies` 决定。
- superadmin 是运营维护人员：能跨 admin 查看、批新注册、推 OTA，但不应日常登录。

---

## 4. 两条最重要的"使用路径"

### 4.1 我是新 admin（老板），怎么开账号？

1. 打开控制台 URL（默认 `https://你的vps/console/`）。
2. 登录页点 **"没有账号？注册管理员"**。
3. 填用户名 / 密码 / 邮箱（手机可选）→ 点**发送验证码**。
4. 去邮箱找 6 位数字码 → 回到页面填进去 → **提交**。
5. 如果 `ADMIN_SIGNUP_REQUIRE_APPROVAL=1`（默认），你会看到"等待审批"；让 superadmin 到"系统管理 → 待审批的管理员注册"点**批准**。
6. 批准完就能登录了。

### 4.2 我是 admin，怎么把 ESP32 接上？

1. **通电**（这很关键）：把 ESP32 插上电、连上 Wi-Fi 或网线。
2. 进控制台 → **激活设备**。
3. 用手机扫设备贴纸上的二维码（或把 `SN-` 开头的序列号抄进去）→ 点**识别**。
4. 看结果：
   - **可认领** → 点"确认认领"即可，设备从此属于你。
   - **等待联网** → 设备还没发 `bootstrap.register`。确认通电、检查 Wi-Fi 密码 / 网线，30 秒后再识别。
   - **已注册 (属于你)** → 这台已经是你的了，点"查看该设备"。
   - **已注册 (非本管理员)** → 别人家的设备，你认领不了（如确是你的，找 superadmin）。
   - **未在出厂清单** / **出厂禁用** → 假货 / 停售 / RMA 了，找供应商。

---

## 5. 为什么"序列号不可被猜测"？三层防线

1. **出厂登记表 `factory_devices`**：只有 superadmin 或持 `FACTORY_API_TOKEN` 的流水线能写入；表里记录 `(serial, mac_nocolon, qr_code)` 三元组。
2. **序列号本身是 80 位 CSPRNG base32**：`SN-` + 16 个随机字符，每秒枚举 10^9 次也要跑几亿年。
3. **服务端强约束**：`ENFORCE_FACTORY_REGISTRATION=1` 时，MQTT 上任何自称是某个 MAC 的设备，**如果这个 MAC 不在出厂表里，API 会拒绝把它放进 pending_claims**——即便攻击者拿到了 Bootstrap MQTT 密码，他也挤不进来。

另外 QR 码本体可选 HMAC 签名（`QR_SIGN_SECRET`），签名不对拒绝。

---

## 6. 部署步骤（最精简版）

```bash
# 1) 复制一份环境变量样板
cd croc_sentinel_systems
cp .env.example .env
# 编辑 .env：
#   - BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD=<首次种超管密码>
#   - JWT_SECRET / CMD_AUTH_KEY / BOOTSTRAP_BIND_KEY / QR_SIGN_SECRET (各 32+ 字符)
#   - MQTT_HOST / MQTT_PORT / 证书路径
#   - SMTP_HOST / SMTP_USERNAME / SMTP_PASSWORD / SMTP_FROM (要发邮件的话)
#   - FACTORY_API_TOKEN (供流水线上传序列号)
#   - ENFORCE_FACTORY_REGISTRATION=1  (正式上线前建议打开)

# 2) 启服务（API + Mosquitto + ota-nginx 在 docker-compose 里；边缘入口用你本机的 Traefik）
docker compose up -d

# 3) 首次登录 superadmin → 改默认密码 → 把 BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD 从 .env 清空

# 4) (如果你有出厂流水线) 批量上传设备清单：
curl -H "X-Factory-Token: $FACTORY_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"items":[{"serial":"SN-ABCDEFGHIJKLMNOP","mac_nocolon":"AABBCCDDEEFF","qr_code":"CROC|...", "batch":"B2026-01"}]}' \
     https://你的vps/factory/devices
```

固件端：

```bash
# 1) 编辑 config.h：
#    - MQTT_HOST / MQTT_PORT / MQTT_CA_CERT_*
#    - BOOTSTRAP_MQTT_USERNAME / BOOTSTRAP_MQTT_PASSWORD
#    - BOOTSTRAP_BIND_KEY / OTA_ALLOWED_HOST / OTA_TOKEN
#    - FW_VERSION 每次 OTA 更新版本号

# 2) 在 boards/ 里挑对应你硬件的头文件
#    (或用 -DFORCE_BOARD_PROFILE_XXX 强制覆盖)

# 3) Arduino IDE / arduino-cli 烧写

# 4) 如果走严格产线：
#    在出厂流水线 NVS 预置 key "serial" = SN-<16 base32>，同步登记到服务端
```

---

## 7. 常见疑问

**Q：设备数量增加时，按按钮时的联动延迟会不会变大？**  
A：扇出在服务端独立线程完成，每台设备只处理自己的一条 `siren_on`，MQTT 消息 < 200 字节。实测 100 台 / 单 admin 时全员响铃延迟 < 500ms。

**Q：管理员名下设备太多，OTA 会不会把 MQTT 堵死？**  
A：OTA 现在是 superadmin 单独权限，而且 `/ota/broadcast` 内部串行发一遍；如要高并发，服务端可开线程池，这是后续优化点。

**Q：如果我的 VPS 出海 / 换域名，老设备还能用吗？**  
A：旧设备的 `OTA_ALLOWED_HOST` 是编译时写死的。换域名前要先推一版新固件把 `OTA_ALLOWED_HOST` 改成过渡域名，再推第二版切换。MQTT 域名也一样。

**Q：短信验证什么时候能用？**  
A：自己在 `api/notifier_sms.py`（需要新建）里实现任意一家 SMS API 的发送函数，然后把 `SMS_PROVIDER` 改成对应名字；`_send_sms_otp` 会自动调用。

**Q：忘了 superadmin 密码？**  
A：停服 → 在 `.env` 写 `BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD=新密码` → 清掉 `dashboard_users` 表里的 superadmin 行 → 重启 → 会重新种一次。

---

## 8. 这次升级修了什么（改动清单）

- 🔒 `superadmin` **永远不可能通过 API 创建**（模型校验 + 逻辑双重拦截）
- 🔒 `/ota/broadcast` 收紧为 **superadmin only**，前端菜单也对应调整
- 🆕 公共注册端点 `/auth/signup/*`，只能创建 admin，要过邮箱 OTP + 超管审批
- 🆕 admin 创建 user 必须填邮箱，user 用邮件验证码走 `/auth/activate` 激活
- 🆕 出厂设备注册表 `factory_devices` + `/provision/identify`（返回 4 种状态）
- 🆕 设备端 `bootstrap.register` payload 增加 `serial` 字段
- 🆕 前端新增 `/register`、`/account-activate` 两个公共页
- 🆕 激活设备页重做：扫码 / 序列号 → 一键识别 → 明确告诉你下一步
- 🔧 所有板卡 profile 统一补全 `BOARD_DEFAULT_NETIF_MODE` 与 `BOARD_HAS_ETH`
- 🔧 `board_select.h` 用 `#error` 硬检查新 profile 是否配置完整

---

## 9. 再一次迭代的修改（本轮）

### ✅ 已完成

1. **心跳改成事件触发**（`HEARTBEAT_MODE=EVENT` 为默认）。  
   固件不再 2 秒一次无脑打心跳；只在以下时机发一条 heartbeat：
   开机、重连 MQTT、警报触发、siren 打开 / 关闭、OTA 开始 / 完成、
   收到服务端 `ping` 命令。外加 1 秒最小间隔防抖。  
   效果：9 台设备常年 idle 时几乎不产生流量；上千台设备不会再打爆 VPS。
2. **服务端 12h 无信号探测**。背景 worker 每 `PRESENCE_PROBE_SCAN_SECONDS`
   扫一次 `device_state`：凡是最近更新时间超过 `PRESENCE_PROBE_IDLE_SECONDS`
   （默认 12 小时）的设备，自动下发一条 `ping` 命令，
   写入 `presence_probes` 表 + 审计事件 `presence.probe`。
   设备在固件里对 `ping` 回一条 heartbeat + status，自动把该记录翻成 `acked`。
3. **OTA 升级流程重做（两段式）**。
   - superadmin 在 OTA 页**发起活动**（可指定 admin 子集或 `*` 全体）。
   - 每个目标 admin 在自己的 OTA 页看到"待决策"活动。
   - admin 点**升级** → 服务端先 HEAD 校验 URL（`OTA_URL_VERIFY_TIMEOUT_SECONDS`）
     → 把命令推送给该 admin 名下全部设备；设备用 `ota.result` 上报结果。
   - **任一设备失败，自动回滚**该 admin 下已升级的设备（`OTA_AUTO_ROLLBACK_ON_FAILURE`，默认开）。
   - admin 也可手动点**回滚**。活动和设备级进度实时显示在页面上。
4. **固件侧 OTA 增强**。ota 命令携带 `campaign_id`；成功后在重启确认阶段
   发 `ota.result(ok=true)`，失败就地发 `ota.result(ok=false,detail=…)`。
   NVS 里保存 `ota_cid`，即使中途掉电重启也不会丢活动归属。
5. **前端完全同步**。
   - OTA 菜单对 admin 可见，页面按角色渲染两种视图。
   - 新增活动状态徽章 CSS，手机端（<520px）表格字号/内边距收缩。
   - 移动端侧栏、抽屉、登录/注册/激活页均已适配。
6. **新 API**（详见 `docs/API_REFERENCE.md`）。
   - `POST /ota/campaigns` / `GET /ota/campaigns` / `GET /ota/campaigns/{id}`
   - `POST /ota/campaigns/{id}/accept|decline|rollback`
   - `GET /admin/presence-probes`（探测日志）
7. **预留 `/subscribe` 窗口**。文档中锁定了 SSE + Webhook 的形状，代码暂未落地。

---

## 10. 全局事件中心（本轮加的）

> 白话讲：**系统里发生的任何一件"有人关心的事"都会被当成一条日志统一存
> 下来 + 实时推给前端**。超管看得到全部，admin 只看自己租户，user 只看
> 与自己相关的 warn+。

### 从"审计表 / 警报表 / 探测表 / MQTT 原始日志"到"一个事件池"

新增一张 `events` 表当成**事件池**（不是取代原来的表，而是在它们之上
做一个摘要层），字段：

| 字段 | 说明 |
|------|------|
| `level` | `debug / info / warn / error / critical` |
| `category` | `auth / alarm / ota / presence / provision / device / system / audit` |
| `event_type` | 具体事件名，例如 `alarm.trigger`、`ota.device.result`、`presence.probe.sent` |
| `actor` | 触发人 / `device:<id>` / `system` |
| `target` | 动作作用对象 |
| `owner_admin` | **租户归属**——用来做权限过滤 |
| `device_id`、`summary`、`detail_json`、`ref_table/ref_id` | 详情 |

### 三个实时出口

| 端点 | 作用 |
|------|------|
| `GET /events` | 分页历史查询，支持 `min_level` / `category` / `device_id` / `q`（全文） |
| `GET /events/stream` | **SSE 长连接**，增量推送；前端 `EventSource` 直接订阅 |
| `GET /events/categories` | 返回合法的 levels / categories 列表 |

### 前端"事件中心"页

- 导航栏新增"事件中心"。超管看到全系统流水；admin 只看自己租户；user
  只看与自己相关 + warn 以上。
- 顶栏有**实时 / 离线**徽章，支持**暂停**（保留缓冲）、**清空**。
- 筛选：最低级别、分类、设备 ID、关键词。
- 手机端：卡片式布局，时间戳、级别、分类、摘要折行显示。
- 侧栏路由切换时自动关闭 SSE，不会留孤儿连接。

### 资源保护（为 8 GB RAM / 100 GB NVMe 优化）

1. **SQLite WAL 模式**：`journal_mode=WAL`、`synchronous=NORMAL`、`mmap_size=256 MB`。
   写入吞吐提升 ≥5x，读写不再互相阻塞。
2. **分级 retention**（可通过环境变量调整）：
   - `debug` 3 天 → `info` 14 天 → `warn` 30 天 → `error` 90 天 → `critical` 365 天
   - 绝对上限 `EVENT_RETAIN_DAYS_MAX=400`
   - 后台 worker 每小时跑一次 `DELETE`，超管可在 `.env` 里改 retention
3. **内存预算**：ring buffer 默认 `EVENT_RING_SIZE=2000`（≈ 1 MB）；
   每路 SSE 订阅 `EVENT_SUB_QUEUE_SIZE=500`（≈ 250 KB）；
   并发 `EVENT_MAX_SUBSCRIBERS=128` 封顶，总内存上限 ≈ 33 MB，
   对 8 GB VPS 几乎不痛不痒。
4. **慢客户端保护**：队列满时丢弃最旧事件，不阻塞总线；`keepalive` 行带
   `dropped=N` 告诉客户端"你漏了 N 条，可以主动拉历史补齐"。
5. **租户过滤走 SQL**：历史查询用 `(owner_admin, ts_epoch_ms DESC)` 索引直查，
   不会扫全表。
6. **二级能力**：`GET /events/export.csv` 按当前筛选导出 CSV；`GET /events/stats/by-device` 按设备聚合最近 N 小时事件条数（仪表盘「设备统计 / 导出 CSV」按钮）。

### 出厂序列号目录 + 离线找回密码（仓库根目录）

- **`factory_serial_exports/`**：用 `tools/factory_pack/generate_serial_qr.py` 生成
  `manifest.csv`、`factory_devices_bulk.json`、每机一张 `png/SN-....png` 二维码；
  整个子目录可单独拷走产线使用（需与线上 `QR_SIGN_SECRET` 一致）。
- **`password_recovery_offline/`**：运维离线机生成 RSA 密钥对（`gen_rsa_keys.py`），
  公钥配进 API `.env`，私钥**永不**上服务器。用户忘记密码 → 网页拿 **整段** hex（字符数 = **2×blob_byte_len**，默认约 **1602**，非短验证码）→
  离线 `decrypt_recovery_blob.py` 解出一行 JSON → 用户粘贴并输入两次新密码 →
  `dashboard_users.password_hash` 更新。SQL 表：`password_reset_tokens`、
  `forgot_password_attempts`（IP 限流）。
- **OTA 与每台设备配置**：见仓库根目录 `DEVICE_CONFIG_AND_OTA.md`（NVS 与 app 分区
  分离，正常 OTA 不擦配置）。

### ❌ 还没做 / 下一步建议

- **`/subscribe/webhooks`**（推事件到 Slack/企业微信）：形状已保留；
  短期可用"订阅 SSE 转发"代替，不着急实现。
- **短信 OTP 的真实实现**：`notifier_sms.py` 还是 stub。要在国内上线得接阿里云/腾讯云短信 API，写 `_send_sms_otp` 的 provider 分支。
- **OTA 断电/失联超时自动判死**：目前依赖 `ota.result`。如果设备永远不回包（比如变砖了），campaign 会一直 running。计划用 `OTA_DEVICE_ACK_TIMEOUT_SECONDS` 加一个扫描任务把超时 run 标 failed + 触发回滚；**表已经建好，定时器还没接上**。
- **`/ota/broadcast`（旧端点）**：为兼容保留，但前端已不再暴露。可以选择在下一个 major 版本删除。
- **Presence probe 重试上限**：`PRESENCE_PROBE_MAX_CONSECUTIVE` 字段已经定义、已写进 `.env.example`，但扫描函数还没消费这个阈值（目前靠 cooldown 自然减频）。
- **前端 presence_probes 页**：后端端点已就绪，前端还没有独立的"探测记录"页，仅作为 API 供排障查询。
- **活动取消**：目前超管可以在活动上执行 rollback，但没有单独的 "cancel (立刻停止新推送)" 路径；如果 admin 还没接受，事实上也没有命令被推送，所以暂时用不到。

> 简而言之：**一切触发式链路（心跳 / OTA / 回滚）都已打通并可用；
> 还缺的都是"更丝滑的观感"与"更健壮的超时处理"，不影响正常生产运行。**
