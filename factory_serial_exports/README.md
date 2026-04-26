# 出厂序列号 / 二维码导出目录

本目录用于存放 **`tools/factory_pack`** 脚本生成的批次文件（CSV + **`sn_qr.tsv`**（S/N 与整段 `CROC|…` 同列）+ PNG 二维码下方叠印 S/N），方便你**单独拷贝到 U 盘**带去产线。

## 自动生成两条密钥（贴进服务器 `.env`）

无需 openssl，在仓库根目录：

```bash
python tools/factory_pack/gen_factory_secrets.py
```

把输出的 **`QR_SIGN_SECRET`**、**`FACTORY_API_TOKEN`** 复制到 **`croc_sentinel_systems/.env`**，自行补一行 **`FACTORY_UI_API_BASE`**（公网经 Traefik 时用 **`https://你的域名/api`**，不要写 **`https://域名:8088`**），然后 **`docker compose restart api`**。仅本机直连容器时用例如 **`http://127.0.0.1:8088`**。

## 生成

在仓库根目录执行（需先 `pip install -r tools/factory_pack/requirements.txt`）：

**推荐（密钥不写进 shell 历史）：** 在 `croc_sentinel_systems/factory.env`（出厂专用，见 `factory.env.example`）里配置好 `QR_SIGN_SECRET`，然后不传 `--qr-secret`，脚本会**自动读取**该文件：

```bash
python tools/factory_pack/generate_serial_qr.py --count 5 --batch TEST001
```

或显式指定 env 路径：

```bash
python tools/factory_pack/generate_serial_qr.py --count 5 --dotenv croc_sentinel_systems/factory.env --batch TEST001
```

或临时传入（与服务器 **必须** 一致）：

```bash
python tools/factory_pack/generate_serial_qr.py --count 100 --qr-secret "与服务器 QR_SIGN_SECRET 完全一致"
```

**仅验证一条二维码**（与服务器同一套密钥）：

```bash
python tools/factory_pack/generate_serial_qr.py --verify-qr "CROC|SN-....|....|...."
```

二维码格式为 **`CROC|<serial>|<unix_ts>|<HMAC>`**，只有掌握 **`QR_SIGN_SECRET`** 的 API 才能校验签名（见 `api/app.py` 的 `verify_qr_signature`）。

可选：`--out factory_serial_exports/output_20260417`、`--batch BATCH001`

**一键生成并写入服务器数据库**（需 `.env` 里 `FACTORY_API_TOKEN`、`FACTORY_UI_API_BASE`，且与 `QR_SIGN_SECRET` 同源）：

```bash
python tools/factory_pack/generate_serial_qr.py --count 5 --batch TEST001 --push
```

**免每次手写 `--push`**：在 **`croc_sentinel_systems/.env`**（或 `--dotenv` 指向的文件）里设 **`FACTORY_AUTO_PUSH=1`** 且已配置 **`FACTORY_UI_API_BASE`** + **`FACTORY_API_TOKEN`**，则只运行：

```bash
python tools/factory_pack/generate_serial_qr.py --count 20 --batch LINE02
```

即会在写本地文件后 **自动 POST `/factory/devices`**。

**先测连通再量产**：

```bash
python tools/factory_pack/generate_serial_qr.py --ping
# 或指定 API 根（生产 Traefik）：  --api-base https://YOUR_HOST/api
```

部署新版 API 后，可用 **`GET /factory/ping`** + 头 **`X-Factory-Token`** 验证 Token 是否生效（**`factory_ui`「测试 API+Token」** 即调用此接口）。

浏览器激活页支持深链预填：`#/activate?q=<序列号或整段CROC|...>`（需已登录）。

## 服务器如何“认识”这台板子 / Register so the server accepts the device

在 **`ENFORCE_FACTORY_REGISTRATION=1`** 时，设备进 `pending_claims` 前必须在表 **`factory_devices`** 里有一条记录，且 **`serial` 或 `mac_nocolon`** 能对上 bootstrap 上报。

1. **生成批次时已 `--push`**：若 manifest 里该 SN 已在服务器，只需板子 NVS 写入同一 `SN-...` + MAC 与登记一致即可。  
2. **补登一条**（示例，把 `API`、`TOKEN`、MAC、整段 `qr_code` 换成你的）：

```bash
curl -sS -X POST "https://YOUR_HOST/api/factory/devices" \
  -H "Content-Type: application/json" \
  -H "X-Factory-Token: YOUR_FACTORY_API_TOKEN" \
  -d "{\"items\":[{\"serial\":\"SN-653BSYV4WP6YAEJB\",\"mac_nocolon\":\"AABBCCDDEEFF\",\"qr_code\":\"CROC|SN-653BSYV4WP6YAEJB|1776514219|....\",\"batch\":\"manual1\"}]}"
```

`mac_nocolon` 为板子 Wi‑Fi MAC **无冒号大写** 12 位；`qr_code` 与 `generate_serial_qr.py` 生成的 **`CROC|...`** 一致（或你策略允许的值）。确保服务器 `.env` 里 **`FACTORY_API_TOKEN`**、**`QR_SIGN_SECRET`** 已配置并已 **`docker compose restart api`**。

## 板子 NVS 烧 `serial`（与固件 `sentinel` 命名空间一致）

Arduino IDE 打开：**`tools/factory_pack/BurnSentinelSerial/BurnSentinelSerial.ino`**

- 在文件顶部把 **`SERIAL_DEFAULT`** 设为 `SN-...`，或留空、115200 串口下粘贴整行序列号后回车。  
- 烧录 → 串口出现 **`OK NVS sentinel/serial = ...`** 后，再烧录根目录 **`Croc Sentinel.ino`**，且**不要**勾选 **Erase Flash**。

## 图形界面（简易 UI）

仓库根目录执行（需已安装 `tools/factory_pack/requirements.txt`）：

```bash
python tools/factory_pack/factory_ui.py
```

填写 **API 根地址**（公网 Traefik：**`https://域名/api`**；本机直连：**`http://127.0.0.1:8088`**）、确认 **Factory Token** 与 **`.env` 路径**，勾选 **「生成后自动登记」**，即可：**本地 PNG+JSON** 与 **`factory_devices` 表** 一步完成；之后在 Dashboard **激活设备**里扫码/输序列号做 **`/provision/identify`** 验证即可。

## 导入服务器

将生成的 `factory_devices_bulk.json` 通过 `POST /factory/devices`（`X-Factory-Token` 或 superadmin JWT）导入，与线上一致。
