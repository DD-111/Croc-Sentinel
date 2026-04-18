# 出厂序列号 / 二维码导出目录

本目录用于存放 **`tools/factory_pack`** 脚本生成的批次文件（CSV + PNG 二维码），方便你**单独拷贝到 U 盘**带去产线。

## 自动生成两条密钥（贴进服务器 `.env`）

无需 openssl，在仓库根目录：

```bash
python tools/factory_pack/gen_factory_secrets.py
```

把输出的 **`QR_SIGN_SECRET`**、**`FACTORY_API_TOKEN`** 复制到 **`croc_sentinel_systems/.env`**，自行补一行 **`FACTORY_UI_API_BASE=https://...:8088`**，然后 **`docker compose restart api`**。

## 生成

在仓库根目录执行（需先 `pip install -r tools/factory_pack/requirements.txt`）：

**推荐（密钥不写进 shell 历史）：** 在 `croc_sentinel_systems/.env` 里配置好 `QR_SIGN_SECRET`，然后不传 `--qr-secret`，脚本会**自动读取**该文件：

```bash
python tools/factory_pack/generate_serial_qr.py --count 5 --batch TEST001
```

或显式指定 env 路径：

```bash
python tools/factory_pack/generate_serial_qr.py --count 5 --dotenv croc_sentinel_systems/.env --batch TEST001
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

部署新版 API 后，可用 **`GET /factory/ping`** + 头 **`X-Factory-Token`** 验证 Token 是否生效（**`factory_ui`「测试 API+Token」** 即调用此接口）。

浏览器激活页支持深链预填：`#/activate?q=<序列号或整段CROC|...>`（需已登录）。

## 图形界面（简易 UI）

仓库根目录执行（需已安装 `tools/factory_pack/requirements.txt`）：

```bash
python tools/factory_pack/factory_ui.py
```

填写 **API 根地址**（如 `https://IP:8088`）、确认 **Factory Token** 与 **`.env` 路径**，勾选 **「生成后自动登记」**，即可：**本地 PNG+JSON** 与 **`factory_devices` 表** 一步完成；之后在 Dashboard **激活设备**里扫码/输序列号做 **`/provision/identify`** 验证即可。

## 导入服务器

将生成的 `factory_devices_bulk.json` 通过 `POST /factory/devices`（`X-Factory-Token` 或 superadmin JWT）导入，与线上一致。
