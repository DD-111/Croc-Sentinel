# 出厂序列号 / 二维码导出目录

本目录用于存放 **`tools/factory_pack`** 脚本生成的批次文件（CSV + PNG 二维码），方便你**单独拷贝到 U 盘**带去产线。

## 生成

在仓库根目录执行（需先 `pip install -r tools/factory_pack/requirements.txt`）：

```bash
python tools/factory_pack/generate_serial_qr.py --count 100 --qr-secret "与服务器 .env 中 QR_SIGN_SECRET 完全一致"
```

可选：`--out factory_serial_exports/output_20260417`、`--batch BATCH001`

## 导入服务器

将生成的 `factory_devices_bulk.json` 通过 `POST /factory/devices`（`X-Factory-Token` 或 superadmin JWT）导入，与线上一致。
