# 密码离线找回 — **公钥**（可部署在 VPS）

1. 在离线机运行 `password_recovery_offline/gen_rsa_keys.py`，会在本目录生成 `private.pem`（**绝不提交 Git、绝不放服务器**）与 `public.pem`。
2. 把 **`public.pem` 全文**配置到 API 环境变量：
   - `PASSWORD_RECOVERY_PUBLIC_KEY_PATH=/path/to/public.pem`  
   或  
   - `PASSWORD_RECOVERY_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"`
3. 私钥只放在你掌握的离线目录 `password_recovery_offline/`，用于解密用户从网页复制的 `recovery_blob_hex`。  
   用户可见的是**十六进制**：字符数 ≈ **2 × `blob_byte_len`**（默认约 **1602** 字符），复制时必须完整、无空格。
