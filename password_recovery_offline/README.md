# 密码离线找回 — 解密工具（仅运维离线机）

## 流程

1. 用户在登录页点「忘记密码」，输入用户名后得到 **一长串十六进制** `recovery_blob_hex`。  
   **字符数 = 2 × `blob_byte_len`**（接口 JSON 里会同时返回 `blob_byte_len` 与整段 `recovery_blob_hex`，便于核对是否复制全）。  
   在默认 **RSA-2048** 且 `PASSWORD_RECOVERY_PLAINTEXT_PAD=512` 时，`blob_byte_len` 一般为 **801**，对应 **1602** 个十六进制字符——**不是 64 位短码**。
2. 用户把该串发给你（微信 / 邮件 / 工单）。
3. 你在**不联网的电脑**上运行解密脚本（需 `private.pem`）：

```bash
pip install cryptography
python decrypt_recovery_blob.py --private ../password_recovery_keys/private.pem --hex "<粘贴整段hex>"
```

4. 终端会输出 **一行 JSON**（`recovery_plain`）。用户把它连同**两次新密码**填回网页「完成重置」表单。
5. API 校验 JSON 中的 `jti` / `s` 与数据库中未过期、未使用的记录一致后，写入 `dashboard_users.password_hash`（bcrypt）。

## 安全说明

- 服务器**只持有公钥**，没有私钥则无法伪造可用重置包。
- 假用户名也会返回随机 blob，长度与真请求一致，降低枚举风险。
- 默认令牌 TTL：`FORGOT_PASSWORD_TOKEN_TTL_SECONDS`（默认 24h）。

## 常见失败原因（运维对照）

| 现象 | 处理 |
|------|------|
| 解密脚本报 `invalid blob header` / 长度不对 | 用户只复制了前半段，或中间被 IM/邮件折行插入空格。让对方从网页**全选** `recovery_blob_hex` 再发；脚本侧可先去掉所有空白后 `hex` 解码。 |
| `invalid credentials` / 解密乱码 | 私钥与服务器上的**公钥不是一对**；或发错环境（测试/生产混用）。 |
| API 返回 `invalid or already-used recovery token` | 该 `jti` 已用过，或复制了**旧**一次生成的 hex。让用户重新点「获取编码」拿新包。 |
| `recovery token expired` | 超过 `FORGOT_PASSWORD_TOKEN_TTL_SECONDS`，需重新发起。 |
| 服务器 `503 password recovery not configured` | 未配置 `PASSWORD_RECOVERY_PUBLIC_KEY_PATH` / `_PEM`，或 PEM 不是 RSA 公钥。 |
