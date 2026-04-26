# 出厂便携目录 / Portable factory secrets

## `factory.env`（本目录）

- 放 **仅出厂** 需要的变量：`FACTORY_API_TOKEN`、`QR_SIGN_SECRET`（与 API 容器一致）。
- 此文件已被根目录 `.gitignore` 忽略，**不要**手动 `git add`。
- 整个 **`factory_portable` 文件夹** 可以复制到 U 盘；开发时留在仓库里也可，程序会**优先**读这里的 `factory.env`。

## 单独「炒」一份最小文件夹（推荐）

在任意位置新建文件夹，例如 `D:\CrocFactory\`，放入：

| 来源（仓库内） | 目标 |
|----------------|------|
| `tools/factory_pack/*.py` | 同一目录 |
| `tools/factory_pack/requirements.txt` | 同一目录 |
| `factory.env`（从 `factory_portable` 复制或按 `factory.env.example` 填写） | 与上面 **同一目录** |

在同一目录启动（`FACTORY_DOTENV_PATH` 指向该目录下的 `factory.env`）：

```powershell
cd D:\CrocFactory
$env:FACTORY_DOTENV_PATH = "D:\CrocFactory\factory.env"
pip install -r requirements.txt
python .\factory_ui.py
```

也可把仓库里的 `factory_portable/run_factory_ui.ps1` 拷到该目录，与 `factory_ui.py` 并列后执行（脚本会自动设 `FACTORY_DOTENV_PATH`）。

## 仍在仓库里开发时

解析顺序见 `factory_core.default_dotenv_path()`：`FACTORY_DOTENV_PATH` → `factory_portable/factory.env` → `croc_sentinel_systems/factory.env`。
