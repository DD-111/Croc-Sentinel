#!/usr/bin/env python3
"""Simple Tk GUI: generate signed serials + QR PNGs, optionally auto-register on API."""
from __future__ import annotations

import sys
import threading
import time
import urllib.parse
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

# Allow `python tools/factory_pack/factory_ui.py` from repo root.
_PACK = Path(__file__).resolve().parent
if str(_PACK) not in sys.path:
    sys.path.insert(0, str(_PACK))

from factory_core import (  # noqa: E402
    append_pending_push_queue,
    DEFAULT_FACTORY_UI_API_BASE,
    default_dotenv_path,
    drain_pending_push_queue,
    generate_items,
    get_factory_ping,
    load_pending_push_queue,
    post_factory_devices,
    read_dotenv_keys,
    repo_root,
    verify_qr_local,
    write_push_status_file,
    write_batch_files,
)


class FactoryApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Croc Sentinel — 出厂序列号 / 二维码")
        self.geometry("720x560")
        self.minsize(640, 480)

        root = repo_root()
        self._dotenv_path = tk.StringVar(value=str(default_dotenv_path()))
        self._api_base = tk.StringVar(value=DEFAULT_FACTORY_UI_API_BASE)
        self._factory_token = tk.StringVar()
        self._batch = tk.StringVar(value=f"GUI_{int(time.time())}")
        self._count = tk.IntVar(value=3)
        self._auto_push = tk.BooleanVar(value=True)
        self._insecure = tk.BooleanVar(value=False)

        pad = {"padx": 8, "pady": 4}
        f = ttk.LabelFrame(self, text="配置（从 .env 自动填充 FACTORY_* / QR_SIGN_SECRET）")
        f.pack(fill=tk.X, **pad)

        r0 = ttk.Frame(f)
        r0.pack(fill=tk.X, **pad)
        ttk.Label(r0, text=".env 路径").pack(side=tk.LEFT)
        ttk.Entry(r0, textvariable=self._dotenv_path, width=56).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(r0, text="浏览…", command=self._browse_dotenv).pack(side=tk.LEFT)

        r1 = ttk.Frame(f)
        r1.pack(fill=tk.X, **pad)
        ttk.Label(r1, text="API 根地址", width=12).pack(side=tk.LEFT)
        ttk.Entry(r1, textvariable=self._api_base, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(
            f,
            text="默认 https://esasecure.com:8088（仅 API 根，不要带 /Croc_Sentinel_systems 或 /factory）；可被 .env 的 FACTORY_UI_API_BASE 覆盖",
            foreground="#555",
        ).pack(anchor=tk.W, padx=8)

        r2 = ttk.Frame(f)
        r2.pack(fill=tk.X, **pad)
        ttk.Label(r2, text="Factory Token", width=12).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self._factory_token, width=60, show="*").pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Label(
            f,
            text="与服务器 .env 中 FACTORY_API_TOKEN 一致；留空则尝试从 .env 读取",
            foreground="#555",
        ).pack(anchor=tk.W, padx=8)

        r3 = ttk.Frame(f)
        r3.pack(fill=tk.X, **pad)
        ttk.Label(r3, text="批次 batch", width=12).pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self._batch, width=24).pack(side=tk.LEFT)
        ttk.Label(r3, text="数量").pack(side=tk.LEFT, padx=(16, 4))
        sp = ttk.Spinbox(r3, from_=1, to=2000, textvariable=self._count, width=8)
        sp.pack(side=tk.LEFT)

        r4 = ttk.Frame(f)
        r4.pack(fill=tk.X, **pad)
        ttk.Checkbutton(r4, text="生成后自动登记到服务器（POST /factory/devices）", variable=self._auto_push).pack(
            side=tk.LEFT
        )
        ttk.Checkbutton(r4, text="跳过 HTTPS 证书校验（仅内网/自签测试）", variable=self._insecure).pack(
            side=tk.LEFT, padx=(16, 0)
        )

        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, **pad)
        ttk.Button(btn_row, text="重新加载 .env", command=self._load_env).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="测试 API+Token", command=self._ping_async).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="生成 +（可选）登记", command=self._run_async).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="仅验证二维码…", command=self._verify_dialog).pack(side=tk.LEFT, padx=4)

        ttk.Label(self, text="日志").pack(anchor=tk.W, padx=8)
        self._log = tk.Text(self, height=16, wrap=tk.WORD, font=("Consolas", 10))
        self._log.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self._load_env()

    def _browse_dotenv(self) -> None:
        p = filedialog.askopenfilename(
            title="选择 .env",
            filetypes=[("env", "*.env"), ("All", "*.*")],
        )
        if p:
            self._dotenv_path.set(p)

    def _append(self, s: str) -> None:
        self._log.insert(tk.END, s + "\n")
        self._log.see(tk.END)

    def _load_env(self) -> None:
        dot = Path(self._dotenv_path.get())
        env = read_dotenv_keys(dot, ("QR_SIGN_SECRET", "FACTORY_API_TOKEN", "FACTORY_UI_API_BASE"))
        if env.get("FACTORY_UI_API_BASE", "").strip():
            self._api_base.set(env["FACTORY_UI_API_BASE"].strip())
        if env.get("FACTORY_API_TOKEN") and not self._factory_token.get().strip():
            self._factory_token.set(env["FACTORY_API_TOKEN"].strip())
        ft = env.get("FACTORY_API_TOKEN") or ""
        self._append(
            f"[load] {dot}  QR_SECRET={'yes' if env.get('QR_SIGN_SECRET') else 'NO'}  "
            f"FACTORY_TOKEN={'yes' if ft.strip() else 'NO'}(len={len(ft.strip())})  "
            f"API_BASE={'set' if (env.get('FACTORY_UI_API_BASE') or '').strip() else 'NO'}"
        )

    def _run_async(self) -> None:
        threading.Thread(target=self._run_job, daemon=True).start()

    def _ping_async(self) -> None:
        threading.Thread(target=self._ping_job, daemon=True).start()

    def _ping_job(self) -> None:
        def ui(fn, *a, **kw):
            self.after(0, lambda: fn(*a, **kw))

        dot = Path(self._dotenv_path.get())
        env = read_dotenv_keys(dot, ("FACTORY_API_TOKEN", "FACTORY_UI_API_BASE"))
        api = self._api_base.get().strip().rstrip("/") or env.get("FACTORY_UI_API_BASE", "").strip().rstrip("/")
        tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
        if not api or not tok:
            ui(messagebox.showwarning, "缺少配置", "请填写 API 根地址与 Factory Token（或写入 .env）。")
            return
        code, body = get_factory_ping(api, tok, insecure_ssl=self._insecure.get())
        ui(self._append, f"[ping] GET /factory/ping -> HTTP {code}\n{body}")
        if code in (200, 201):
            ui(messagebox.showinfo, "连接正常", "FACTORY_API_TOKEN 已被服务器接受。")
        else:
            ui(messagebox.showerror, "失败", f"HTTP {code}\n{body[:600]}")

    def _run_job(self) -> None:
        def ui(fn, *a, **kw):
            self.after(0, lambda: fn(*a, **kw))

        try:
            dot = Path(self._dotenv_path.get())
            env = read_dotenv_keys(dot, ("QR_SIGN_SECRET", "FACTORY_API_TOKEN", "FACTORY_UI_API_BASE"))
            secret = (env.get("QR_SIGN_SECRET") or "").strip()
            if not secret:
                ui(messagebox.showerror, "错误", "未找到 QR_SIGN_SECRET，请在 .env 中配置。")
                return

            n = int(self._count.get())
            batch = self._batch.get().strip() or f"GUI_{int(time.time())}"
            ui(self._append, f"[gen] count={n} batch={batch}")
            items = generate_items(n, secret, batch)
            out = repo_root() / "factory_serial_exports" / f"output_{int(time.time())}"
            write_batch_files(out, items, batch)
            ui(self._append, f"[ok] 已写入: {out}")

            if self._auto_push.get():
                api = self._api_base.get().strip().rstrip("/")
                tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
                if not api:
                    ui(messagebox.showwarning, "未登记", "未填写 API 根地址，已只生成本地文件。")
                    return
                if not tok:
                    ui(messagebox.showerror, "错误", "需要 FACTORY_API_TOKEN（界面或 .env）才能登记。")
                    return
                queue_path = repo_root() / "factory_serial_exports" / "pending_push_queue.json"
                queued_before = len(load_pending_push_queue(queue_path))
                if queued_before:
                    drained, attempts = drain_pending_push_queue(
                        queue_path,
                        api,
                        tok,
                        insecure_ssl=self._insecure.get(),
                        max_batches=20,
                    )
                    ui(self._append, f"[retry] queue_before={queued_before} drained={drained} remain={len(load_pending_push_queue(queue_path))}")
                    for a in attempts:
                        ui(self._append, f"[retry] batch={a.get('batch')} code={a.get('code')} ok={a.get('ok')}")
                ui(self._append, f"[push] POST {api}/factory/devices  token_len={len(tok)}")
                code, body = post_factory_devices(
                    api, tok, items, insecure_ssl=self._insecure.get()
                )
                ui(self._append, f"[push] HTTP {code}\n{body}")
                ok = code in (200, 201)
                status_file = write_push_status_file(out, batch, items, code, body, pushed_ok=ok, retry_attempt=0)
                ui(self._append, f"[push] status file: {status_file}")
                if ok:
                    first = str(items[0].get("serial") or "")
                    qr0 = str(items[0].get("qr_code") or "")
                    base = api.rstrip("/")
                    qparam = urllib.parse.quote(qr0 if qr0 else first, safe="")
                    dash = f"{base}/dashboard/#/activate?q={qparam}"
                    ui(self._append, f"[link] 登录 Dashboard 后打开（预填激活框）:\n{dash}")
                    ui(
                        messagebox.showinfo,
                        "完成",
                        f"已登记 {len(items)} 条。\n\n下一步：浏览器登录控制台后打开「激活设备」，或复制日志里的 link 整行。\n\n{out}",
                    )
                else:
                    qlen = append_pending_push_queue(queue_path, batch, items, reason=f"HTTP {code}: {body[:500]}")
                    ui(self._append, f"[queue] pushed to retry queue: {queue_path} (size={qlen})")
                    hint = ""
                    if code == 403:
                        hint = (
                            "\n\n403 常见原因：\n"
                            "1) 服务器 croc_sentinel_systems/.env 里未设置 FACTORY_API_TOKEN，或改后未执行 docker compose restart api；\n"
                            "2) 本界面 / 本机 .env 里的 Token 与服务器那一行不完全一致（空格、换行、引号）。"
                        )
                    ui(messagebox.showerror, "登记失败", f"HTTP {code}\n{body[:800]}{hint}")
            else:
                ui(messagebox.showinfo, "完成", f"已生成 {len(items)} 条（未推送）。\n{out}")
        except Exception as e:
            ui(self._append, f"[err] {e!r}")
            ui(messagebox.showerror, "错误", str(e))

    def _verify_dialog(self) -> None:
        dot = Path(self._dotenv_path.get())
        env = read_dotenv_keys(dot, ("QR_SIGN_SECRET",))
        secret = (env.get("QR_SIGN_SECRET") or "").strip()
        if not secret:
            messagebox.showerror("错误", "需要 QR_SIGN_SECRET")
            return
        d = tk.Toplevel(self)
        d.title("验证二维码")
        d.geometry("640x200")
        ttk.Label(d, text="粘贴整行 CROC|...").pack(anchor=tk.W, padx=8, pady=4)
        txt = tk.Text(d, height=4, wrap=tk.NONE)
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        def go() -> None:
            q = txt.get("1.0", tk.END).strip()
            ok = verify_qr_local(q, secret)
            messagebox.showinfo("结果", "签名正确" if ok else "签名错误或格式不对")

        ttk.Button(d, text="验证", command=go).pack(pady=8)


def main() -> None:
    app = FactoryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
