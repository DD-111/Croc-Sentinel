#!/usr/bin/env python3
"""Simple Tk GUI: generate signed serials + QR PNGs, optionally auto-register on API."""
from __future__ import annotations

import os
import subprocess
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
    build_output_dir_name,
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


def _open_path_in_os(path: Path) -> None:
    path = path.resolve()
    if not path.exists():
        return
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        subprocess.run(["xdg-open", str(path)], check=False)


class FactoryApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Croc Sentinel — 出厂序列号 / 二维码")
        self.geometry("880x620")
        self.minsize(720, 520)

        self._apply_style()

        root = repo_root()
        self._dotenv_path = tk.StringVar(value=str(default_dotenv_path()))
        self._api_base = tk.StringVar(value=DEFAULT_FACTORY_UI_API_BASE)
        self._factory_token = tk.StringVar()
        self._batch = tk.StringVar(value=f"GUI_{int(time.time())}")
        self._count = tk.IntVar(value=3)
        self._auto_push = tk.BooleanVar(value=True)
        self._insecure = tk.BooleanVar(value=False)
        self._last_out: Path | None = None

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill=tk.BOTH, expand=True)

        cfg = ttk.LabelFrame(outer, text="配置（.env：QR_SIGN_SECRET / FACTORY_*）", padding=10)
        cfg.pack(fill=tk.X, pady=(0, 10))

        r0 = ttk.Frame(cfg)
        r0.pack(fill=tk.X, pady=2)
        ttk.Label(r0, text=".env 路径", width=14).pack(side=tk.LEFT)
        ttk.Entry(r0, textvariable=self._dotenv_path).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 8))
        ttk.Button(r0, text="浏览…", command=self._browse_dotenv, width=10).pack(side=tk.LEFT)

        r1 = ttk.Frame(cfg)
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="API 根地址", width=14).pack(side=tk.LEFT)
        ttk.Entry(r1, textvariable=self._api_base).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))
        ttk.Label(
            cfg,
            text="默认指向部署的 /api（Traefik StripPrefix）；不要拼接 /factory；可用 .env 的 FACTORY_UI_API_BASE 覆盖",
            foreground="#5a5a5a",
            wraplength=820,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(4, 0))

        r2 = ttk.Frame(cfg)
        r2.pack(fill=tk.X, pady=6)
        ttk.Label(r2, text="Factory Token", width=14).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self._factory_token, show="*").pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0)
        )

        batch_fr = ttk.LabelFrame(outer, text="批次与生成", padding=10)
        batch_fr.pack(fill=tk.X, pady=(0, 10))

        r3 = ttk.Frame(batch_fr)
        r3.pack(fill=tk.X, pady=2)
        ttk.Label(r3, text="批次 batch", width=14).pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self._batch, width=28).pack(side=tk.LEFT, padx=(4, 24))
        ttk.Label(r3, text="数量").pack(side=tk.LEFT)
        ttk.Spinbox(r3, from_=1, to=2000, textvariable=self._count, width=10).pack(side=tk.LEFT, padx=(8, 0))

        r4 = ttk.Frame(batch_fr)
        r4.pack(fill=tk.X, pady=(8, 2))
        ttk.Checkbutton(r4, text="生成后自动 POST /factory/devices", variable=self._auto_push).pack(side=tk.LEFT)
        ttk.Checkbutton(r4, text="跳过 HTTPS 证书校验（内网/自签）", variable=self._insecure).pack(
            side=tk.LEFT, padx=(16, 0)
        )

        hint = ttk.Label(
            batch_fr,
            text="导出目录：仓库根下 factory_serial_exports/output_<Unix时间戳>/，内含 manifest.csv、factory_devices_bulk.json、png/、README_BATCH.txt、BATCH_ID.txt",
            foreground="#5a5a5a",
            wraplength=820,
            justify=tk.LEFT,
        )
        hint.pack(anchor=tk.W, pady=(6, 0))

        btn_row = ttk.Frame(outer)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        for text, cmd, pad in (
            ("重新加载 .env", self._load_env, (0, 6)),
            ("测试 API + Token", self._ping_async, (0, 6)),
            ("生成（可选登记）", self._run_async, (0, 6)),
            ("验证二维码…", self._verify_dialog, (0, 6)),
            ("打开上次导出文件夹", self._open_last_export, (0, 6)),
            ("复制上次路径", self._copy_last_path, (0, 0)),
        ):
            ttk.Button(btn_row, text=text, command=cmd).pack(side=tk.LEFT, padx=pad)

        log_fr = ttk.LabelFrame(outer, text="日志", padding=(8, 6))
        log_fr.pack(fill=tk.BOTH, expand=True)

        log_wrap = ttk.Frame(log_fr)
        log_wrap.pack(fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(log_wrap)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._log = tk.Text(
            log_wrap,
            height=14,
            wrap=tk.WORD,
            font=("Consolas", 10),
            yscrollcommand=scroll.set,
            undo=False,
        )
        self._log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=self._log.yview)

        self._ping_lock = threading.Lock()
        self._load_env()

    def _apply_style(self) -> None:
        try:
            self.call("tk", "scaling", 1.1)
        except tk.TclError:
            pass
        style = ttk.Style(self)
        if sys.platform == "win32":
            style.theme_use("vista")
        else:
            style.theme_use("clam")
        style.configure("TLabelframe", padding=(10, 8))
        style.configure("TButton", padding=(10, 6))

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

    def _set_last_out(self, p: Path) -> None:
        self._last_out = p

    def _open_last_export(self) -> None:
        if not self._last_out or not self._last_out.is_dir():
            messagebox.showinfo("提示", "尚无本次会话内的导出目录；请先生成一批。")
            return
        _open_path_in_os(self._last_out)

    def _copy_last_path(self) -> None:
        if not self._last_out:
            messagebox.showinfo("提示", "尚无导出路径。")
            return
        self.clipboard_clear()
        self.clipboard_append(str(self._last_out.resolve()))
        self._append(f"[clipboard] {self._last_out}")

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

        if not self._ping_lock.acquire(blocking=False):
            ui(self._append, "[ping] skipped — test already running")
            return
        try:
            dot = Path(self._dotenv_path.get())
            env = read_dotenv_keys(dot, ("FACTORY_API_TOKEN", "FACTORY_UI_API_BASE"))
            api = self._api_base.get().strip().rstrip("/") or env.get("FACTORY_UI_API_BASE", "").strip().rstrip("/")
            tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
            if not api or not tok:
                ui(messagebox.showwarning, "缺少配置", "请填写 API 根地址与 Factory Token（或写入 .env）。")
                return
            ui(self._append, f"[ping] trying {api}/factory/ping …")
            code, body = get_factory_ping(api, tok, insecure_ssl=self._insecure.get())
            ui(self._append, f"[ping] GET /factory/ping -> HTTP {code}\n{body}")
            if code in (200, 201):
                ui(messagebox.showinfo, "连接正常", "FACTORY_API_TOKEN 已被服务器接受。")
            else:
                ui(messagebox.showerror, "失败", f"HTTP {code}\n{body[:900]}")
        finally:
            self._ping_lock.release()

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
            out = repo_root() / "factory_serial_exports" / build_output_dir_name(len(items))
            write_batch_files(out, items, batch, qr_secret=secret)
            (out / "BATCH_ID.txt").write_text(batch + "\n", encoding="utf-8")
            ui(self._set_last_out, out)
            ui(self._append, f"[ok] 已写入: {out}")
            ui(self._append, "[qr] policy+signature verification passed for all generated items")

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
                    ui(
                        self._append,
                        f"[retry] queue_before={queued_before} drained={drained} remain={len(load_pending_push_queue(queue_path))}",
                    )
                    for a in attempts:
                        ui(self._append, f"[retry] batch={a.get('batch')} code={a.get('code')} ok={a.get('ok')}")
                ui(self._append, f"[push] POST {api}/factory/devices  token_len={len(tok)}")
                code, body = post_factory_devices(api, tok, items, insecure_ssl=self._insecure.get())
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
                    qlen = append_pending_push_queue(
                        queue_path, batch, items, reason=f"HTTP {code}: {body[:500]}"
                    )
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
        d.geometry("640x240")
        d.minsize(480, 200)
        ttk.Label(d, text="粘贴整行 CROC|…").pack(anchor=tk.W, padx=12, pady=(10, 4))
        txt = tk.Text(d, height=5, wrap=tk.NONE, font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        def go() -> None:
            q = txt.get("1.0", tk.END).strip()
            ok = verify_qr_local(q, secret)
            messagebox.showinfo("结果", "签名正确" if ok else "签名错误或格式不对")

        bf = ttk.Frame(d)
        bf.pack(fill=tk.X, pady=(0, 12))
        ttk.Button(bf, text="验证", command=go).pack(side=tk.LEFT, padx=12)


def main() -> None:
    app = FactoryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
