#!/usr/bin/env python3
"""Tk GUI: factory serials + QR PNGs; optional POST /factory/devices."""
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

_PACK = Path(__file__).resolve().parent
if str(_PACK) not in sys.path:
    sys.path.insert(0, str(_PACK))

from factory_core import (  # noqa: E402
    append_pending_push_queue,
    build_output_dir_name,
    DEFAULT_FACTORY_UI_API_BASE,
    default_dotenv_path,
    drain_pending_push_queue,
    FACTORY_PUBLIC_HTTP_PORT,
    generate_items,
    get_factory_ping,
    load_pending_push_queue,
    normalize_factory_api_base,
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
        self.title("Croc Sentinel · 出厂工具")
        self.geometry("960x780")
        self.minsize(800, 620)

        self._dotenv_path = tk.StringVar(value=str(default_dotenv_path()))
        self._api_base = tk.StringVar(value=DEFAULT_FACTORY_UI_API_BASE)
        self._factory_token = tk.StringVar()
        self._batch = tk.StringVar(value=f"GUI_{int(time.time())}")
        self._count = tk.IntVar(value=3)
        self._auto_push = tk.BooleanVar(value=True)
        self._insecure = tk.BooleanVar(value=False)
        self._last_out: Path | None = None
        self._conn_status = tk.StringVar(value="未检测 · 请点击「测试连接」")
        self._resolved_ping = tk.StringVar(value="")

        self._apply_style()

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill=tk.BOTH, expand=True)

        # —— 连接状态（与服务器是否通）——
        stat_fr = ttk.LabelFrame(outer, text="服务器连接", padding=10)
        stat_fr.pack(fill=tk.X, pady=(0, 8))
        row_s = ttk.Frame(stat_fr)
        row_s.pack(fill=tk.X)
        self._lbl_status = ttk.Label(row_s, textvariable=self._conn_status, font=("Segoe UI", 10))
        self._lbl_status.pack(side=tk.LEFT, anchor=tk.W)
        ttk.Label(
            stat_fr,
            textvariable=self._resolved_ping,
            foreground="#1565c0",
            font=("Consolas", 9),
            wraplength=900,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, fill=tk.X, pady=(6, 0))

        deploy = ttk.LabelFrame(outer, text="端口说明（必读）", padding=(10, 8))
        deploy.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(
            deploy,
            text=(
                f"• 本仓库 docker-compose 把容器内 8088 映射到宿主机端口 {FACTORY_PUBLIC_HTTP_PORT}（不是把 8088 暴露到公网）。\n"
                "• FACTORY_UI_API_BASE 填「API 根」，不要带 /factory；Traefik 示例：https://域名/api\n"
                "• 若 ping 超时 (WinError 10060)：多为防火墙、错端口（常见误用 :8088）、或 VPS 未映射 18999。\n"
                "• 控制台 SPA 与出厂工具都应指向同一可达的 API 根（浏览器 Network 里成功的 origin）。"
            ),
            foreground="#444",
            justify=tk.LEFT,
            wraplength=900,
        ).pack(anchor=tk.W)

        cfg = ttk.LabelFrame(outer, text="密钥与 API（与 croc_sentinel_systems/.env 一致）", padding=10)
        cfg.pack(fill=tk.X, pady=(0, 8))

        r0 = ttk.Frame(cfg)
        r0.pack(fill=tk.X, pady=2)
        ttk.Label(r0, text=".env 路径", width=14).pack(side=tk.LEFT)
        ttk.Entry(r0, textvariable=self._dotenv_path).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 8))
        ttk.Button(r0, text="浏览…", command=self._browse_dotenv, width=10).pack(side=tk.LEFT)

        self._api_presets = (
            DEFAULT_FACTORY_UI_API_BASE,
            f"http://127.0.0.1:{FACTORY_PUBLIC_HTTP_PORT}",
            "https://esasecure.com/api",
        )
        r1 = ttk.Frame(cfg)
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="API 根地址", width=14).pack(side=tk.LEFT)
        self._api_combo = ttk.Combobox(
            r1,
            textvariable=self._api_base,
            values=self._api_presets,
            width=52,
        )
        self._api_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 6))
        ttk.Button(
            r1,
            text=f":8088 → :{FACTORY_PUBLIC_HTTP_PORT}",
            command=self._swap_compose_port,
            width=18,
        ).pack(side=tk.LEFT)

        hint_api = (
            "下拉可选预设；若手动填 IP，请与服务器实际放行端口一致（compose 默认 "
            f"{FACTORY_PUBLIC_HTTP_PORT}）。误填 :8088 会导致连接超时。"
        )
        ttk.Label(cfg, text=hint_api, foreground="#555", wraplength=860, justify=tk.LEFT).pack(
            anchor=tk.W, pady=(4, 0)
        )

        r2 = ttk.Frame(cfg)
        r2.pack(fill=tk.X, pady=6)
        ttk.Label(r2, text="Factory Token", width=14).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self._factory_token, show="*").pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0)
        )

        batch_fr = ttk.LabelFrame(outer, text="批次生成", padding=10)
        batch_fr.pack(fill=tk.X, pady=(0, 8))

        r3 = ttk.Frame(batch_fr)
        r3.pack(fill=tk.X, pady=2)
        ttk.Label(r3, text="批次 batch", width=14).pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self._batch, width=28).pack(side=tk.LEFT, padx=(4, 24))
        ttk.Label(r3, text="数量").pack(side=tk.LEFT)
        ttk.Spinbox(r3, from_=1, to=2000, textvariable=self._count, width=10).pack(side=tk.LEFT, padx=(8, 0))

        r4 = ttk.Frame(batch_fr)
        r4.pack(fill=tk.X, pady=(6, 2))
        ttk.Checkbutton(r4, text="生成后登记到服务器（POST /factory/devices）", variable=self._auto_push).pack(
            side=tk.LEFT
        )
        ttk.Checkbutton(r4, text="跳过 HTTPS 证书校验", variable=self._insecure).pack(side=tk.LEFT, padx=(16, 0))

        ttk.Label(
            batch_fr,
            text="导出: 仓库 factory_serial_exports/output_<时间戳>/ · manifest.csv · png/ · factory_devices_bulk.json · BATCH_ID.txt",
            foreground="#555",
            wraplength=860,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(6, 0))

        btn_row = ttk.Frame(outer)
        btn_row.pack(fill=tk.X, pady=(0, 6))
        for text, cmd, pad in (
            ("加载 .env", self._load_env, (0, 6)),
            ("测试连接", self._ping_async, (0, 6)),
            ("生成", self._run_async, (0, 6)),
            ("验证二维码…", self._verify_dialog, (0, 6)),
            ("打开导出目录", self._open_last_export, (0, 6)),
            ("复制导出路径", self._copy_last_path, (0, 6)),
            ("清空日志", self._clear_log, (0, 0)),
        ):
            ttk.Button(btn_row, text=text, command=cmd).pack(side=tk.LEFT, padx=pad)

        log_fr = ttk.LabelFrame(outer, text="运行日志（一行一条）", padding=(8, 6))
        log_fr.pack(fill=tk.BOTH, expand=True)

        log_wrap = ttk.Frame(log_fr)
        log_wrap.pack(fill=tk.BOTH, expand=True)
        log_wrap.grid_columnconfigure(0, weight=1)
        log_wrap.grid_rowconfigure(0, weight=1)
        xscroll = ttk.Scrollbar(log_wrap, orient=tk.HORIZONTAL)
        yscroll = ttk.Scrollbar(log_wrap)
        self._log = tk.Text(
            log_wrap,
            height=18,
            wrap=tk.NONE,
            font=("Consolas", 9),
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set,
            undo=False,
        )
        self._log.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        yscroll.config(command=self._log.yview)
        xscroll.config(command=self._log.xview)

        self._ping_lock = threading.Lock()
        self._api_base.trace_add("write", lambda *_: self.after(60, self._refresh_resolved_ping_label))
        self._load_env()

    def _effective_api_base(self, dot: Path) -> str:
        raw_ui = self._api_base.get().strip()
        env = read_dotenv_keys(dot, ("FACTORY_UI_API_BASE",))
        env_b = (env.get("FACTORY_UI_API_BASE") or "").strip()
        merged = raw_ui or env_b
        return normalize_factory_api_base(merged)

    def _refresh_resolved_ping_label(self) -> None:
        dot = Path(self._dotenv_path.get())
        api = self._effective_api_base(dot)
        if api:
            mis = ":8088" in api and "127.0.0.1" not in api and "localhost" not in api.lower()
            warn = "  [!] 常见误配：compose 对外是 :18999 而非 :8088" if mis else ""
            self._resolved_ping.set(f"实际请求: GET {api}/factory/ping{warn}")
        else:
            self._resolved_ping.set("实际请求: （填写 API 根或 .env 中 FACTORY_UI_API_BASE）")

    def _swap_compose_port(self) -> None:
        raw = self._api_base.get()
        if ":8088" not in raw:
            messagebox.showinfo(
                "提示",
                f"当前地址里没有 :8088。\n若连接超时，请改为宿主机映射端口 :{FACTORY_PUBLIC_HTTP_PORT}（见上方说明）。",
            )
            return
        self._api_base.set(raw.replace(":8088", f":{FACTORY_PUBLIC_HTTP_PORT}", 1))
        self._refresh_resolved_ping_label()
        self._line(f"[ui] replaced :8088 → :{FACTORY_PUBLIC_HTTP_PORT} in API base")

    def _apply_style(self) -> None:
        try:
            self.call("tk", "scaling", 1.08)
        except tk.TclError:
            pass
        style = ttk.Style(self)
        if sys.platform == "win32":
            style.theme_use("vista")
        else:
            style.theme_use("clam")
        style.configure("TLabelframe", padding=(10, 8))
        style.configure("TButton", padding=(8, 5))

    def _browse_dotenv(self) -> None:
        p = filedialog.askopenfilename(title="选择 .env", filetypes=[("env", "*.env"), ("All", "*.*")])
        if p:
            self._dotenv_path.set(p)

    def _clear_log(self) -> None:
        self._log.delete("1.0", tk.END)

    def _line(self, msg: str) -> None:
        """One logical line (no embedded newlines — split caller side)."""
        self._log.insert(tk.END, msg.rstrip("\r\n") + "\n")
        self._log.see(tk.END)

    def _lines(self, prefix: str, text: str, *, max_lines: int = 80) -> None:
        """Split server body into one log line each."""
        parts = text.replace("\r\n", "\n").split("\n")
        for i, ln in enumerate(parts[:max_lines]):
            s = ln.strip()
            if not s and i > 0:
                continue
            self._line(f"{prefix}{s}")
        if len(parts) > max_lines:
            self._line(f"{prefix}… ({len(parts) - max_lines} more lines omitted)")

    def _set_status(self, text: str) -> None:
        self._conn_status.set(text)

    def _browse_dotenv_path_display(self, dot: Path) -> None:
        env = read_dotenv_keys(dot, ("QR_SIGN_SECRET", "FACTORY_API_TOKEN", "FACTORY_UI_API_BASE"))
        if env.get("FACTORY_UI_API_BASE", "").strip():
            self._api_base.set(normalize_factory_api_base(env["FACTORY_UI_API_BASE"].strip()))
        if env.get("FACTORY_API_TOKEN") and not self._factory_token.get().strip():
            self._factory_token.set(env["FACTORY_API_TOKEN"].strip())
        qs = "yes" if env.get("QR_SIGN_SECRET") else "NO"
        ft = env.get("FACTORY_API_TOKEN") or ""
        fs = "yes" if ft.strip() else "NO"
        flen = len(ft.strip())
        ab = "yes" if (env.get("FACTORY_UI_API_BASE") or "").strip() else "NO"
        self._line(f"[env] path={dot}")
        self._line(f"[env] QR_SIGN_SECRET={qs}")
        self._line(f"[env] FACTORY_API_TOKEN={fs} len={flen}")
        self._line(f"[env] FACTORY_UI_API_BASE={ab}")

    def _load_env(self) -> None:
        dot = Path(self._dotenv_path.get())
        self._browse_dotenv_path_display(dot)
        self._set_status("已从 .env 加载 · 请点击「测试连接」确认服务器")
        self._refresh_resolved_ping_label()

    def _set_last_out(self, p: Path) -> None:
        self._last_out = p

    def _open_last_export(self) -> None:
        if not self._last_out or not self._last_out.is_dir():
            messagebox.showinfo("提示", "尚无导出目录；请先生成一批。")
            return
        _open_path_in_os(self._last_out)

    def _copy_last_path(self) -> None:
        if not self._last_out:
            messagebox.showinfo("提示", "尚无导出路径。")
            return
        self.clipboard_clear()
        self.clipboard_append(str(self._last_out.resolve()))
        self._line(f"[clipboard] {self._last_out}")

    def _run_async(self) -> None:
        threading.Thread(target=self._run_job, daemon=True).start()

    def _ping_async(self) -> None:
        threading.Thread(target=self._ping_job, daemon=True).start()

    def _ping_job(self) -> None:
        def ui(fn, *a, **kw):
            self.after(0, lambda: fn(*a, **kw))

        if not self._ping_lock.acquire(blocking=False):
            self._line("[ping] skipped (already running)")
            return
        try:
            dot = Path(self._dotenv_path.get())
            env = read_dotenv_keys(dot, ("FACTORY_API_TOKEN", "FACTORY_UI_API_BASE"))
            api = self._effective_api_base(dot)
            tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
            if not api or not tok:
                ui(messagebox.showwarning, "缺少配置", "请填写 API 根地址与 Factory Token（或写入 .env）。")
                ui(self._set_status, "失败 · 缺少 API 或 Token")
                return
            ui(self._refresh_resolved_ping_label)
            ui(self._set_status, f"检测中… {api}")
            ui(self._line, f"[ping] GET {api}/factory/ping")
            ui(self._line, f"[ping] token_len={len(tok)}")
            code, body = get_factory_ping(api, tok, insecure_ssl=self._insecure.get())
            ui(self._line, f"[ping] http_status={code}")
            ui(self._lines, "[ping] body | ", body)
            if code in (200, 201):
                ui(self._set_status, f"已连接 · {api}")
                ui(messagebox.showinfo, "连接正常", "服务器已接受 FACTORY_API_TOKEN。")
            else:
                ui(self._set_status, f"失败 · HTTP {code}")
                ui(messagebox.showerror, "连接失败", f"HTTP {code}\n{body[:1200]}")
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
            ui(self._line, "[gen] start")
            ui(self._line, f"[gen] count={n}")
            ui(self._line, f"[gen] batch={batch}")
            items = generate_items(n, secret, batch)
            out = repo_root() / "factory_serial_exports" / build_output_dir_name(len(items))
            write_batch_files(out, items, batch, qr_secret=secret)
            (out / "BATCH_ID.txt").write_text(batch + "\n", encoding="utf-8")
            ui(self._set_last_out, out)
            ui(self._line, f"[gen] output_dir={out}")
            ui(self._line, "[gen] qr_verify=all_ok")

            if self._auto_push.get():
                api = self._effective_api_base(dot)
                tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
                if not api:
                    ui(messagebox.showwarning, "未登记", "未填写 API 根地址，仅生成本地文件。")
                    ui(self._set_status, "仅本地导出（未推送）")
                    return
                if not tok:
                    ui(messagebox.showerror, "错误", "登记需要 FACTORY_API_TOKEN。")
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
                    ui(self._line, f"[retry] queue_before={queued_before}")
                    ui(self._line, f"[retry] drained={drained}")
                    ui(self._line, f"[retry] remain={len(load_pending_push_queue(queue_path))}")
                    for a in attempts:
                        ui(self._line, f"[retry] batch={a.get('batch')} code={a.get('code')} ok={a.get('ok')}")
                ui(self._line, f"[push] url={api}/factory/devices")
                ui(self._line, f"[push] token_len={len(tok)}")
                code, body = post_factory_devices(api, tok, items, insecure_ssl=self._insecure.get())
                ui(self._line, f"[push] http_status={code}")
                ui(self._lines, "[push] body | ", body)
                ok = code in (200, 201)
                status_file = write_push_status_file(out, batch, items, code, body, pushed_ok=ok, retry_attempt=0)
                ui(self._line, f"[push] status_json={status_file}")
                if ok:
                    first = str(items[0].get("serial") or "")
                    qr0 = str(items[0].get("qr_code") or "")
                    base = api.rstrip("/")
                    qparam = urllib.parse.quote(qr0 if qr0 else first, safe="")
                    dash = f"{base}/dashboard/#/activate?q={qparam}"
                    ui(self._line, "[push] ok=1")
                    ui(self._line, f"[link] activate_url={dash}")
                    ui(self._set_status, f"已登记 · {api}")
                    ui(
                        messagebox.showinfo,
                        "完成",
                        f"已登记 {len(items)} 条。\n导出目录:\n{out}",
                    )
                else:
                    qlen = append_pending_push_queue(
                        queue_path, batch, items, reason=f"HTTP {code}: {body[:500]}"
                    )
                    ui(self._line, f"[queue] path={queue_path}")
                    ui(self._line, f"[queue] size={qlen}")
                    ui(self._set_status, f"登记失败 · HTTP {code}")
                    hint = ""
                    if code == 403:
                        hint = (
                            "\n\n403: 核对服务器 FACTORY_API_TOKEN；改 .env 后 docker compose restart api。"
                        )
                    ui(messagebox.showerror, "登记失败", f"HTTP {code}\n{body[:800]}{hint}")
            else:
                ui(self._line, "[push] skipped auto_push=0")
                ui(self._set_status, "仅本地导出")
                ui(messagebox.showinfo, "完成", f"已生成 {len(items)} 条（未推送）。\n{out}")
        except Exception as e:
            ui(self._line, f"[err] {e!r}")
            ui(self._set_status, "出错")
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
        d.geometry("640x260")
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
