#!/usr/bin/env python3
"""Tk GUI: factory serials + signed QR PNGs + optional POST /factory/devices.

Phase-100 wizard rewrite
========================
Re-organised into a 4-step guided flow so a factory operator can run the
happy path top-to-bottom without hunting for buttons:

  Step 1 — Connection: load ``croc_sentinel_systems/factory.env`` (manufacturing-only),
           Factory Token (API host/port fixed in code),
           [Test connection]. Server metadata (qr_sign_required,
           cmd_proto, server_time, …) is shown so the operator can
           confirm they hit the right deployment.
  Step 2 — Batch config: batch label, count, auto-push toggle.
           Locked until Step 1 passes OR operator picks "local only".
  Step 3 — Generate + register: one big button + progressbar.
  Step 4 — Result: export dir, all activation links, copy-all button,
           inline QR verifier.

Heavy lifting (random_serial / sign_qr / write_batch_files /
post_factory_devices / drain_pending_push_queue / verify_qr_local) still
lives in ``factory_core.py``, so ``generate_serial_qr.py`` (CLI) and the
GUI remain wire-compatible with each other AND with the server.
"""
from __future__ import annotations

from collections import Counter
import json
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


# ---------------------------------------------------------------------------
# UI palette + helpers
# ---------------------------------------------------------------------------

PALETTE = {
    "bg": "#f6f8fb",
    "card_bg": "#ffffff",
    "border": "#dfe5ef",
    "title": "#101728",
    "muted": "#5a6478",
    "accent": "#1565c0",
    "ok": "#1b8a3a",
    "warn": "#b06a00",
    "err": "#b3261e",
    "step_locked_bg": "#f0f1f4",
    "step_locked_fg": "#9099a8",
}

# Human hints for POST /factory/devices per-item rejects (see routers/factory.py).
_FACTORY_REJECT_HINTS: dict[str, str] = {
    "invalid mac": "MAC 须为 12 位十六进制（无冒号）。",
    "qr_code missing": "服务器开启签名校验时，每条必须有 qr_code。",
    "qr_code policy": "二维码字符串不符合服务器 QR_CODE_REGEX（以 /factory/ping 返回为准）。",
    "qr_code signature": "HMAC 与服务器 QR_SIGN_SECRET 不一致：本地生成 .env 的 QR_SIGN_SECRET 必须与 API 容器一致。",
}


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


def _try_parse_json(raw: str) -> dict | None:
    try:
        obj = json.loads(raw or "")
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------


class FactoryApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Croc Sentinel · 出厂工具 · Factory Console")
        # Slightly larger default window so labels + log remain readable at bumped font sizes.
        self.geometry("1200x900")
        self.minsize(960, 700)
        self.configure(bg=PALETTE["bg"])

        # ----- State vars -----
        self._dotenv_path = tk.StringVar(value=str(default_dotenv_path()))
        self._factory_token = tk.StringVar()
        self._batch = tk.StringVar(value=f"GUI_{int(time.time())}")
        # Default to 1 unit per run (operators scale up explicitly when batching).
        self._count = tk.IntVar(value=1)
        self._auto_push = tk.BooleanVar(value=True)
        self._insecure = tk.BooleanVar(value=False)
        self._local_only = tk.BooleanVar(value=False)
        self._show_token = tk.BooleanVar(value=False)
        self._last_out: Path | None = None
        self._last_items: list[dict] | None = None
        self._connected = False
        self._busy = False

        # status label vars
        self._banner_text = tk.StringVar(value="未连接 / Not connected")
        self._banner_color = PALETTE["warn"]
        self._step1_status = tk.StringVar(value="未测试")
        self._server_meta = tk.StringVar(value="（连接前不显示服务器信息）")
        self._step3_progress = tk.IntVar(value=0)

        self._apply_style()
        self._build_layout()

        self._ping_lock = threading.Lock()
        self._local_only.trace_add("write", lambda *_: self._refresh_step_locks())

        self._load_env()
        self._refresh_step_locks()
        # Try a silent ping if env supplied both pieces — saves one click.
        if self._has_connection_inputs():
            self.after(400, self._ping_async)

    # -----------------------------------------------------------------------
    # Style
    # -----------------------------------------------------------------------

    def _apply_style(self) -> None:
        try:
            self.call("tk", "scaling", 1.22)
        except tk.TclError:
            pass
        s = ttk.Style(self)
        if sys.platform == "win32":
            s.theme_use("vista")
        else:
            s.theme_use("clam")
        s.configure("App.TFrame", background=PALETTE["bg"])
        s.configure("Card.TFrame", background=PALETTE["card_bg"], relief="solid", borderwidth=1)
        s.configure("Card.TLabel", background=PALETTE["card_bg"], foreground=PALETTE["title"], font=("Segoe UI", 12))
        s.configure(
            "Step.TLabel",
            background=PALETTE["card_bg"],
            foreground=PALETTE["title"],
            font=("Segoe UI", 14, "bold"),
        )
        s.configure(
            "StepLocked.TLabel",
            background=PALETTE["step_locked_bg"],
            foreground=PALETTE["step_locked_fg"],
            font=("Segoe UI", 14, "bold"),
        )
        s.configure(
            "Sub.TLabel",
            background=PALETTE["card_bg"],
            foreground=PALETTE["muted"],
            font=("Segoe UI", 11),
        )
        s.configure(
            "Banner.TLabel",
            background=PALETTE["bg"],
            font=("Segoe UI", 15, "bold"),
        )
        s.configure(
            "Mono.TLabel",
            background=PALETTE["card_bg"],
            foreground=PALETTE["muted"],
            font=("Consolas", 11),
        )
        s.configure("Primary.TButton", padding=(16, 10), font=("Segoe UI", 12, "bold"))
        s.configure("TButton", padding=(12, 8))
        s.configure("TLabelframe", background=PALETTE["card_bg"], padding=(12, 10))
        s.configure(
            "TLabelframe.Label",
            background=PALETTE["card_bg"],
            foreground=PALETTE["title"],
            font=("Segoe UI", 12, "bold"),
        )
        s.configure("TCheckbutton", background=PALETTE["card_bg"])
        s.configure("TRadiobutton", background=PALETTE["card_bg"])
        s.configure("TEntry", padding=4)
        s.configure("Horizontal.TProgressbar", thickness=14)

    # -----------------------------------------------------------------------
    # Layout
    # -----------------------------------------------------------------------

    def _build_layout(self) -> None:
        outer = ttk.Frame(self, padding=14, style="App.TFrame")
        outer.pack(fill=tk.BOTH, expand=True)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(5, weight=1)

        self._build_banner(outer, row=0)
        self._build_step1(outer, row=1)
        self._build_step2(outer, row=2)
        self._build_step3(outer, row=3)
        self._build_step4(outer, row=4)
        self._build_log(outer, row=5)

    # ----- Banner ----------------------------------------------------------

    def _build_banner(self, parent: ttk.Frame, row: int) -> None:
        bar = ttk.Frame(parent, style="App.TFrame")
        bar.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        bar.grid_columnconfigure(1, weight=1)
        ttk.Label(
            bar,
            text="Croc Sentinel · 出厂序列号 / 二维码生成器",
            style="Banner.TLabel",
        ).grid(row=0, column=0, sticky="w")
        self._banner_dot = tk.Label(
            bar,
            text="●",
            font=("Segoe UI", 16, "bold"),
            fg=self._banner_color,
            bg=PALETTE["bg"],
        )
        self._banner_dot.grid(row=0, column=2, sticky="e", padx=(0, 6))
        ttk.Label(bar, textvariable=self._banner_text, style="Banner.TLabel").grid(
            row=0, column=3, sticky="e"
        )

    # ----- Step 1: connection ---------------------------------------------

    def _build_step1(self, parent: ttk.Frame, row: int) -> None:
        f = ttk.LabelFrame(parent, text="① 服务器连接 / Connection")
        f.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        f.grid_columnconfigure(1, weight=1)

        # factory.env path (manufacturing-only; not the full server .env)
        ttk.Label(f, text="factory.env", style="Card.TLabel", width=12).grid(row=0, column=0, sticky="w", pady=2)
        e_env = ttk.Entry(f, textvariable=self._dotenv_path)
        e_env.grid(row=0, column=1, sticky="ew", padx=6, pady=2)
        ttk.Button(f, text="浏览", command=self._browse_dotenv, width=6).grid(row=0, column=2, padx=(0, 4))
        ttk.Button(f, text="重新加载", command=self._load_env, width=8).grid(row=0, column=3)

        # API: fixed shipping default in code; UI shows port only (no full URL).
        ttk.Label(f, text="API", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Label(f, text=f":{FACTORY_PUBLIC_HTTP_PORT}", style="Card.TLabel").grid(
            row=1, column=1, columnspan=3, sticky="w", padx=6, pady=2
        )

        # Factory token
        ttk.Label(f, text="Factory Token", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=2)
        self._token_entry = ttk.Entry(f, textvariable=self._factory_token, show="*")
        self._token_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=2)
        ttk.Checkbutton(
            f,
            text="显示",
            variable=self._show_token,
            command=self._toggle_token_visible,
        ).grid(row=2, column=2, sticky="w")

        # Test connection action + status
        action = ttk.Frame(f)
        action.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        action.grid_columnconfigure(2, weight=1)
        self._btn_test = ttk.Button(action, text="测试连接 / Test", style="Primary.TButton", command=self._ping_async)
        self._btn_test.grid(row=0, column=0, padx=(0, 8))
        ttk.Checkbutton(action, text="跳过 HTTPS 证书校验", variable=self._insecure).grid(row=0, column=1, padx=(0, 8))
        ttk.Label(action, textvariable=self._step1_status, style="Card.TLabel").grid(row=0, column=2, sticky="e")

        # Server metadata line
        meta = ttk.Frame(f)
        meta.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        meta.grid_columnconfigure(0, weight=1)
        ttk.Label(meta, textvariable=self._server_meta, style="Sub.TLabel", wraplength=1120, justify="left").grid(
            row=0, column=0, sticky="ew"
        )

        # Local-only escape hatch
        ttk.Checkbutton(
            f,
            text="仅本地导出 PNG（跳过服务器登记） / Local export only (skip register)",
            variable=self._local_only,
        ).grid(row=5, column=0, columnspan=4, sticky="w", pady=(8, 0))

        self._step1_frame = f

    # ----- Step 2: batch config --------------------------------------------

    def _build_step2(self, parent: ttk.Frame, row: int) -> None:
        f = ttk.LabelFrame(parent, text="② 批次配置 / Batch")
        f.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        f.grid_columnconfigure(1, weight=1)

        ttk.Label(f, text="批次 batch", style="Card.TLabel", width=12).grid(row=0, column=0, sticky="w", pady=2)
        self._batch_entry = ttk.Entry(f, textvariable=self._batch, width=30)
        self._batch_entry.grid(row=0, column=1, sticky="w", padx=6, pady=2)
        ttk.Label(f, text="数量 count", style="Card.TLabel").grid(row=0, column=2, sticky="e", padx=(20, 0))
        self._count_spin = ttk.Spinbox(f, from_=1, to=2000, textvariable=self._count, width=10)
        self._count_spin.grid(row=0, column=3, sticky="w", padx=(8, 0))

        # auto-push (only meaningful when not local-only)
        self._auto_push_cb = ttk.Checkbutton(
            f,
            text="生成后立即登记到服务器（POST /factory/devices）",
            variable=self._auto_push,
        )
        self._auto_push_cb.grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 2))

        ttk.Label(
            f,
            text=(
                "导出：factory_serial_exports/output_<时间戳>/ "
                "（manifest.csv · sn_qr.tsv · png/ 含 S/N 印于码下 · factory_devices_bulk.json）"
            ),
            style="Sub.TLabel",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))

        self._step2_frame = f

    # ----- Step 3: action ---------------------------------------------------

    def _build_step3(self, parent: ttk.Frame, row: int) -> None:
        f = ttk.LabelFrame(parent, text="③ 生成 & 登记 / Generate")
        f.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        f.grid_columnconfigure(1, weight=1)

        self._btn_run = ttk.Button(
            f,
            text="生成并登记 / Run",
            style="Primary.TButton",
            command=self._run_async,
        )
        self._btn_run.grid(row=0, column=0, padx=(0, 12), pady=4)

        self._progress = ttk.Progressbar(
            f,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=self._step3_progress,
            style="Horizontal.TProgressbar",
        )
        self._progress.grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        self._progress_lbl = ttk.Label(f, text="待机 idle", style="Sub.TLabel")
        self._progress_lbl.grid(row=0, column=2, padx=(8, 0))

        self._step3_frame = f

    # ----- Step 4: result + helpers ----------------------------------------

    def _build_step4(self, parent: ttk.Frame, row: int) -> None:
        f = ttk.LabelFrame(parent, text="④ 完成 / Result")
        f.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        f.grid_columnconfigure(1, weight=1)

        ttk.Label(f, text="导出目录", style="Card.TLabel", width=12).grid(row=0, column=0, sticky="w", pady=2)
        self._out_var = tk.StringVar(value="（尚未生成）")
        ttk.Label(f, textvariable=self._out_var, style="Mono.TLabel").grid(row=0, column=1, sticky="w", padx=6)

        btns = ttk.Frame(f)
        btns.grid(row=0, column=2, sticky="e")
        self._btn_open_out = ttk.Button(btns, text="打开目录", command=self._open_last_export, width=10)
        self._btn_open_out.pack(side=tk.LEFT, padx=(0, 4))
        self._btn_copy_path = ttk.Button(btns, text="复制路径", command=self._copy_last_path, width=10)
        self._btn_copy_path.pack(side=tk.LEFT, padx=(0, 4))
        self._btn_verify = ttk.Button(btns, text="验证二维码…", command=self._verify_dialog, width=12)
        self._btn_verify.pack(side=tk.LEFT)

        ttk.Label(
            f,
            text="S/N + 激活链接（Tab 分隔，每行一条）· SN + activation link per line",
            style="Sub.TLabel",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 2))

        link_wrap = ttk.Frame(f)
        link_wrap.grid(row=2, column=0, columnspan=3, sticky="ew")
        link_wrap.grid_columnconfigure(0, weight=1)
        self._links_text = tk.Text(
            link_wrap,
            height=5,
            wrap=tk.NONE,
            font=("Consolas", 11),
            background="#fafbfd",
            relief="solid",
            borderwidth=1,
        )
        self._links_text.grid(row=0, column=0, sticky="ew")
        self._links_text.configure(state="disabled")
        self._btn_copy_links = ttk.Button(
            f, text="复制全部 S/N+链接", command=self._copy_all_links, width=18
        )
        self._btn_copy_links.grid(row=3, column=2, sticky="e", pady=(6, 0))

        self._step4_frame = f

    # ----- Log --------------------------------------------------------------

    def _build_log(self, parent: ttk.Frame, row: int) -> None:
        log_fr = ttk.LabelFrame(parent, text="运行日志 / Log")
        log_fr.grid(row=row, column=0, sticky="nsew")
        log_fr.grid_columnconfigure(0, weight=1)
        log_fr.grid_rowconfigure(0, weight=1)

        wrap = ttk.Frame(log_fr)
        wrap.grid(row=0, column=0, sticky="nsew")
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)
        ys = ttk.Scrollbar(wrap)
        xs = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL)
        self._log = tk.Text(
            wrap,
            height=12,
            wrap=tk.NONE,
            font=("Consolas", 11),
            yscrollcommand=ys.set,
            xscrollcommand=xs.set,
            undo=False,
            background="#0e1318",
            foreground="#d6e2ee",
            insertbackground="#d6e2ee",
        )
        self._log.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        ys.config(command=self._log.yview)
        xs.config(command=self._log.xview)
        bar = ttk.Frame(log_fr)
        bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(bar, text="清空日志", command=self._clear_log, width=10).pack(side=tk.RIGHT)

    # -----------------------------------------------------------------------
    # State machine
    # -----------------------------------------------------------------------

    def _has_connection_inputs(self) -> bool:
        api = self._effective_api_base(Path(self._dotenv_path.get()))
        env = read_dotenv_keys(Path(self._dotenv_path.get()), ("FACTORY_API_TOKEN",))
        tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
        return bool(api and tok)

    def _set_connected(self, ok: bool, *, info: dict | None = None, body: str = "", code: int | None = None) -> None:
        self._connected = bool(ok)
        if ok:
            self._banner_text.set("已连接 / Connected")
            self._banner_color = PALETTE["ok"]
            self._step1_status.set("✓ 已连接")
            if info:
                meta_parts = [
                    f"actor={info.get('actor', '?')}",
                    f"qr_sign_required={info.get('qr_sign_required', False)}",
                    f"qr_verify_on_register={info.get('qr_verify_on_register', False)}",
                    f"enforce_factory_registration={info.get('enforce_factory_registration', False)}",
                    f"cmd_proto={info.get('cmd_proto', '?')}",
                    f"server_time={info.get('server_time', '?')}",
                ]
                self._server_meta.set("服务器: " + " · ".join(meta_parts))
            else:
                self._server_meta.set("服务器: ok=true（旧版本服务端未返回元数据）")
        else:
            self._banner_text.set("连接失败 / Failed")
            self._banner_color = PALETTE["err"]
            self._step1_status.set(f"✗ HTTP {code}" if code is not None else "✗ 失败")
            self._server_meta.set(
                (body or "服务器无响应或 token 错误")[:300]
            )
        self._banner_dot.configure(fg=self._banner_color)
        self._refresh_step_locks()

    def _refresh_step_locks(self) -> None:
        # Step 2/3 unlocked when connected OR explicitly local-only.
        unlocked = self._connected or self._local_only.get()
        state = "normal" if unlocked else "disabled"
        for w in (
            getattr(self, "_batch_entry", None),
            getattr(self, "_count_spin", None),
            getattr(self, "_auto_push_cb", None),
            getattr(self, "_btn_run", None),
        ):
            if w is None:
                continue
            try:
                w.configure(state=state)
            except tk.TclError:
                pass
        # auto-push only meaningful when actually connected (not local-only).
        if self._local_only.get():
            try:
                self._auto_push_cb.configure(state="disabled")
            except tk.TclError:
                pass

    def _toggle_token_visible(self) -> None:
        try:
            self._token_entry.configure(show="" if self._show_token.get() else "*")
        except tk.TclError:
            pass

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _effective_api_base(self, _dot: Path) -> str:
        """Single fixed API root from ``factory_core`` (host hidden in UI; port shown as :18999)."""
        return normalize_factory_api_base(DEFAULT_FACTORY_UI_API_BASE)

    def _browse_dotenv(self) -> None:
        p = filedialog.askopenfilename(
            title="选择出厂密钥文件 (factory.env)",
            filetypes=[("factory env", "*.env"), ("All", "*.*")],
        )
        if p:
            self._dotenv_path.set(p)

    def _load_env(self) -> None:
        dot = Path(self._dotenv_path.get())
        if not dot.is_file():
            self._line(
                f"[env] 未找到 {dot} — 请复制 croc_sentinel_systems/factory.env.example "
                "为 factory.env，填入与服务器一致的 QR_SIGN_SECRET 与 FACTORY_API_TOKEN。"
            )
        env = read_dotenv_keys(dot, ("QR_SIGN_SECRET", "FACTORY_API_TOKEN"))
        if env.get("FACTORY_API_TOKEN") and not self._factory_token.get().strip():
            self._factory_token.set(env["FACTORY_API_TOKEN"].strip())
        qs = "yes" if env.get("QR_SIGN_SECRET") else "NO"
        ft = env.get("FACTORY_API_TOKEN") or ""
        self._line(f"[env] path={dot}")
        self._line(
            f"[env] QR_SIGN_SECRET={qs}  FACTORY_API_TOKEN={'yes' if ft.strip() else 'NO'} "
            f"(len={len(ft.strip())})  api=:{FACTORY_PUBLIC_HTTP_PORT} (fixed)"
        )
        self._step1_status.set("已从 .env 加载，请测试连接")
        self._banner_text.set("已加载配置 / Loaded")
        self._banner_color = PALETTE["warn"]
        self._banner_dot.configure(fg=self._banner_color)

    # -----------------------------------------------------------------------
    # Log
    # -----------------------------------------------------------------------

    def _clear_log(self) -> None:
        self._log.delete("1.0", tk.END)

    def _line(self, msg: str) -> None:
        self._log.insert(tk.END, msg.rstrip("\r\n") + "\n")
        self._log.see(tk.END)

    def _lines(self, prefix: str, text: str, *, max_lines: int = 80) -> None:
        parts = (text or "").replace("\r\n", "\n").split("\n")
        for i, ln in enumerate(parts[:max_lines]):
            s = ln.strip()
            if not s and i > 0:
                continue
            self._line(f"{prefix}{s}")
        if len(parts) > max_lines:
            self._line(f"{prefix}… ({len(parts) - max_lines} more lines omitted)")

    # -----------------------------------------------------------------------
    # Async actions: ping
    # -----------------------------------------------------------------------

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
            env = read_dotenv_keys(dot, ("FACTORY_API_TOKEN",))
            api = self._effective_api_base(dot)
            tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
            if not api or not tok:
                ui(self._set_connected, False, body="缺少 Factory Token")
                ui(self._line, "[ping] 缺少 Factory Token")
                return
            ui(self._step1_status.set, "测试中…")
            ui(self._line, f"[ping] GET {api}/factory/ping  token_len={len(tok)}")
            code, body = get_factory_ping(api, tok, insecure_ssl=self._insecure.get())
            ui(self._line, f"[ping] http_status={code}")
            ui(self._lines, "[ping] body | ", body)
            info = _try_parse_json(body) if code in (200, 201) else None
            ok = bool(code in (200, 201))
            ui(self._set_connected, ok, info=info, body=body, code=code)
            if not ok and code == 403:
                ui(messagebox.showerror, "连接失败", "HTTP 403：请核对服务器 .env 里的 FACTORY_API_TOKEN，改完后 docker compose restart api。")
            elif not ok:
                ui(messagebox.showerror, "连接失败", f"HTTP {code}\n{body[:1200]}")
        finally:
            self._ping_lock.release()

    # -----------------------------------------------------------------------
    # Async actions: generate + push
    # -----------------------------------------------------------------------

    def _run_async(self) -> None:
        if self._busy:
            messagebox.showinfo("提示", "已有任务在运行，请稍候。")
            return
        threading.Thread(target=self._run_job, daemon=True).start()

    def _set_progress(self, pct: int, label: str) -> None:
        self._step3_progress.set(max(0, min(100, int(pct))))
        try:
            self._progress_lbl.configure(text=label)
        except tk.TclError:
            pass

    def _run_job(self) -> None:
        def ui(fn, *a, **kw):
            self.after(0, lambda: fn(*a, **kw))

        self._busy = True
        try:
            dot = Path(self._dotenv_path.get())
            env = read_dotenv_keys(dot, ("QR_SIGN_SECRET", "FACTORY_API_TOKEN"))
            secret = (env.get("QR_SIGN_SECRET") or "").strip()
            if not secret:
                ui(messagebox.showerror, "错误", "未找到 QR_SIGN_SECRET，请在 .env 中配置。")
                return

            n = int(self._count.get() or 1)
            batch = self._batch.get().strip() or f"GUI_{int(time.time())}"
            ui(self._set_progress, 5, f"生成 {n} 个序列号…")
            ui(self._line, f"[gen] start count={n} batch={batch}")
            items = generate_items(n, secret, batch)

            ui(self._set_progress, 35, "写入 PNG / manifest…")
            out = repo_root() / "factory_serial_exports" / build_output_dir_name(len(items))
            write_batch_files(out, items, batch, qr_secret=secret)
            (out / "BATCH_ID.txt").write_text(batch + "\n", encoding="utf-8")
            self._last_out = out
            self._last_items = items
            ui(self._out_var.set, str(out))
            ui(self._line, f"[gen] output_dir={out}")
            ui(self._line, "[gen] qr_verify=all_ok")

            do_push = self._auto_push.get() and not self._local_only.get()
            if not do_push:
                ui(self._set_progress, 100, "完成 · 仅本地导出")
                ui(self._render_links, items, api_base="", local_only=True)
                ui(messagebox.showinfo, "完成", f"已生成 {len(items)} 条（未推送）。\n{out}")
                return

            api = self._effective_api_base(dot)
            tok = self._factory_token.get().strip() or env.get("FACTORY_API_TOKEN", "").strip()
            if not api or not tok:
                ui(self._set_progress, 100, "登记跳过 · 缺少 Token")
                ui(messagebox.showwarning, "未登记", "缺少 FACTORY_API_TOKEN，仅本地导出。")
                ui(self._render_links, items, api_base="", local_only=True)
                return

            queue_path = repo_root() / "factory_serial_exports" / "pending_push_queue.json"
            queued_before = len(load_pending_push_queue(queue_path))
            if queued_before:
                ui(self._set_progress, 50, f"补传历史失败批次（{queued_before}）…")
                drained, attempts = drain_pending_push_queue(
                    queue_path, api, tok, insecure_ssl=self._insecure.get(), max_batches=20
                )
                ui(self._line, f"[retry] queue_before={queued_before} drained={drained} remain={len(load_pending_push_queue(queue_path))}")
                for a in attempts:
                    ui(self._line, f"[retry] batch={a.get('batch')} code={a.get('code')} ok={a.get('ok')}")

            ui(self._set_progress, 70, "登记到服务器…")
            ui(self._line, f"[push] url={api}/factory/devices token_len={len(tok)}")
            code, body = post_factory_devices(api, tok, items, insecure_ssl=self._insecure.get())
            ui(self._line, f"[push] http_status={code}")
            ui(self._lines, "[push] body | ", body)
            ok = code in (200, 201)
            status_file = write_push_status_file(out, batch, items, code, body, pushed_ok=ok, retry_attempt=0)
            ui(self._line, f"[push] status_json={status_file}")

            if ok:
                resp = _try_parse_json(body) or {}
                rejected = resp.get("rejected") or []
                written = int(resp.get("written") or 0)
                ui(self._set_progress, 100, f"完成 · 登记 {written}/{len(items)}")
                ui(self._render_links, items, api_base=api, local_only=False)
                if rejected:
                    rc = Counter(str(r.get("reason") or "?") for r in rejected)
                    ui(self._line, f"[push] rejected_count={len(rejected)} by_reason={dict(rc)}")
                    lines = []
                    for r in rejected[:30]:
                        rs = str(r.get("serial") or "")
                        rr = str(r.get("reason") or "")
                        hint = _FACTORY_REJECT_HINTS.get(rr, "")
                        lines.append(f"{rs}: {rr}" + (f" — {hint}" if hint else ""))
                    msg = "\n".join(lines)
                    ui(messagebox.showwarning, "部分拒绝", f"已登记 {written} 条。\n被拒绝 {len(rejected)} 条：\n{msg}")
                else:
                    ui(messagebox.showinfo, "完成", f"已登记 {len(items)} 条。\n{out}")
            else:
                resp = _try_parse_json(body) or {}
                detail = resp.get("detail") if isinstance(resp.get("detail"), dict) else resp
                rejected = (detail or {}).get("rejected") or []
                qlen = append_pending_push_queue(queue_path, batch, items, reason=f"HTTP {code}: {body[:500]}")
                ui(self._set_progress, 100, f"登记失败 · HTTP {code} · 已入队列")
                ui(self._line, f"[queue] path={queue_path} size={qlen}")
                hint = ""
                if code == 403:
                    hint = "\n\n403：核对服务器 FACTORY_API_TOKEN；改 .env 后 docker compose restart api。"
                elif code == 400 and rejected:
                    lines400 = []
                    for r in rejected[:30]:
                        rs = str(r.get("serial") or "")
                        rr = str(r.get("reason") or "")
                        h = _FACTORY_REJECT_HINTS.get(rr, "")
                        lines400.append(f"  {rs}: {rr}" + (f" — {h}" if h else ""))
                    sample = "\n".join(lines400)
                    hint = f"\n\n服务器拒绝 {len(rejected)} 条：\n{sample}"
                ui(messagebox.showerror, "登记失败", f"HTTP {code}\n{body[:800]}{hint}")
                ui(self._render_links, items, api_base=api, local_only=False)
        except Exception as e:
            ui(self._line, f"[err] {e!r}")
            ui(self._set_progress, 100, "出错")
            ui(messagebox.showerror, "错误", str(e))
        finally:
            self._busy = False

    # -----------------------------------------------------------------------
    # Step 4 helpers
    # -----------------------------------------------------------------------

    def _activation_link(self, item: dict, api_base: str) -> str:
        base = (api_base or "").rstrip("/")
        if not base:
            return ""
        qr = str(item.get("qr_code") or "")
        serial = str(item.get("serial") or "")
        qparam = urllib.parse.quote(qr if qr else serial, safe="")
        dp = (os.environ.get("DASHBOARD_PATH") or "/console").strip() or "/console"
        if not dp.startswith("/"):
            dp = "/" + dp
        dp = dp.rstrip("/") or "/console"
        return f"{base}{dp}/#/activate?q={qparam}"

    def _render_links(self, items: list[dict], api_base: str, local_only: bool) -> None:
        try:
            self._links_text.configure(state="normal")
            self._links_text.delete("1.0", tk.END)
            if local_only:
                for it in items[:200]:
                    sn = str(it.get("serial") or "")
                    q = str(it.get("qr_code") or "")
                    self._links_text.insert(tk.END, f"{sn}\t{q}\n")
                if len(items) > 200:
                    self._links_text.insert(
                        tk.END,
                        f"… ({len(items) - 200} more — 全量见 sn_qr.tsv / manifest.csv)\n",
                    )
            elif not api_base:
                self._links_text.insert(
                    tk.END,
                    "（未生成链接：缺少 API 或未登记）\n",
                )
            else:
                for it in items[:200]:
                    link = self._activation_link(it, api_base)
                    sn = str(it.get("serial") or "")
                    self._links_text.insert(tk.END, f"{sn}\t{link}\n")
                if len(items) > 200:
                    self._links_text.insert(
                        tk.END,
                        f"… ({len(items) - 200} more — 全量见 sn_qr.tsv / manifest.csv)\n",
                    )
        finally:
            self._links_text.configure(state="disabled")

    def _copy_all_links(self) -> None:
        try:
            self._links_text.configure(state="normal")
            txt = self._links_text.get("1.0", tk.END).strip()
        finally:
            self._links_text.configure(state="disabled")
        if not txt or txt.startswith("（"):
            messagebox.showinfo("提示", "尚无 S/N+链接可复制。")
            return
        self.clipboard_clear()
        self.clipboard_append(txt)
        self._line(f"[clipboard] 已复制 {len(txt.splitlines())} 行（S/N + 链接或二维码）")

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

    def _verify_dialog(self) -> None:
        dot = Path(self._dotenv_path.get())
        env = read_dotenv_keys(dot, ("QR_SIGN_SECRET",))
        secret = (env.get("QR_SIGN_SECRET") or "").strip()
        if not secret:
            messagebox.showerror("错误", "需要 QR_SIGN_SECRET")
            return
        d = tk.Toplevel(self)
        d.title("验证二维码 / Verify QR")
        d.geometry("680x280")
        d.minsize(520, 220)
        ttk.Label(d, text="粘贴整行 CROC|... 进行 HMAC 校验").pack(anchor=tk.W, padx=12, pady=(10, 4))
        txt = tk.Text(d, height=5, wrap=tk.NONE, font=("Consolas", 12))
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)
        out = tk.StringVar(value="")
        ttk.Label(d, textvariable=out, foreground=PALETTE["accent"]).pack(anchor=tk.W, padx=12, pady=(0, 6))

        def go() -> None:
            q = txt.get("1.0", tk.END).strip()
            ok = verify_qr_local(q, secret)
            out.set("✓ 签名正确 / valid" if ok else "✗ 签名错误或格式不对 / invalid")
            messagebox.showinfo("结果", "签名正确" if ok else "签名错误或格式不对")

        bf = ttk.Frame(d)
        bf.pack(fill=tk.X, pady=(0, 12))
        ttk.Button(bf, text="验证", command=go, style="Primary.TButton").pack(side=tk.LEFT, padx=12)
        ttk.Button(bf, text="关闭", command=d.destroy).pack(side=tk.LEFT)


def main() -> None:
    app = FactoryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
