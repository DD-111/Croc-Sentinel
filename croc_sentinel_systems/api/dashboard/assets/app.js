/* Croc Sentinel Console - SPA */
(function () {
  "use strict";

  // ------------------------------------------------------------------ const
  const LS = {
    token: "croc.token",
    user: "croc.user",
    role: "croc.role",
    zones: "croc.zones",
    theme: "croc.theme",
  };
  const OFFLINE_MS = 90 * 1000;

  const NAV = [
    { id: "overview",  label: "Overview",  ico: "◎", path: "#/overview",   min: "user"  },
    { id: "signals",   label: "Signals",   ico: "◉", path: "#/signals",    min: "user"  },
    { id: "alerts",    label: "Siren",     ico: "!", path: "#/alerts",     min: "user"  },
    { id: "activate",  label: "Activate",  ico: "+", path: "#/activate",   min: "admin" },
    { id: "ota",       label: "OTA",       ico: "↑", path: "#/ota",        min: "admin" },
    { id: "events",    label: "Events",    ico: "≈", path: "#/events",     min: "user"  },
    { id: "audit",     label: "Audit",     ico: "≡", path: "#/audit",      min: "admin" },
    { id: "admin",     label: "Admin",     ico: "☼", path: "#/admin",      min: "admin" },
  ];

  const ROLE_WEIGHT = { user: 1, admin: 2, superadmin: 3 };

  // ------------------------------------------------------------------ state
  const state = {
    me: null,
    mqttConnected: false,
  };

  /** 注册/激活页「几秒后跳转登录」的定时器，路由切换时必须清掉以免泄漏与误跳转 */
  let routeRedirectTimer = null;
  function clearRouteRedirectTimer() {
    if (routeRedirectTimer) {
      clearTimeout(routeRedirectTimer);
      routeRedirectTimer = null;
    }
  }
  function scheduleRouteRedirect(ms, hash) {
    clearRouteRedirectTimer();
    routeRedirectTimer = setTimeout(() => {
      routeRedirectTimer = null;
      location.hash = hash;
    }, ms);
  }

  /** 离开「事件中心」后应置空；仅在该页赋值，用于切回前台时重连 SSE */
  window.__eventsStreamResume = null;

  let healthPollTimer = null;
  /** 总览设备搜索防抖；离开页面时清掉，避免对已卸载 DOM 赋值 */
  let overviewFilterDebounce = null;
  function clearHealthPollTimer() {
    if (healthPollTimer) {
      clearInterval(healthPollTimer);
      healthPollTimer = null;
    }
  }
  function tickHealthIfVisible() {
    if (document.visibilityState !== "visible") return;
    loadHealth();
  }

  // ------------------------------------------------------------------ utils
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function apiBase() {
    return location.origin;
  }

  function getToken() { return localStorage.getItem(LS.token) || ""; }
  function setToken(t) { t ? localStorage.setItem(LS.token, t) : localStorage.removeItem(LS.token); }

  function escapeHtml(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function fmtTs(v) {
    if (!v) return "—";
    const t = typeof v === "number" ? (v > 1e12 ? v : v * 1000) : Date.parse(v);
    if (!Number.isFinite(t)) return String(v);
    const d = new Date(t);
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function fmtRel(v) {
    if (!v) return "—";
    const t = Date.parse(v);
    if (!Number.isFinite(t)) return String(v);
    const diff = Date.now() - t;
    if (diff < 60_000) return "just now";
    if (diff < 3600_000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400_000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  }

  function roleWeight(r) { return ROLE_WEIGHT[r] || 0; }
  function hasRole(min) { return state.me && roleWeight(state.me.role) >= roleWeight(min); }
  function can(cap) { return !!(state.me && state.me.policy && state.me.policy[cap]); }
  function isOnline(d) { return Date.now() - Date.parse(d.updated_at || 0) < OFFLINE_MS; }

  function toast(msg, kind) {
    const el = $("#toast");
    if (!el) return;
    el.textContent = String(msg);
    el.className = "toast show " + (kind || "");
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.className = "toast"; }, 3200);
  }

  // ------------------------------------------------------------------ api
  async function api(path, opts) {
    opts = opts || {};
    const token = getToken();
    const headers = Object.assign(
      { Authorization: token ? "Bearer " + token : "" },
      opts.headers || {}
    );
    let body = opts.body;
    if (body && typeof body === "object" && !(body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    const r = await fetch(apiBase() + path, { method: opts.method || "GET", headers, body });
    if (r.status === 401) {
      setToken("");
      state.me = null;
      if (location.hash !== "#/login") location.hash = "#/login";
      throw new Error("401 Unauthorized or session expired");
    }
    if (!r.ok) {
      const t = await r.text().catch(() => "");
      let msg;
      try { msg = JSON.parse(t).detail || t; } catch { msg = t; }
      throw new Error(`${r.status} ${msg || r.statusText}`);
    }
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) return r.json();
    if (opts.raw) return r;
    return r.text();
  }

  async function login(username, password) {
    const r = await fetch(apiBase() + "/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
    const j = await r.json();
    setToken(j.access_token || "");
    localStorage.setItem(LS.user, username);
    localStorage.setItem(LS.role, j.role || "");
    localStorage.setItem(LS.zones, JSON.stringify(j.zones || []));
    return j;
  }

  async function loadMe() {
    try {
      state.me = await api("/auth/me");
    } catch (e) {
      state.me = null;
    }
    renderAuthState();
  }

  async function loadHealth() {
    try {
      const h = await api("/health");
      state.mqttConnected = !!h.mqtt_connected;
    } catch {
      state.mqttConnected = false;
    }
    renderMqttDot();
  }

  // ------------------------------------------------------------------ layout
  function renderAuthState() {
    document.body.dataset.auth = state.me ? "ok" : "none";
    const who = $("#who");
    if (state.me) {
      who.innerHTML =
        `<div><strong>${escapeHtml(state.me.username)}</strong></div>` +
        `<div class="muted">${escapeHtml(state.me.role)} · ${escapeHtml((state.me.zones || []).join(", ") || "—")}</div>`;
    } else {
      who.textContent = "Signed out";
    }
    renderNav();
  }

  function renderNav() {
    const nav = $("#nav");
    if (!nav) return;
    if (!state.me) { nav.innerHTML = ""; return; }
    const hash = location.hash || "#/overview";
    const items = NAV.filter((n) => hasRole(n.min)).map((n) => {
      const active = hash.startsWith(n.path) ? ` aria-current="page"` : "";
      return `<a href="${n.path}"${active}><span class="nav-ico">${n.ico}</span>${escapeHtml(n.label)}</a>`;
    }).join("");
    nav.innerHTML = `<div class="nav-section">Menu</div>${items}`;
  }

  function renderMqttDot() {
    const dot = $("#mqttDot");
    if (!dot) return;
    dot.className = "dot-status " + (state.mqttConnected ? "ok" : "bad");
    dot.title = state.mqttConnected ? "MQTT up" : "MQTT down";
  }

  function setCrumb(text) { const el = $("#crumb"); if (el) el.textContent = text; }

  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    localStorage.setItem(LS.theme, t);
  }

  function initTheme() {
    const saved = localStorage.getItem(LS.theme);
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(saved || (prefersDark ? "dark" : "light"));
  }

  function toggleNav(open) {
    if (open == null) open = document.body.dataset.nav !== "open";
    document.body.dataset.nav = open ? "open" : "";
  }

  // ------------------------------------------------------------------ router
  const routes = {};

  function registerRoute(id, handler) { routes[id] = handler; }

  async function renderRoute() {
    const view = $("#view");
    let hashFull = location.hash || "#/overview";
    let routeQuery = new URLSearchParams("");
    const qm = hashFull.indexOf("?");
    if (qm >= 0) {
      try {
        routeQuery = new URLSearchParams(hashFull.slice(qm + 1));
      } catch (_) {}
      hashFull = hashFull.slice(0, qm);
    }
    window.__routeQuery = routeQuery;
    const [_, rawId, ...rest] = hashFull.split("/");
    const id = rawId || "overview";
    const args = rest;

    clearRouteRedirectTimer();
    if (overviewFilterDebounce) {
      clearTimeout(overviewFilterDebounce);
      overviewFilterDebounce = null;
    }
    if (window.__pendingEvListRaf) {
      try { cancelAnimationFrame(window.__pendingEvListRaf); } catch (_) {}
      window.__pendingEvListRaf = 0;
    }
    window.__eventsStreamResume = null;
    toggleNav(false);
    if (window.__evSSE) { try { window.__evSSE.close(); } catch {} window.__evSSE = null; }

    const publicRoutes = new Set(["login", "register", "account-activate", "forgot-password"]);
    if (!state.me && !publicRoutes.has(id)) {
      location.hash = "#/login";
      return;
    }
    if (state.me && publicRoutes.has(id)) {
      location.hash = "#/overview";
      return;
    }
    const routeId = id === "alarm-log" ? "signals" : id;
    const handler = routes[routeId] || routes["overview"];
    try {
      view.innerHTML = '<div class="card"><span class="muted">Loading…</span></div>';
      await handler(view, args);
      renderNav();
    } catch (e) {
      view.innerHTML = `<div class="card"><h2>Load failed</h2><p class="muted">${escapeHtml(e.message || e)}</p></div>`;
    }
  }

  window.addEventListener("hashchange", renderRoute);

  // ------------------------------------------------------------------ pages
  // Login
  registerRoute("login", async (view) => {
    setCrumb("Sign in");
    document.body.dataset.auth = "none";
    view.innerHTML = `
      <div class="login-wrap">
        <form class="login-card" id="loginForm" autocomplete="on">
          <h1>Croc Sentinel</h1>
          <p class="muted">Sign in with username and password.</p>
          <label class="field">
            <span>Username</span>
            <input name="username" autocomplete="username" required />
          </label>
          <label class="field" style="margin-top:10px">
            <span>Password</span>
            <input name="password" type="password" autocomplete="current-password" required />
          </label>
          <div style="margin-top:18px">
            <button class="btn btn-tap btn-block" type="submit">Sign in</button>
          </div>
          <p class="muted" id="loginMsg" style="margin-top:10px;min-height:1.4em"></p>
          <div class="login-link-stack">
            <a class="link-tile" href="#/register">Register admin (email OTP)</a>
            <a class="link-tile" href="#/account-activate">Activate account (email code)</a>
            <a class="link-tile" href="#/forgot-password" title="Offline RSA recovery">Forgot password</a>
          </div>
        </form>
      </div>`;
    const form = $("#loginForm", view);
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const data = new FormData(form);
      const msg = $("#loginMsg", view);
      msg.textContent = "";
      try {
        await login(data.get("username"), data.get("password"));
        await loadMe();
        await loadHealth();
        location.hash = "#/overview";
      } catch (e) {
        msg.textContent = String(e.message || e);
      }
    });
  });

  // Forgot password — offline RSA decrypt flow
  registerRoute("forgot-password", async (view) => {
    setCrumb("忘记密码");
    document.body.dataset.auth = "none";
    let enabled = true;
    try {
      const r = await fetch(apiBase() + "/auth/forgot/enabled");
      const j = await r.json();
      enabled = !!j.enabled;
    } catch { enabled = false; }
    view.innerHTML = `
      <div class="login-wrap">
        <div class="login-card" style="max-width:520px">
          <h1>忘记密码</h1>
          <p class="muted">
            本流程用于<strong>未配置邮箱自助重置</strong>或<strong>更高安全要求</strong>的部署。
            点击「获取编码」后，会得到字段 <span class="mono">recovery_blob_hex</span>：
            它是<strong>纯十六进制</strong>字符串，字符数 ≈ <strong>2 × blob_byte_len</strong>（与接口返回的
            <span class="mono">blob_byte_len</span> 一致）。当前服务端为 RSA-2048 且
            <span class="mono">PASSWORD_RECOVERY_PLAINTEXT_PAD=512</span> 时，长度约为 <strong>1602</strong> 个字符
            ——不是「64 位短码」，请务必<strong>整段复制</strong>、勿换行截断、勿夹空格。
            把整段发给运维；运维在<strong>离线机</strong>用
            <span class="mono">password_recovery_offline/decrypt_recovery_blob.py</span>
            + <span class="mono">private.pem</span> 解密后，将输出的一行 JSON 粘贴到下方「解密明文」，
            再输入两次新密码即可写入数据库。
          </p>
          ${enabled ? "" : `<p class="badge revoked" style="margin:10px 0">当前服务器未配置公钥（<span class="mono">PASSWORD_RECOVERY_PUBLIC_KEY_*</span>），无法发起找回。</p>`}
          <div id="fpStep1">
            <label class="field"><span>用户名</span><input id="fp_user" autocomplete="username" /></label>
            <div style="margin-top:14px;display:flex;flex-direction:column;gap:10px">
              <button class="btn btn-tap btn-block" type="button" id="fp_go" ${enabled ? "" : "disabled"}>获取编码</button>
              <a class="link-tile" href="#/login" style="text-align:center">返回登录</a>
            </div>
            <p class="muted" id="fp_msg1" style="margin-top:10px"></p>
          </div>
          <div id="fpStep2" style="display:none">
            <label class="field"><span>recovery_blob_hex（整段复制）</span>
              <textarea id="fp_blob" readonly rows="6" class="mono" style="width:100%;font-size:11px"></textarea>
            </label>
            <p class="muted" id="fp_blob_hint" style="margin-top:6px;font-size:12px"></p>
            <p class="muted" id="fp_meta"></p>
            <label class="field"><span>解密明文（一行 JSON）</span>
              <textarea id="fp_plain" rows="3" placeholder='{"jti":"...","u":"...","s":"...","e":...}' style="width:100%"></textarea>
            </label>
            <label class="field"><span>新密码（≥8 位）</span><input id="fp_p1" type="password" autocomplete="new-password" /></label>
            <label class="field"><span>确认新密码</span><input id="fp_p2" type="password" autocomplete="new-password" /></label>
            <div style="margin-top:14px;display:flex;flex-direction:column;gap:10px">
              <button class="btn btn-tap btn-block" type="button" id="fp_done">更新密码</button>
              <button class="btn secondary btn-tap btn-block" type="button" id="fp_back">上一步</button>
            </div>
            <p class="muted" id="fp_msg2" style="margin-top:10px"></p>
          </div>
        </div>
      </div>`;
    const m1 = $("#fp_msg1"), m2 = $("#fp_msg2");
    $("#fp_go").addEventListener("click", async () => {
      m1.textContent = "";
      const username = $("#fp_user").value.trim();
      if (!username) { m1.textContent = "请输入用户名"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/forgot/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
          const det = d.detail;
          const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || r.statusText);
          throw new Error(msg);
        }
        const hex = d.recovery_blob_hex || "";
        $("#fp_blob").value = hex;
        const bl = d.blob_byte_len;
        const hexLen = hex.length;
        $("#fp_blob_hint").textContent =
          bl != null
            ? `当前编码：十六进制 ${hexLen} 个字符（应等于 2×${bl}=${2 * Number(bl)}）。请完整复制到解密脚本，不要只复制前几行。`
            : `当前编码：十六进制 ${hexLen} 个字符。请完整复制，不要截断。`;
        $("#fp_meta").textContent = `有效时间约 ${((d.ttl_seconds || 0) / 3600).toFixed(1)} 小时 · 二进制长度 ${bl != null ? bl + " 字节" : "—"}`;
        $("#fpStep1").style.display = "none";
        $("#fpStep2").style.display = "block";
      } catch (e) { m1.textContent = String(e.message || e); }
    });
    $("#fp_back").addEventListener("click", () => {
      $("#fpStep2").style.display = "none";
      $("#fpStep1").style.display = "block";
      m2.textContent = "";
    });
    $("#fp_done").addEventListener("click", async () => {
      m2.textContent = "";
      const username = $("#fp_user").value.trim();
      const recovery_plain = ($("#fp_plain").value || "").trim();
      const password = $("#fp_p1").value;
      const password_confirm = $("#fp_p2").value;
      if (!recovery_plain || !password) { m2.textContent = "请填写解密明文与密码"; return; }
      if (password !== password_confirm) { m2.textContent = "两次密码不一致"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/forgot/complete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, recovery_plain, password, password_confirm }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
          const det = d.detail;
          const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || r.statusText);
          throw new Error(msg);
        }
        m2.textContent = "密码已更新，请返回登录。";
        toast("密码已更新", "ok");
      } catch (e) { m2.textContent = String(e.message || e); }
    });
  });

  // Public admin signup
  registerRoute("register", async (view) => {
    setCrumb("注册管理员");
    document.body.dataset.auth = "none";
    view.innerHTML = `
      <div class="login-wrap">
        <div class="login-card login-card--wide">
          <h1>注册管理员</h1>
          <p class="muted">只创建 <strong>管理员</strong> 角色。用<strong>邮箱收验证码</strong>完成验证，不需要手机号。<br>
            超级管理员由运维在服务器配置，不从此页注册。若开启审批，验证通过后还需超管批准才能登录。</p>
          <ol class="login-steps" aria-label="注册步骤">
            <li id="r_step_ind1" class="is-active">① 填写资料</li>
            <li id="r_step_ind2">② 邮箱验证</li>
          </ol>
          <div id="rStep1">
            <label class="field"><span>用户名（2–64 位：字母数字以及 ._-）</span><input id="r_user" autocomplete="username"/></label>
            <label class="field" style="margin-top:10px"><span>密码（至少 8 位）</span><input id="r_pass" type="password" autocomplete="new-password"/></label>
            <label class="field" style="margin-top:10px"><span>邮箱（收验证码与通知）</span><input id="r_email" type="email" autocomplete="email"/></label>
            <div style="margin-top:16px;display:flex;flex-direction:column;gap:10px">
              <button class="btn btn-tap btn-block" type="button" id="r_start">发送邮件验证码</button>
              <a class="link-tile" href="#/login" style="text-align:center">已有账号，去登录</a>
            </div>
            <p class="muted" id="r_msg1" style="margin-top:10px"></p>
          </div>
          <div id="rStep2" style="display:none">
            <p>我们已向 <strong class="mono" id="r_shown_email"></strong> 发送验证码。请打开邮箱（含垃圾邮件夹）查看。</p>
            <label class="field" style="margin-top:10px"><span>邮箱里的验证码</span><input id="r_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code"/></label>
            <div style="margin-top:16px;display:flex;flex-direction:column;gap:10px">
              <button class="btn btn-tap btn-block" type="button" id="r_verify">完成注册</button>
              <button class="btn secondary btn-tap btn-block" type="button" id="r_resend">重发邮件验证码</button>
              <button class="btn ghost btn-tap btn-block" type="button" id="r_back_step">返回上一步</button>
            </div>
            <p class="muted" id="r_msg2" style="margin-top:10px"></p>
          </div>
        </div>
      </div>`;
    const m1 = $("#r_msg1"), m2 = $("#r_msg2");
    $("#r_start").addEventListener("click", async () => {
      m1.textContent = "";
      const body = {
        username: $("#r_user").value.trim(),
        password: $("#r_pass").value,
        email: $("#r_email").value.trim(),
      };
      if (!body.username || !body.password || !body.email) { m1.textContent = "请填写用户名、密码和邮箱"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/signup/start", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        sessionStorage.setItem("croc.signup_user", body.username);
        $("#r_shown_email").textContent = body.email;
        $("#r_step_ind1").classList.remove("is-active");
        $("#r_step_ind2").classList.add("is-active");
        $("#rStep1").style.display = "none";
        $("#rStep2").style.display = "";
      } catch (e) { m1.textContent = String(e.message || e); }
    });
    $("#r_verify").addEventListener("click", async () => {
      m2.textContent = "";
      const body = {
        username: sessionStorage.getItem("croc.signup_user") || "",
        email_code: $("#r_email_code").value.trim(),
      };
      try {
        const r = await fetch(apiBase() + "/auth/signup/verify", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        if (j.status === "awaiting_approval") {
          m2.innerHTML = `<span class="badge online">验证成功</span> 账号已提交，正在等待超级管理员审批，审批通过后可登录。`;
        } else {
          m2.innerHTML = `<span class="badge online">验证成功</span> 账号已激活，3 秒后跳转到登录…`;
          scheduleRouteRedirect(3000, "#/login");
        }
      } catch (e) { m2.textContent = String(e.message || e); }
    });
    $("#r_back_step").addEventListener("click", () => {
      m2.textContent = "";
      $("#r_step_ind2").classList.remove("is-active");
      $("#r_step_ind1").classList.add("is-active");
      $("#rStep2").style.display = "none";
      $("#rStep1").style.display = "";
    });
    $("#r_resend").addEventListener("click", async () => {
      const username = sessionStorage.getItem("croc.signup_user") || "";
      if (!username) { m2.textContent = "请先在上一步提交"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/code/resend", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, channel: "email", purpose: "signup" }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        m2.textContent = "已重新发送";
      } catch (e) { m2.textContent = String(e.message || e); }
    });
  });

  // Account activation (admin-created users arrive here)
  registerRoute("account-activate", async (view) => {
    setCrumb("激活账号");
    document.body.dataset.auth = "none";
    view.innerHTML = `
      <div class="login-wrap">
        <div class="login-card login-card--wide">
          <h1>激活账号</h1>
          <p class="muted">管理员已在后台为你开好账号，并往你的邮箱发了验证码。在下面输入<strong>用户名</strong>和<strong>邮件里的验证码</strong>即可激活（无需手机号）。</p>
          <label class="field"><span>用户名</span><input id="a_user" autocomplete="username"/></label>
          <label class="field" style="margin-top:10px"><span>邮箱验证码</span><input id="a_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code"/></label>
          <div style="margin-top:16px;display:flex;flex-direction:column;gap:10px">
            <button class="btn btn-tap btn-block" type="button" id="a_submit">激活账号</button>
            <button class="btn secondary btn-tap btn-block" type="button" id="a_resend">重发邮件验证码</button>
            <a class="link-tile" href="#/login" style="text-align:center">返回登录</a>
          </div>
          <p class="muted" id="a_msg" style="margin-top:10px"></p>
        </div>
      </div>`;
    const msg = $("#a_msg");
    $("#a_submit").addEventListener("click", async () => {
      const body = {
        username: $("#a_user").value.trim(),
        email_code: $("#a_email_code").value.trim(),
      };
      msg.textContent = "";
      try {
        const r = await fetch(apiBase() + "/auth/activate", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        msg.innerHTML = `<span class="badge online">已激活</span> 3 秒后回到登录…`;
        scheduleRouteRedirect(3000, "#/login");
      } catch (e) { msg.textContent = String(e.message || e); }
    });
    $("#a_resend").addEventListener("click", async () => {
      msg.textContent = "";
      const username = $("#a_user").value.trim();
      if (!username) { msg.textContent = "请先填写用户名"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/code/resend", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, channel: "email", purpose: "activate" }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        msg.textContent = "已尝试重新发送，请查收邮箱（含垃圾邮件）。";
      } catch (e) { msg.textContent = String(e.message || e); }
    });
  });

  // Overview
  registerRoute("overview", async (view) => {
    setCrumb("Overview");
    const [ov, list] = await Promise.all([api("/dashboard/overview"), api("/devices")]);
    const devices = list.items || [];
    const online = (ov.presence && ov.presence.online != null) ? ov.presence.online : devices.filter(isOnline).length;
    const offline = (ov.presence && ov.presence.offline_total != null) ? ov.presence.offline_total : Math.max(0, devices.length - online);
    const pr = ov.presence || {};
    const tp = ov.throughput || {};
    const bps = (v) => {
      v = Number(v || 0);
      if (v < 1024) return v.toFixed(0) + " B/s";
      if (v < 1024 * 1024) return (v / 1024).toFixed(1) + " KB/s";
      return (v / 1024 / 1024).toFixed(2) + " MB/s";
    };
    const stats = [
      ["Devices", ov.total_devices ?? devices.length, "in your scope"],
      ["Online", online, "recent status online=true"],
      ["Offline", offline, ">90s stale / online=false"],
      ["Alarms 24h", ov.alarms_24h ?? 0, "device alarm count"],
      ["MQTT", ov.mqtt_connected ? "up" : "down", "broker"],
      ["Throughput", `${bps(tp.tx_bps_total)} / ${bps(tp.rx_bps_total)}`, "Tx / Rx sum"],
    ].map(([k, v, s]) => `<div class="stat"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div><div class="sub">${escapeHtml(s)}</div></div>`).join("");
    const presenceCards = `
      <div class="stat"><div class="k">Power low</div><div class="v">${pr.reason_power_low || 0}</div><div class="sub">vbat</div></div>
      <div class="stat"><div class="k">Network lost</div><div class="v">${pr.reason_network_lost || 0}</div><div class="sub">link / timeout</div></div>
      <div class="stat"><div class="k">Weak signal</div><div class="v">${pr.reason_signal_weak || 0}</div><div class="sub">RSSI</div></div>
      <div class="stat"><div class="k">Unknown</div><div class="v">${pr.reason_unknown || 0}</div><div class="sub">no reason yet</div></div>`;

    view.innerHTML = `
      <section class="stats">${stats}</section>
      <section class="card">
        <div class="row">
          <h3 style="margin:0">Offline breakdown</h3>
          <span class="muted">disconnect_reason from devices</span>
        </div>
        <div class="divider"></div>
        <section class="stats">${presenceCards}</section>
      </section>
      <section class="card">
        <div class="row" style="align-items:center">
          <h2 style="margin:0">Devices</h2>
          <span class="muted">${devices.length} total</span>
          <input id="q" placeholder="Filter id / name / zone / fw" class="grow right" />
        </div>
        <div class="divider"></div>
        <div class="device-grid" id="devGrid"></div>
      </section>`;

    const renderList = () => {
      const grid = document.getElementById("devGrid");
      if (!grid) return;
      const q = ($("#q").value || "").toLowerCase().trim();
      const rows = devices.filter((d) => !q || [d.device_id, d.display_label, d.zone, d.fw, d.board_profile, d.chip_target].join(" ").toLowerCase().includes(q));
      grid.innerHTML = rows.length === 0
        ? `<p class="muted">No matching devices.</p>`
        : rows.map((d) => {
          const on = isOnline(d);
          const title = d.display_label ? `${escapeHtml(d.display_label)} · ${escapeHtml(d.device_id)}` : escapeHtml(d.device_id || "unknown");
          return `<a class="device-card" href="#/devices/${encodeURIComponent(d.device_id)}" style="text-decoration:none;color:inherit">
            <h3>${title}</h3>
            <div><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
              ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
              ${d.fw ? `<span class="chip">v${escapeHtml(d.fw)}</span>` : ""}
            </div>
            <div class="meta">
              Chip: ${escapeHtml(d.chip_target || "—")}<br/>
              Board: ${escapeHtml(d.board_profile || "—")}<br/>
              Net: ${escapeHtml(d.net_type || "—")}<br/>
              Updated: ${escapeHtml(fmtRel(d.updated_at))}
            </div>
          </a>`;
        }).join("");
    };
    $("#q").addEventListener("input", () => {
      clearTimeout(overviewFilterDebounce);
      overviewFilterDebounce = setTimeout(() => {
        overviewFilterDebounce = null;
        renderList();
      }, 140);
    });
    renderList();
  });

  // Device detail
  registerRoute("devices", async (view, args) => {
    const id = decodeURIComponent(args[0] || "");
    if (!id) { location.hash = "#/overview"; return; }
    setCrumb(`Device · ${id}`);

    const [d, msgs] = await Promise.all([
      api(`/devices/${encodeURIComponent(id)}`),
      api(`/devices/${encodeURIComponent(id)}/messages?limit=25`).catch(() => ({ items: [] })),
    ]);
    const on = isOnline(d);
    const s = d.last_status_json || {};
    const bps = (v) => {
      v = Number(v || 0);
      if (v < 1024) return v.toFixed(0) + " B/s";
      if (v < 1024 * 1024) return (v / 1024).toFixed(1) + " KB/s";
      return (v / 1024 / 1024).toFixed(2) + " MB/s";
    };
    const reasonEn = {
      none: "OK",
      power_low: "Power low",
      network_lost: "Network lost",
      signal_weak: "Weak signal",
    };
    const reason = s.disconnect_reason || (on ? "none" : "network_lost");
    const vbat = (s.vbat == null || s.vbat < 0) ? "—" : `${Number(s.vbat).toFixed(2)} V`;
    const rssi = (s.rssi == null || s.rssi === -127) ? "—" : `${s.rssi} dBm`;

    view.innerHTML = `
      <div class="card">
        <div class="row">
          <h2 style="margin:0">${escapeHtml(id)}</h2>
          <span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
          <span class="chip">${escapeHtml(reasonEn[reason] || reason)}</span>
          ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
          <a href="#/overview" class="btn ghost right">← Overview</a>
        </div>
        <div class="divider"></div>
        <div class="row" style="gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:10px">
          <label class="field grow"><span>Display name</span>
            <input id="dispLabel" value="${escapeHtml(d.display_label || "")}" maxlength="80" />
          </label>
          <button class="btn secondary" type="button" id="saveLabel">Save</button>
        </div>
        <dl class="kv">
          <dt>Firmware</dt><dd class="mono">${escapeHtml(d.fw || "—")}</dd>
          <dt>Chip</dt><dd class="mono">${escapeHtml(d.chip_target || "—")}</dd>
          <dt>Board</dt><dd class="mono">${escapeHtml(d.board_profile || "—")}</dd>
          <dt>Network</dt><dd class="mono">${escapeHtml(d.net_type || "—")} · ${escapeHtml(s.ip || "—")}</dd>
          <dt>RSSI</dt><dd class="mono">${escapeHtml(rssi)}</dd>
          <dt>Battery</dt><dd class="mono">${escapeHtml(vbat)}</dd>
          <dt>Tx / Rx</dt><dd class="mono">${escapeHtml(bps(s.tx_bps))} / ${escapeHtml(bps(s.rx_bps))}</dd>
          <dt>Disconnect</dt><dd class="mono">${escapeHtml(reason)}</dd>
          <dt>Provisioned</dt><dd>${d.provisioned ? "yes" : "no"}</dd>
          <dt>Uptime</dt><dd class="mono">${escapeHtml((s.uptime_s ? `${Math.floor(s.uptime_s / 3600)}h ${Math.floor((s.uptime_s % 3600) / 60)}m` : "—"))}</dd>
          <dt>Free heap</dt><dd class="mono">${escapeHtml(s.free_heap ? `${s.free_heap} B (min ${s.min_free_heap || "?"} B)` : "—")}</dd>
          <dt>Updated</dt><dd>${escapeHtml(fmtTs(d.updated_at))} (${escapeHtml(fmtRel(d.updated_at))})</dd>
        </dl>
      </div>

      <div class="split">
        <div class="card">
          <h3>Quick actions</h3>
          <div class="row">
            <button class="btn" id="alertOn" ${can("can_alert") ? "" : "disabled"}>Siren ON</button>
            <button class="btn secondary" id="alertOff" ${can("can_alert") ? "" : "disabled"}>Siren OFF</button>
            <button class="btn secondary" id="selfTest" ${can("can_send_command") ? "" : "disabled"}>Self-test</button>
          </div>
          <div class="row" style="margin-top:10px">
            <input id="rebootDelay" placeholder="Delay seconds (e.g. 30)" style="max-width:200px" />
            <button class="btn secondary" id="doReboot" ${can("can_send_command") ? "" : "disabled"}>Schedule reboot</button>
          </div>
          <div class="row" style="margin-top:14px">
            <button class="btn danger" id="revoke" ${can("can_send_command") ? "" : "disabled"}>Revoke</button>
            <button class="btn secondary" id="unrevoke" ${can("can_send_command") ? "" : "disabled"}>Unrevoke</button>
          </div>
        </div>
        <div class="card">
          <h3>Raw command</h3>
          <label class="field"><span>cmd</span><input id="cmdName" placeholder="get_info / ota" ${can("can_send_command") ? "" : "disabled"} /></label>
          <label class="field" style="margin-top:8px"><span>params (JSON)</span><textarea id="cmdParams" placeholder='{"key":"value"}' ${can("can_send_command") ? "" : "disabled"}></textarea></label>
          <div class="row" style="margin-top:8px;justify-content:flex-end">
            <button class="btn" id="sendCmd" ${can("can_send_command") ? "" : "disabled"}>Send</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row">
          <h3 style="margin:0">Recent messages</h3>
          <span class="muted">last 25</span>
        </div>
        <div class="divider"></div>
        <div class="table-wrap">
          <table class="t">
            <thead><tr><th>Time</th><th>Channel</th><th>Payload</th></tr></thead>
            <tbody>
              ${(msgs.items || []).map((m) => `
                <tr>
                  <td>${escapeHtml(fmtTs(m.ts_received))}</td>
                  <td><span class="chip">${escapeHtml(m.channel || "")}</span></td>
                  <td><pre class="code">${escapeHtml(JSON.stringify(m.payload || {}))}</pre></td>
                </tr>`).join("") || `<tr><td colspan="3" class="muted">No messages</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;

    $("#saveLabel").addEventListener("click", async () => {
      try {
        await api(`/devices/${encodeURIComponent(id)}/display-label`, {
          method: "PATCH",
          body: { display_label: ($("#dispLabel").value || "").trim() },
        });
        toast("Saved", "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });

    const withDev = (fn) => async () => {
      try { await fn(); toast("Sent", "ok"); }
      catch (e) { toast(e.message || e, "err"); }
    };

    $("#alertOn").addEventListener("click", withDev(() =>
      api(`/devices/${encodeURIComponent(id)}/alert/on?duration_ms=10000`, { method: "POST" })));
    $("#alertOff").addEventListener("click", withDev(() =>
      api(`/devices/${encodeURIComponent(id)}/alert/off`, { method: "POST" })));
    $("#selfTest").addEventListener("click", withDev(() =>
      api(`/devices/${encodeURIComponent(id)}/self-test`, { method: "POST" })));
    $("#doReboot").addEventListener("click", withDev(() => {
      const v = parseInt($("#rebootDelay").value, 10);
      if (!Number.isFinite(v) || v < 5) throw new Error("delay must be >= 5 seconds");
      return api(`/devices/${encodeURIComponent(id)}/schedule-reboot`, { method: "POST", body: { delay_s: v } });
    }));
    $("#revoke").addEventListener("click", async () => {
      if (!confirm("Revoke this device?")) return;
      try {
        await api(`/devices/${encodeURIComponent(id)}/revoke`, { method: "POST", body: { reason: "console manual" } });
        toast("Revoked", "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });
    $("#unrevoke").addEventListener("click", withDev(() =>
      api(`/devices/${encodeURIComponent(id)}/unrevoke`, { method: "POST" })));

    $("#sendCmd").addEventListener("click", async () => {
      const name = ($("#cmdName").value || "").trim();
      if (!name) { toast("Enter cmd", "err"); return; }
      let params = {};
      const raw = ($("#cmdParams").value || "").trim();
      if (raw) {
        try { params = JSON.parse(raw); } catch { toast("Invalid JSON in params", "err"); return; }
      }
      try {
        await api(`/devices/${encodeURIComponent(id)}/commands`, { method: "POST", body: { cmd: name, params } });
        toast("Command sent", "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });
  });

  // Alerts
  registerRoute("alerts", async (view) => {
    setCrumb("Siren");
    const enabled = can("can_alert");
    const list = await api("/devices").catch(() => ({ items: [] }));
    const devices = list.items || [];

    view.innerHTML = `
      <div class="card">
        <h2>Bulk siren</h2>
        <p class="muted">MQTT <span class="mono">siren_on</span> / <span class="mono">siren_off</span>. Requires <span class="mono">can_alert</span>.</p>
        ${enabled ? "" : `<p class="badge revoked">No can_alert — ask admin (Policies).</p>`}
        <div class="inline-form" style="margin-top:12px">
          <label class="field"><span>Action</span>
            <select id="action"><option value="on">ON</option><option value="off">OFF</option></select>
          </label>
          <label class="field"><span>Duration (ms)</span>
            <input id="dur" type="number" value="10000" min="500" max="120000" />
          </label>
          <label class="field wide"><span>Targets (empty = all visible)</span>
            <select id="targets" multiple size="6"></select>
          </label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn danger" id="fire" ${enabled ? "" : "disabled"}>Run</button>
          </div>
        </div>
      </div>`;

    const sel = $("#targets");
    sel.innerHTML = devices.map((d) => {
      const lab = d.display_label ? `${escapeHtml(d.display_label)} · ` : "";
      return `<option value="${escapeHtml(d.device_id)}">${lab}${escapeHtml(d.device_id)} · ${escapeHtml(d.zone || "")}</option>`;
    }).join("");

    $("#fire").addEventListener("click", async () => {
      const action = $("#action").value;
      const dur = parseInt($("#dur").value, 10) || 10000;
      const ids = Array.from(sel.selectedOptions).map((o) => o.value);
      if (action === "on" && !confirm(`Siren ON for ${ids.length === 0 ? "ALL visible devices" : ids.length + " device(s)"}?`)) return;
      try {
        const r = await api("/alerts", { method: "POST", body: { action, duration_ms: dur, device_ids: ids } });
        toast(`${action === "on" ? "ON" : "OFF"} → ${r.sent_count} device(s)`, "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });
  });

  // Activate
  registerRoute("activate", async (view) => {
    setCrumb("激活设备");
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">仅管理员可访问。</p></div>`; return; }
    const canClaim = can("can_claim_device");

    view.innerHTML = `
      <div class="card">
        <h2 style="margin-top:0">激活新设备</h2>
        <p class="muted">
          1) 先把 ESP32 通电，连上 Wi-Fi 或网线，等状态灯稳定。<br>
          2) 用手机扫一下设备背面二维码，或把序列号（以 <span class="mono">SN-</span> 开头）抄到下面的框里。<br>
          3) 点击"识别"——系统会告诉你这台设备是：未注册 / 已注册 / 还没联网 / 不在出厂清单。
        </p>
        ${canClaim ? "" : `<p class="badge revoked" style="margin-top:6px">当前账号无 can_claim_device 能力，联系管理员开启。</p>`}
        <div class="inline-form" style="margin-top:10px">
          <label class="field wide"><span>扫描二维码 或 粘贴序列号</span>
            <input id="idn_input" placeholder="SN-XXXXXXXXXXXXXXXX 或 CROC|SN-…|…|…" autocomplete="off"/>
          </label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn secondary" id="idn_go" ${canClaim ? "" : "disabled"}>识别</button>
          </div>
        </div>
        <div id="idnResult" style="margin-top:14px"></div>
      </div>

      <div class="card">
        <div class="row">
          <h3 style="margin:0">最近联网、等待被激活的设备</h3>
          <span class="muted">来自 MQTT 的 bootstrap.register 事件</span>
          <button class="btn secondary right" id="reload">刷新</button>
        </div>
        <div class="divider"></div>
        <div id="pendList"></div>
      </div>`;

    const resultBox = $("#idnResult");
    const drawBadge = (kind, label) =>
      `<span class="badge ${kind === "ok" ? "online" : (kind === "err" ? "offline" : "")}">${escapeHtml(label)}</span>`;

    const showClaimForm = (serial, mac, qr) => {
      resultBox.insertAdjacentHTML("beforeend", `
        <div class="card" style="margin-top:10px">
          <h4 style="margin-top:0">确认认领为你名下</h4>
          <div class="inline-form">
            <label class="field"><span>device_id (=序列号，不建议修改)</span><input id="c_id" value="${escapeHtml(serial)}"/></label>
            <label class="field"><span>mac_nocolon</span><input id="c_mac" value="${escapeHtml(mac)}"/></label>
            <label class="field"><span>zone</span><input id="c_zone" value="all"/></label>
            <label class="field wide"><span>qr_code (可选)</span><input id="c_qr" value="${escapeHtml(qr || "")}"/></label>
            <div class="row wide" style="justify-content:flex-end">
              <button class="btn" id="c_submit">确认认领</button>
            </div>
          </div>
        </div>`);
      $("#c_submit").addEventListener("click", async () => {
        const body = {
          mac_nocolon: ($("#c_mac").value || "").trim().toUpperCase(),
          device_id: ($("#c_id").value || "").trim().toUpperCase(),
          zone: ($("#c_zone").value || "all").trim(),
        };
        const q = ($("#c_qr").value || "").trim();
        if (q) body.qr_code = q;
        try {
          await api("/provision/claim", { method: "POST", body });
          toast("认领成功", "ok");
          renderRoute();
        } catch (e) { toast(e.message || e, "err"); }
      });
    };

    $("#idn_go").addEventListener("click", async () => {
      resultBox.innerHTML = `<p class="muted">识别中…</p>`;
      const raw = ($("#idn_input").value || "").trim();
      if (!raw) { resultBox.innerHTML = `<p class="muted">请输入序列号或扫码结果</p>`; return; }
      const body = raw.startsWith("CROC|") ? { qr_code: raw } : { serial: raw.toUpperCase() };
      try {
        const r = await api("/provision/identify", { method: "POST", body });
        const kv = (k, v) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(v)}</dd>`;
        switch (r.status) {
          case "ready":
            resultBox.innerHTML = `${drawBadge("ok", "✓ 可认领")}
              <dl class="kv">${kv("序列号", r.serial)}${kv("MAC", r.mac_nocolon)}${kv("固件", r.fw || "—")}${kv("最近上报", r.last_seen_at || "—")}</dl>
              <p>${escapeHtml(r.message)}</p>`;
            showClaimForm(r.serial, r.mac_nocolon, raw.startsWith("CROC|") ? raw : "");
            break;
          case "already_registered":
            resultBox.innerHTML = `${drawBadge("err", r.by_you ? "已注册 (属于你)" : "已注册 (非本管理员)")}
              <dl class="kv">${kv("序列号", r.serial)}${kv("device_id", r.device_id)}${kv("归属 admin", r.owner_admin || "—")}${kv("登记时间", r.claimed_at)}</dl>
              <p class="muted">${escapeHtml(r.message)}</p>
              ${r.by_you ? `<a class="btn secondary" href="#/devices/${encodeURIComponent(r.device_id)}">查看该设备</a>` : ""}`;
            break;
          case "offline":
            resultBox.innerHTML = `${drawBadge("", "等待联网")}
              <dl class="kv">${kv("序列号", r.serial)}${r.mac_hint ? kv("出厂 MAC", r.mac_hint) : ""}</dl>
              <p>${escapeHtml(r.message)}</p>`;
            break;
          case "blocked":
            resultBox.innerHTML = `${drawBadge("err", "出厂禁用")}<p>${escapeHtml(r.message)}</p>`;
            break;
          case "unknown_serial":
            resultBox.innerHTML = `${drawBadge("err", "未在出厂清单")}<p>${escapeHtml(r.message)}</p>`;
            break;
          default:
            resultBox.innerHTML = `<p class="muted">未知状态: ${escapeHtml(r.status)}</p>`;
        }
      } catch (e) { resultBox.innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`; }
    });

    $("#reload").addEventListener("click", () => renderRoute());

    try {
      const rq = window.__routeQuery || new URLSearchParams("");
      const pre = (rq.get("q") || rq.get("serial") || "").trim();
      if (pre) {
        const el = $("#idn_input");
        if (el) el.value = pre;
      }
    } catch (_) {}

    const data = await api("/provision/pending").catch(() => ({ items: [] }));
    const items = data.items || [];
    $("#pendList").innerHTML = `
      <div class="table-wrap"><table class="t">
        <thead><tr><th>MAC</th><th>序列号 / 建议ID</th><th>QR</th><th>固件</th><th>上报时间</th></tr></thead>
        <tbody>${items.length === 0 ? `<tr><td colspan="5" class="muted">暂无</td></tr>` :
          items.map((p) => `<tr>
            <td class="mono">${escapeHtml(p.mac_nocolon || p.mac || "")}</td>
            <td class="mono">${escapeHtml(p.proposed_device_id || "—")}</td>
            <td class="mono">${escapeHtml(p.qr_code || "—")}</td>
            <td>${escapeHtml(p.fw || "—")}</td>
            <td>${escapeHtml(fmtTs(p.last_seen_at))}</td>
          </tr>`).join("")}</tbody>
      </table></div>`;
  });

  // Event Center — global live + historical log stream
  // NOTE: SSE isn't automatically torn down on route change, so we stash the
  // active EventSource on window so leaving the page closes it.
  registerRoute("events", async (view) => {
    setCrumb("事件中心");
    const me = state.me || { username: "", role: "" };
    const isSuper = me.role === "superadmin";
    const scopeLabel = isSuper ? "全局（superadmin）" : (me.role === "admin" ? `我的租户 · ${escapeHtml(me.username)}` : `我的上级租户`);

    view.innerHTML = `
      <div class="card">
        <div class="row between" style="flex-wrap:wrap;gap:10px">
          <div>
            <h2 style="margin:0">事件中心</h2>
            <p class="muted" style="margin:4px 0 0">范围：${scopeLabel} · 超管可见全部；管理员默认仅本租户；用户仅与自己相关 + warn+</p>
          </div>
          <div class="row" style="gap:8px;align-items:center">
            <span id="evLive" class="badge offline" title="实时连接状态">离线</span>
            <button class="btn sm secondary" id="evPause">暂停</button>
            <button class="btn sm secondary" id="evClear">清空</button>
          </div>
        </div>
        <div class="divider"></div>
        <div class="inline-form" style="margin-bottom:10px">
          <label class="field"><span>最低级别</span>
            <select id="evLevel">
              <option value="">全部</option>
              <option value="debug">debug+</option>
              <option value="info" selected>info+</option>
              <option value="warn">warn+</option>
              <option value="error">error+</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label class="field"><span>分类</span>
            <select id="evCategory">
              <option value="">全部</option>
              <option value="alarm">alarm</option>
              <option value="ota">ota</option>
              <option value="presence">presence</option>
              <option value="provision">provision</option>
              <option value="device">device</option>
              <option value="auth">auth</option>
              <option value="audit">audit</option>
              <option value="system">system</option>
            </select>
          </label>
          <label class="field"><span>设备 ID</span><input id="evDevice" placeholder="SN-... 或 dev_id" /></label>
          <label class="field wide"><span>关键词</span><input id="evQ" placeholder="搜索摘要 / actor / event_type" /></label>
          <div class="row wide" style="justify-content:flex-end;gap:8px;flex-wrap:wrap">
            <button class="btn sm secondary" id="evApply">应用筛选</button>
            <button class="btn sm" id="evReload">历史 200 条</button>
            <button class="btn sm secondary" id="evStats">设备统计(7天)</button>
            <button class="btn sm secondary" id="evCsv">导出 CSV</button>
          </div>
        </div>
      </div>
      <div id="evStatsBox" class="card" style="margin-top:12px;display:none">
        <h3 style="margin:0 0 8px">按设备事件数（最近 7 天）</h3>
        <div id="evStatsInner" class="muted">—</div>
      </div>
      <div class="card" style="margin-top:12px">
        <div id="evList" class="events-list muted">连接中…</div>
      </div>`;

    let paused = false;
    let buffer = [];  // newest first
    const BUFFER_MAX = 500;

    function badgeClass(lvl) {
      return ({
        debug: "neutral", info: "accent", warn: "partial",
        error: "failed", critical: "revoked",
      })[lvl] || "neutral";
    }
    function catClass(cat) {
      return ({
        alarm: "failed", ota: "accent", presence: "partial",
        provision: "accent", device: "neutral", auth: "partial",
        audit: "neutral", system: "neutral",
      })[cat] || "neutral";
    }
    function rowHtml(e) {
      const summary = e.summary || e.event_type || "";
      const tsShort = (e.ts || "").replace("T", " ").replace(/\..*/, "");
      const dev = e.device_id ? `<span class="chip mono">${escapeHtml(e.device_id)}</span>` : "";
      const owner = e.owner_admin ? `<span class="chip">@${escapeHtml(e.owner_admin)}</span>` : "";
      const detailTxt = (e.detail && Object.keys(e.detail).length) ? JSON.stringify(e.detail) : "";
      return `<div class="ev-row" data-level="${escapeHtml(e.level || "")}">
        <span class="ev-ts mono">${escapeHtml(tsShort)}</span>
        <span class="badge ${badgeClass(e.level)}">${escapeHtml(e.level || "")}</span>
        <span class="badge ${catClass(e.category)}">${escapeHtml(e.category || "")}</span>
        <span class="ev-type mono">${escapeHtml(e.event_type || "")}</span>
        <span class="ev-actor">${escapeHtml(e.actor || "")}</span>
        <span class="ev-summary">${escapeHtml(summary)}</span>
        ${dev} ${owner}
        ${detailTxt ? `<details class="ev-detail"><summary class="muted">详情</summary><pre class="code">${escapeHtml(detailTxt)}</pre></details>` : ""}
      </div>`;
    }
    function flushEvRender() {
      const listEl = document.getElementById("evList");
      if (!listEl) return;
      if (buffer.length === 0) {
        listEl.innerHTML = `<p class="muted">无事件。</p>`;
        return;
      }
      listEl.innerHTML = buffer.map(rowHtml).join("");
    }
    function scheduleEvRender() {
      if (window.__pendingEvListRaf) return;
      window.__pendingEvListRaf = requestAnimationFrame(() => {
        window.__pendingEvListRaf = 0;
        flushEvRender();
      });
    }
    function pushEvent(ev) {
      if (paused) return;
      buffer.unshift(ev);
      if (buffer.length > BUFFER_MAX) buffer.length = BUFFER_MAX;
      scheduleEvRender();
    }
    function currentFilters() {
      const p = new URLSearchParams();
      const lvl = $("#evLevel").value.trim(); if (lvl) p.set("min_level", lvl);
      const cat = $("#evCategory").value.trim(); if (cat) p.set("category", cat);
      const dev = $("#evDevice").value.trim(); if (dev) p.set("device_id", dev);
      const q = $("#evQ").value.trim(); if (q) p.set("q", q);
      return p;
    }

    async function loadHistory() {
      try {
        const p = currentFilters(); p.set("limit", "200");
        const r = await api("/events?" + p.toString());
        buffer = (r.items || []).slice();
        if (window.__pendingEvListRaf) {
          cancelAnimationFrame(window.__pendingEvListRaf);
          window.__pendingEvListRaf = 0;
        }
        flushEvRender();
      } catch (e) { toast(e.message || e, "err"); }
    }

    function closeStream() {
      if (window.__evSSE) { try { window.__evSSE.close(); } catch {} window.__evSSE = null; }
      $("#evLive").textContent = "离线"; $("#evLive").className = "badge offline";
    }
    function openStream() {
      closeStream();
      const p = currentFilters();
      p.set("token", getToken());
      p.set("backlog", String(Math.min(100, BUFFER_MAX - buffer.length)));
      const url = apiBase() + "/events/stream?" + p.toString();
      const es = new EventSource(url);
      window.__evSSE = es;
      es.onopen = () => { $("#evLive").textContent = "实时"; $("#evLive").className = "badge online"; };
      es.onerror = () => {
        $("#evLive").textContent = "重连中…"; $("#evLive").className = "badge offline";
      };
      es.onmessage = (m) => {
        try {
          const ev = JSON.parse(m.data);
          if (ev.event_type === "stream.hello") return;
          pushEvent(ev);
        } catch {}
      };
    }

    $("#evPause").addEventListener("click", () => {
      paused = !paused;
      $("#evPause").textContent = paused ? "恢复" : "暂停";
    });
    $("#evClear").addEventListener("click", () => {
      buffer = [];
      if (window.__pendingEvListRaf) {
        cancelAnimationFrame(window.__pendingEvListRaf);
        window.__pendingEvListRaf = 0;
      }
      flushEvRender();
    });
    $("#evApply").addEventListener("click", () => { loadHistory().then(openStream); });
    $("#evReload").addEventListener("click", loadHistory);
    $("#evStats").addEventListener("click", async () => {
      try {
        const r = await api("/events/stats/by-device?hours=168&limit=200");
        const items = r.items || [];
        $("#evStatsBox").style.display = "block";
        if (items.length === 0) {
          $("#evStatsInner").innerHTML = "<p class='muted'>无带 device_id 的事件。</p>";
          return;
        }
        $("#evStatsInner").innerHTML = `<div class="table-wrap"><table class="t"><thead><tr><th>设备</th><th>条数</th></tr></thead><tbody>${
          items.map((x) => `<tr><td class="mono">${escapeHtml(x.device_id)}</td><td>${x.count}</td></tr>`).join("")
        }</tbody></table></div>`;
      } catch (e) { toast(e.message || e, "err"); }
    });
    $("#evCsv").addEventListener("click", async () => {
      try {
        const p = currentFilters();
        p.set("limit", "8000");
        const url = apiBase() + "/events/export.csv?" + p.toString();
        const r = await fetch(url, { headers: { Authorization: "Bearer " + getToken() } });
        if (!r.ok) {
          const t = await r.text();
          throw new Error(t || r.statusText);
        }
        const blob = await r.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "croc_sentinel_events.csv";
        a.click();
        URL.revokeObjectURL(a.href);
        toast("已下载 CSV", "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });

    await loadHistory();
    openStream();
    window.__eventsStreamResume = () => {
      if (paused) return;
      openStream();
    };
  });

  // Audit
  registerRoute("audit", async (view) => {
    setCrumb("审计");
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">仅管理员可访问。</p></div>`; return; }
    view.innerHTML = `
      <div class="card">
        <div class="row">
          <h2 style="margin:0">审计事件</h2>
          <label class="field" style="max-width:180px"><span>actor</span><input id="f_actor" /></label>
          <label class="field" style="max-width:180px"><span>action 前缀</span><input id="f_action" placeholder="device / user / command" /></label>
          <label class="field" style="max-width:180px"><span>target</span><input id="f_target" /></label>
          <button class="btn secondary right" id="f_reload">查询</button>
        </div>
        <div class="divider"></div>
        <div id="auditList"></div>
      </div>`;

    const reload = async () => {
      const qs = new URLSearchParams();
      const a = $("#f_actor").value.trim(); if (a) qs.set("actor", a);
      const ac = $("#f_action").value.trim(); if (ac) qs.set("action", ac);
      const t = $("#f_target").value.trim(); if (t) qs.set("target", t);
      qs.set("limit", "150");
      try {
        const d = await api("/audit?" + qs.toString());
        const items = d.items || [];
        $("#auditList").innerHTML = items.length === 0
          ? `<p class="muted">无记录。</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>时间</th><th>actor</th><th>action</th><th>target</th><th>detail</th></tr></thead>
              <tbody>${items.map((e) => `
                <tr>
                  <td>${escapeHtml(fmtTs(e.created_at))}</td>
                  <td>${escapeHtml(e.actor)}</td>
                  <td><span class="chip">${escapeHtml(e.action)}</span></td>
                  <td class="mono">${escapeHtml(e.target || "")}</td>
                  <td><pre class="code">${escapeHtml(JSON.stringify(e.detail || {}))}</pre></td>
                </tr>`).join("")}</tbody></table></div>`;
      } catch (e) { toast(e.message || e, "err"); }
    };
    $("#f_reload").addEventListener("click", reload);
    reload();
  });

  // Admin
  registerRoute("admin", async (view) => {
    setCrumb("系统管理");
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">仅管理员可访问。</p></div>`; return; }
    const isSuper = state.me.role === "superadmin";
    let admins = [];
    if (isSuper) {
      try { admins = (await api("/auth/admins")).items || []; } catch { admins = []; }
    }

    view.innerHTML = `
      <div class="card">
        <h2>用户管理</h2>
        <p class="muted">${isSuper
          ? "superadmin：可创建 admin/user，并为任意 user 设置 manager_admin 与策略。"
          : "admin：仅能管理自己名下的 user，并可开/关其能力。"}</p>
        <div class="row right-end" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
          <button class="btn btn-tap" id="showCreate" type="button">新增用户</button>
          <button class="btn secondary btn-tap" id="reloadUsers" type="button">刷新</button>
        </div>
        <div class="divider"></div>
        <div id="userTable"></div>
      </div>

      <div class="card" id="createPanel" style="display:none">
        <h3>新增用户</h3>
        <div class="inline-form">
          <label class="field"><span>用户名</span><input id="u_name" autocomplete="off" /></label>
          <label class="field"><span>密码（≥8位）</span><input id="u_pass" type="password" autocomplete="new-password" /></label>
          <label class="field"><span>角色</span><select id="u_role">
            ${isSuper
              ? `<option value="user">user</option><option value="admin">admin</option>`
              : `<option value="user">user</option>`}
          </select></label>
          <label class="field" id="u_mgr_wrap" ${isSuper ? "" : 'style="display:none"'}>
            <span>归属管理员 (manager_admin)</span>
            <select id="u_mgr">${admins.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join("")}</select>
          </label>
          <label class="field"><span>邮箱 (必填，收激活码)</span><input id="u_email" type="email" autocomplete="off"/></label>
          <label class="field"><span>tenant（可选）</span><input id="u_tenant" /></label>
          <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
            <button class="btn ghost btn-tap" id="u_cancel" type="button">取消</button>
            <button class="btn btn-tap" id="u_submit" type="button">创建并发邮件激活码</button>
          </div>
          <p class="muted" style="margin:8px 0 0">
            新用户状态为 <span class="mono">pending</span>；必须让该用户在
            <a href="#/account-activate">激活账号</a> 页输入邮箱收到的验证码后才能登录。
          </p>
        </div>
      </div>

      ${isSuper ? `<div class="card">
        <h3>待审批的管理员注册</h3>
        <p class="muted">通过公开注册页提交、已完成邮箱验证、等待你批准的 admin 账号。</p>
        <div id="pendAdmins"></div>
      </div>` : ""}

      <div class="card">
        <h3>告警邮件收件人</h3>
        <p class="muted">这些邮箱会在你所管设备发生警报时收到通知（服务端 SMTP 需已配置）。</p>
        <div id="smtpStatus" class="row" style="gap:6px"></div>
        <div class="divider"></div>
        <div class="inline-form">
          <label class="field wide"><span>邮箱</span><input id="r_email" type="email" autocomplete="off" placeholder="you@company.com"/></label>
          <label class="field"><span>标签</span><input id="r_label" autocomplete="off" placeholder="值班 / 老板"/></label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn" id="r_add">添加</button>
            <button class="btn ghost" id="r_test">发送测试邮件</button>
          </div>
        </div>
        <div id="recipientList" style="margin-top:10px"></div>
      </div>

      <div class="card">
        <h3>Telegram</h3>
        <p class="muted">Forwards <span class="mono">emit_event</span> from server env (<span class="mono">TELEGRAM_BOT_TOKEN</span>, <span class="mono">TELEGRAM_CHAT_IDS</span>). Test does not use the queue.</p>
        <div id="tgStatus" class="row" style="gap:6px;flex-wrap:wrap"></div>
        <div class="row" style="margin-top:10px">
          <button class="btn secondary" id="tgTest" type="button">Send test to all chats</button>
        </div>
      </div>

      ${isSuper ? `<div class="card">
        <h3>数据库备份 / 恢复</h3>
        <p class="muted">调用 <span class="mono">/admin/backup/export</span> 与 <span class="mono">/admin/backup/import</span>：整库 SQLite 按口令加密为 .enc。导入会写入 <span class="mono">*.restored</span>，需按提示停机替换。</p>
        <label class="field" style="max-width:420px">
          <span>加密口令 <span class="muted">X-Backup-Encryption-Key</span></span>
          <input id="bk_key" type="password" autocomplete="off" />
        </label>
        <div class="row" style="margin-top:10px">
          <button class="btn" id="bk_export">导出 .enc</button>
          <input type="file" id="bk_file" accept=".enc,application/octet-stream" />
          <button class="btn secondary" id="bk_import">上传 + 解密</button>
        </div>
      </div>` : ""}`;

    // users
    const loadUsers = async () => {
      try {
        const d = await api("/auth/users");
        const users = d.items || [];
        $("#userTable").innerHTML = users.length === 0
          ? `<p class="muted">暂无。</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>用户</th><th>角色</th><th>manager</th><th>tenant</th><th>创建</th><th></th></tr></thead>
              <tbody>${users.map((u) => {
                const isUser = u.role === "user";
                const self = u.username === (state.me && state.me.username);
                return `<tr>
                  <td><strong>${escapeHtml(u.username)}</strong></td>
                  <td><span class="chip">${escapeHtml(u.role)}</span></td>
                  <td class="mono">${escapeHtml(u.manager_admin || "—")}</td>
                  <td class="mono">${escapeHtml(u.tenant || "—")}</td>
                  <td>${escapeHtml(fmtTs(u.created_at))}</td>
                  <td>
                    ${isUser ? `<button class="btn sm secondary js-pol" data-u="${escapeHtml(u.username)}">策略</button>` : ""}
                    ${self ? "" : `<button class="btn sm danger js-del" data-u="${escapeHtml(u.username)}">删除</button>`}
                  </td>
                </tr><tr class="sub" style="display:none" data-pol-row="${escapeHtml(u.username)}"><td colspan="6"></td></tr>`;
              }).join("")}</tbody></table></div>`;
      } catch (e) {
        $("#userTable").innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`;
      }
    };

    $("#reloadUsers").addEventListener("click", loadUsers);
    $("#showCreate").addEventListener("click", () => {
      $("#createPanel").style.display = "";
      $("#createPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $("#u_cancel").addEventListener("click", () => { $("#createPanel").style.display = "none"; });
    $("#u_submit").addEventListener("click", async () => {
      const body = {
        username: $("#u_name").value.trim(),
        password: $("#u_pass").value,
        role: $("#u_role").value,
      };
      if (!body.username || !body.password) { toast("请填写用户名和密码", "err"); return; }
      const email = $("#u_email").value.trim();
      if (!email) { toast("必须填写邮箱——新用户要用它激活账号", "err"); return; }
      body.email = email;
      const tenant = $("#u_tenant").value.trim(); if (tenant) body.tenant = tenant;
      if (isSuper && body.role === "user") body.manager_admin = $("#u_mgr").value;
      try {
        const resp = await api("/auth/users", { method: "POST", body });
        toast(`创建成功：${resp.message || "已发送验证码"}`, "ok");
        $("#createPanel").style.display = "none";
        $("#u_name").value = ""; $("#u_pass").value = ""; $("#u_tenant").value = "";
        $("#u_email").value = "";
        loadUsers();
      } catch (e) { toast(e.message || e, "err"); }
    });

    const openPolicy = async (username, trRow) => {
      const cell = trRow.querySelector("td");
      cell.innerHTML = `<span class="muted">加载中…</span>`;
      trRow.style.display = "";
      try {
        const p = await api(`/auth/users/${encodeURIComponent(username)}/policy`);
        cell.innerHTML = renderPolicyPanel(username, p);
        cell.querySelector(".js-save").addEventListener("click", async () => {
          const body = {};
          cell.querySelectorAll("input[type=checkbox][data-k]").forEach((i) => body[i.dataset.k] = !!i.checked);
          try {
            const r = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { method: "PUT", body });
            toast(`${username} 策略已更新`, "ok");
            cell.innerHTML = renderPolicyPanel(username, r.policy || r);
            cell.querySelector(".js-save").addEventListener("click", () => openPolicy(username, trRow));
          } catch (e) { toast(e.message || e, "err"); }
        });
      } catch (e) { cell.innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`; }
    };

    $("#userTable").addEventListener("click", async (ev) => {
      const t = ev.target.closest("button");
      if (!t) return;
      const u = t.dataset.u;
      if (t.classList.contains("js-del")) {
        if (!confirm(`确定删除用户 ${u} ?`)) return;
        try { await api(`/auth/users/${encodeURIComponent(u)}`, { method: "DELETE" }); toast("已删除", "ok"); loadUsers(); }
        catch (e) { toast(e.message || e, "err"); }
      }
      if (t.classList.contains("js-pol")) {
        const row = view.querySelector(`tr[data-pol-row="${CSS.escape(u)}"]`);
        if (!row) return;
        if (row.style.display === "") { row.style.display = "none"; return; }
        openPolicy(u, row);
      }
    });

    // backup
    if (isSuper) {
      $("#bk_export").addEventListener("click", async () => {
        const key = ($("#bk_key").value || "").trim();
        if (!key) { toast("请填写加密口令", "err"); return; }
        try {
          const r = await fetch(apiBase() + "/admin/backup/export", {
            headers: { Authorization: "Bearer " + getToken(), "X-Backup-Encryption-Key": key },
          });
          if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
          const blob = new Blob([await r.arrayBuffer()], { type: "application/octet-stream" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob); a.download = "sentinel-backup.enc"; a.click();
          URL.revokeObjectURL(a.href);
          toast("已下载", "ok");
        } catch (e) { toast(e.message || e, "err"); }
      });
      $("#bk_import").addEventListener("click", async () => {
        const key = ($("#bk_key").value || "").trim();
        const f = $("#bk_file").files[0];
        if (!key || !f) { toast("请选择文件并填写加密口令", "err"); return; }
        const fd = new FormData(); fd.append("file", f, f.name || "sentinel-backup.enc");
        try {
          const r = await fetch(apiBase() + "/admin/backup/import", {
            method: "POST",
            headers: { Authorization: "Bearer " + getToken(), "X-Backup-Encryption-Key": key },
            body: fd,
          });
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(`${r.status} ${j.detail || ""}`);
          toast("已写入: " + (j.written_path || "done"), "ok");
        } catch (e) { toast(e.message || e, "err"); }
      });
    }

    // SMTP status + recipients
    const loadSmtpStatus = async () => {
      try {
        const s = await api("/admin/smtp/status");
        const okBadge = s.enabled
          ? `<span class="badge online">SMTP on</span>`
          : `<span class="badge offline">SMTP off</span>`;
        const last = s.last_error ? `<span class="chip" title="last error">${escapeHtml(s.last_error)}</span>` : "";
        $("#smtpStatus").innerHTML = `${okBadge}
          <span class="chip">host: ${escapeHtml(s.host || "—")}:${escapeHtml(String(s.port || "—"))}</span>
          <span class="chip">mode: ${escapeHtml(s.mode || "—")}</span>
          <span class="chip">from: ${escapeHtml(s.sender || "—")}</span>
          <span class="chip">sent: ${s.sent_count || 0}</span>
          <span class="chip">failed: ${s.failed_count || 0}</span>
          <span class="chip">queue: ${s.queue_size ?? 0}/${s.queue_max ?? ""}</span>${last}`;
      } catch (e) {
        $("#smtpStatus").innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`;
      }
    };
    const loadRecipients = async () => {
      try {
        const d = await api("/admin/alert-recipients");
        const items = d.items || [];
        $("#recipientList").innerHTML = items.length === 0
          ? `<p class="muted">尚未配置任何收件人。</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>邮箱</th><th>标签</th><th>启用</th><th>租户</th><th></th></tr></thead>
              <tbody>${items.map((r) => `
                <tr>
                  <td class="mono">${escapeHtml(r.email)}</td>
                  <td>${escapeHtml(r.label || "—")}</td>
                  <td>${r.enabled ? `<span class="badge online">启用</span>` : `<span class="badge offline">关闭</span>`}</td>
                  <td class="mono">${escapeHtml(r.owner_admin || "")}</td>
                  <td>
                    <button class="btn sm secondary js-rtoggle" data-id="${r.id}" data-en="${r.enabled ? 1 : 0}">${r.enabled ? "停用" : "启用"}</button>
                    <button class="btn sm danger js-rdel" data-id="${r.id}">删除</button>
                  </td>
                </tr>`).join("")}</tbody></table></div>`;
      } catch (e) {
        $("#recipientList").innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`;
      }
    };
    $("#r_add").addEventListener("click", async () => {
      const email = ($("#r_email").value || "").trim();
      const label = ($("#r_label").value || "").trim();
      if (!email) { toast("请填写邮箱", "err"); return; }
      try {
        await api("/admin/alert-recipients", { method: "POST", body: { email, label } });
        $("#r_email").value = ""; $("#r_label").value = "";
        toast("已添加", "ok");
        loadRecipients();
      } catch (e) { toast(e.message || e, "err"); }
    });
    $("#r_test").addEventListener("click", async () => {
      const email = ($("#r_email").value || "").trim();
      if (!email) { toast("Enter recipient email first", "err"); return; }
      try {
        await api("/admin/smtp/test", { method: "POST", body: { to: email } });
        toast("SMTP test sent", "ok");
        loadSmtpStatus();
      } catch (e) { toast(e.message || e, "err"); }
    });
    const loadTgStatus = async () => {
      try {
        const t = await api("/admin/telegram/status");
        const badge = t.enabled
          ? `<span class="badge online">enabled</span>`
          : `<span class="badge offline">disabled</span>`;
        $("#tgStatus").innerHTML = `${badge}
          <span class="chip">chats: ${t.chats ?? 0}</span>
          <span class="chip">min_level: ${escapeHtml(t.min_level || "")}</span>
          <span class="chip">queue: ${t.queue_size ?? 0}</span>`;
      } catch (e) {
        $("#tgStatus").innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`;
      }
    };
    $("#tgTest").addEventListener("click", async () => {
      try {
        const r = await api("/admin/telegram/test", { method: "POST", body: { text: "Croc Sentinel UI test" } });
        toast(r.detail || "ok", "ok");
        loadTgStatus();
      } catch (e) { toast(e.message || e, "err"); }
    });
    $("#recipientList").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      const id = b.dataset.id;
      if (b.classList.contains("js-rdel")) {
        if (!confirm("删除这个收件人？")) return;
        try { await api(`/admin/alert-recipients/${id}`, { method: "DELETE" }); toast("已删除", "ok"); loadRecipients(); }
        catch (e) { toast(e.message || e, "err"); }
      }
      if (b.classList.contains("js-rtoggle")) {
        const en = b.dataset.en === "1" ? 0 : 1;
        try { await api(`/admin/alert-recipients/${id}`, { method: "PATCH", body: { enabled: !!en } }); loadRecipients(); }
        catch (e) { toast(e.message || e, "err"); }
      }
    });
    loadSmtpStatus();
    loadRecipients();
    loadTgStatus();

    // Pending admin signups (superadmin approval queue)
    const loadPendAdmins = async () => {
      if (!isSuper) return;
      try {
        const d = await api("/auth/signup/pending");
        const items = d.items || [];
        $("#pendAdmins").innerHTML = items.length === 0
          ? `<p class="muted">没有待审批。</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>用户名</th><th>邮箱</th><th>提交时间</th><th>邮箱已验</th><th></th></tr></thead>
              <tbody>${items.map((u) => `<tr>
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td class="mono">${escapeHtml(u.email || "—")}</td>
                <td>${escapeHtml(fmtTs(u.created_at))}</td>
                <td>${u.email_verified_at ? "✓" : "—"}</td>
                <td>
                  <button class="btn sm js-ok" data-u="${escapeHtml(u.username)}">批准</button>
                  <button class="btn sm danger js-reject" data-u="${escapeHtml(u.username)}">拒绝</button>
                </td>
              </tr>`).join("")}</tbody></table></div>`;
      } catch (e) {
        $("#pendAdmins").innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`;
      }
    };
    if (isSuper) {
      $("#pendAdmins").addEventListener("click", async (ev) => {
        const b = ev.target.closest("button"); if (!b) return;
        const u = b.dataset.u;
        if (b.classList.contains("js-ok")) {
          try { await api(`/auth/signup/approve/${encodeURIComponent(u)}`, { method: "POST" }); toast("已批准", "ok"); loadPendAdmins(); loadUsers(); }
          catch (e) { toast(e.message || e, "err"); }
        } else if (b.classList.contains("js-reject")) {
          if (!confirm(`确定拒绝并删除管理员注册申请: ${u} ?`)) return;
          try { await api(`/auth/signup/reject/${encodeURIComponent(u)}`, { method: "POST" }); toast("已拒绝", "ok"); loadPendAdmins(); }
          catch (e) { toast(e.message || e, "err"); }
        }
      });
      loadPendAdmins();
    }

    loadUsers();
  });

  // Unified: device alarms + dashboard/API remote siren (who / what / when / where / fan-out)
  async function renderSignalsPage(view) {
    setCrumb("Signals");
    view.innerHTML = `
      <div class="card">
        <div class="row">
          <h2 style="margin:0">Signal log</h2>
          <span class="muted">Device alarms + remote siren from dashboard/API</span>
          <label class="field" style="max-width:140px"><span>Hours</span><input id="sig_hours" type="number" value="168" min="1" max="720"/></label>
          <button class="btn secondary right" id="sig_reload">Refresh</button>
        </div>
        <div class="divider"></div>
        <div class="stats" id="sigSummary"></div>
        <div class="divider"></div>
        <div id="sigList"></div>
      </div>`;
    const reload = async () => {
      const hours = parseInt($("#sig_hours").value, 10) || 168;
      const qs = new URLSearchParams({ limit: "200", since_hours: String(hours) });
      try {
        const [d, sumR] = await Promise.all([
          api("/activity/signals?" + qs.toString()),
          api("/alarms/summary").catch(() => ({ last_24h: 0, last_7d: 0, top_sources_7d: [] })),
        ]);
        $("#sigSummary").innerHTML = [
          ["Alarms 24h", sumR.last_24h || 0, "device-side alarm rows"],
          ["Alarms 7d", sumR.last_7d || 0, "same scope"],
          ["Top source 7d", (sumR.top_sources_7d || []).slice(0, 1).map((x) => `${x.source_id} × ${x.c}`).join("") || "—", "by count"],
        ].map(([k, v, s]) => `<div class="stat"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div><div class="sub">${escapeHtml(s)}</div></div>`).join("");
        const items = d.items || [];
        const whoLbl = (w) => ({
          remote_button: "GPIO / local button",
          network: "MQTT / network",
          api: "API / automation",
        }[w] || w);
        $("#sigList").innerHTML = items.length === 0
          ? `<p class="muted">No rows in this window.</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>When (UTC)</th><th>What</th><th>Where</th><th>Device</th><th>Name</th><th>Who</th><th>Fan-out / targets</th><th>Email</th></tr></thead>
              <tbody>${items.map((a) => {
            const dev = a.device_id === "*" ? "(bulk)" : a.device_id;
            const link = a.device_id && a.device_id !== "*"
              ? `<a class="mono" href="#/devices/${encodeURIComponent(a.device_id)}">${escapeHtml(dev)}</a>`
              : escapeHtml(dev);
            const em = a.email_sent ? "queued" : (a.email_detail || "—");
            const fo = a.kind && a.kind.startsWith("bulk") ? String(a.fanout_count || 0) : String(a.fanout_count ?? "—");
            return `<tr>
                  <td>${escapeHtml(fmtTs(a.ts))}</td>
                  <td><span class="chip">${escapeHtml(a.what || a.kind || "")}</span></td>
                  <td><span class="chip">${escapeHtml(a.zone || "all")}</span></td>
                  <td class="mono">${link}</td>
                  <td>${escapeHtml(a.display_label || "—")}</td>
                  <td>${escapeHtml(a.kind === "device_alarm" ? whoLbl(a.who) : a.who)}</td>
                  <td class="mono">${escapeHtml(fo)}</td>
                  <td class="mono">${escapeHtml(em)}</td>
                </tr>`;
          }).join("")}</tbody></table></div>`;
      } catch (e) { toast(e.message || e, "err"); }
    };
    $("#sig_reload").addEventListener("click", reload);
    reload();
  }
  registerRoute("signals", renderSignalsPage);

  // OTA (superadmin only)
  function renderOtaCampaignRow(c, me) {
    const myDec = (c.decisions || []).find((d) => d.admin_username === me.username);
    const decLabel = myDec ? (
      { accepted: "已接受", declined: "已拒绝", rolled_back: "已回滚" }[myDec.action] || myDec.action
    ) : (me.role === "superadmin" ? "—" : "待决策");
    const co = c.counters || {};
    const counters = ["pending","dispatched","success","failed","rolled_back"]
      .filter((k) => co[k])
      .map((k) => `<span class="badge" title="${k}">${k}:${co[k]}</span>`)
      .join(" ");
    return `
      <tr>
        <td class="mono">${escapeHtml(c.id)}</td>
        <td>${escapeHtml(c.fw_version)}</td>
        <td class="mono" style="max-width:320px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(c.url)}</td>
        <td><span class="badge ${c.state}">${escapeHtml(c.state)}</span></td>
        <td>${counters || "<span class='muted'>—</span>"}</td>
        <td>${escapeHtml(decLabel)}</td>
        <td>${escapeHtml(c.created_at)}</td>
        <td>
          ${(me.role === "admin" && (!myDec || myDec.action === "declined"))
              ? `<button class="btn sm js-accept" data-id="${escapeHtml(c.id)}">升级</button>
                 <button class="btn sm secondary js-decline" data-id="${escapeHtml(c.id)}">拒绝</button>`
              : ""}
          ${(myDec && myDec.action === "accepted")
              ? `<button class="btn sm danger js-rollback" data-id="${escapeHtml(c.id)}">回滚</button>`
              : ""}
          <button class="btn sm secondary js-detail" data-id="${escapeHtml(c.id)}">详情</button>
        </td>
      </tr>`;
  }

  registerRoute("ota", async (view) => {
    setCrumb("OTA 更新");
    const me = state.me || { username: "", role: "" };
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">OTA 更新仅对 admin 及以上开放。</p></div>`; return; }
    const isSuper = me.role === "superadmin";

    view.innerHTML = `
      ${isSuper ? `
      <div class="card">
        <h2>下发新 OTA 活动</h2>
        <p class="muted">
          流程：超管在此填写固件版本 + 下载地址 → admin 在各自仪表盘看到
          <strong>待决策</strong>，点击「升级」时服务器先 HEAD 校验 URL 再推送到该
          admin 名下所有设备。任一设备失败会自动回滚到升级前的固件。
        </p>
        <div id="fwList" class="muted">加载固件清单…</div>
        <div class="divider"></div>
        <div class="inline-form" style="margin-top:10px">
          <label class="field"><span>固件版本 *</span><input id="c_fw" placeholder="2.2.0" /></label>
          <label class="field wide"><span>下载 URL *</span><input id="c_url" placeholder="https://你的.vps/fw/sentinel-v2.2.0.bin" /></label>
          <label class="field"><span>SHA-256（可选）</span><input id="c_sha" placeholder="64 hex" /></label>
          <label class="field wide"><span>目标 admin（留空 = 全部 admin）</span>
            <input id="c_admins" placeholder="admin-a, admin-b  或留空" />
          </label>
          <label class="field wide"><span>备注</span><input id="c_notes" maxlength="500" /></label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn danger" id="c_send">发起活动</button>
          </div>
        </div>
      </div>` : ""}
      <div class="card">
        <div class="row between">
          <h2 style="margin:0">OTA 活动</h2>
          <button class="btn sm secondary" id="camp_reload">刷新</button>
        </div>
        <div id="campList" class="muted" style="margin-top:8px">加载中…</div>
      </div>
      <div id="campDetail"></div>`;

    async function loadCampaigns() {
      try {
        const r = await api("/ota/campaigns");
        const list = r.items || [];
        if (list.length === 0) {
          $("#campList").innerHTML = `<p class="muted">暂无 OTA 活动。</p>`;
          return;
        }
        $("#campList").innerHTML = `<div class="table-wrap"><table class="t">
          <thead><tr><th>ID</th><th>版本</th><th>URL</th><th>状态</th><th>设备进度</th><th>我的决策</th><th>创建</th><th></th></tr></thead>
          <tbody>${list.map((c) => renderOtaCampaignRow(c, me)).join("")}</tbody>
        </table></div>`;

        view.querySelectorAll(".js-accept").forEach((b) => b.addEventListener("click", async () => {
          if (!confirm("确认升级？服务器将先验证 URL 再推送到你名下所有设备。")) return;
          try {
            const r2 = await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}/accept`, { method: "POST", body: {} });
            toast(`已下发 ${r2.dispatched}/${r2.target_count} 台，校验：${r2.verify}`, "ok");
            loadCampaigns();
          } catch (e) { toast(e.message || e, "err"); }
        }));
        view.querySelectorAll(".js-decline").forEach((b) => b.addEventListener("click", async () => {
          if (!confirm("拒绝这次升级？")) return;
          try { await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}/decline`, { method: "POST", body: {} }); loadCampaigns(); }
          catch (e) { toast(e.message || e, "err"); }
        }));
        view.querySelectorAll(".js-rollback").forEach((b) => b.addEventListener("click", async () => {
          if (!confirm("确认回滚？已升级设备会被推回升级前的固件。")) return;
          try { const r2 = await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}/rollback`, { method: "POST", body: {} }); toast(`回滚 ${r2.rolled_back} 台`, "ok"); loadCampaigns(); }
          catch (e) { toast(e.message || e, "err"); }
        }));
        view.querySelectorAll(".js-detail").forEach((b) => b.addEventListener("click", async () => {
          try {
            const c = await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}`);
            $("#campDetail").innerHTML = `<div class="card">
              <h3>活动 ${escapeHtml(c.id)}</h3>
              <p class="muted">FW ${escapeHtml(c.fw_version)} · ${escapeHtml(c.state)} · 创建于 ${escapeHtml(c.created_at)}</p>
              <p class="mono" style="word-break:break-all">${escapeHtml(c.url)}</p>
              <h4 style="margin:12px 0 4px">设备执行</h4>
              <div class="table-wrap"><table class="t">
                <thead><tr><th>admin</th><th>设备</th><th>之前 fw</th><th>目标 fw</th><th>状态</th><th>错误</th><th>完成</th></tr></thead>
                <tbody>${(c.device_runs || []).map((r) => `
                  <tr>
                    <td>${escapeHtml(r.admin_username)}</td>
                    <td class="mono">${escapeHtml(r.device_id)}</td>
                    <td>${escapeHtml(r.prev_fw || "—")}</td>
                    <td>${escapeHtml(r.target_fw)}</td>
                    <td><span class="badge ${r.state}">${escapeHtml(r.state)}</span></td>
                    <td class="muted" style="max-width:220px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(r.error || "")}</td>
                    <td>${escapeHtml(r.finished_at || "")}</td>
                  </tr>`).join("")}</tbody>
              </table></div>
            </div>`;
          } catch (e) { toast(e.message || e, "err"); }
        }));
      } catch (e) { $("#campList").innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`; }
    }

    if (isSuper) {
      try {
        const fw = await api("/ota/firmwares");
        $("#fwList").innerHTML = (fw.items || []).length === 0
          ? `<p class="muted">${escapeHtml(fw.dir || "/opt/sentinel/firmware")} 下没有 .bin 文件。</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>文件</th><th>大小</th><th>SHA-256</th><th>修改时间</th><th></th></tr></thead>
              <tbody>${fw.items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.name)}</td>
                  <td>${(it.size / 1024).toFixed(1)} KB</td>
                  <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(it.sha256 || "—")}</td>
                  <td>${escapeHtml(fmtTs(it.mtime))}</td>
                  <td>${it.download_url ? `<button class="btn sm secondary js-use" data-url="${escapeHtml(it.download_url)}" data-fw="${escapeHtml(it.name.replace(/\\.bin$/i, ""))}" data-sha="${escapeHtml(it.sha256 || "")}">填入活动</button>` : ""}</td>
                </tr>`).join("")}</tbody></table></div>`;
        view.querySelectorAll(".js-use").forEach((b) => {
          b.addEventListener("click", () => {
            $("#c_url").value = b.dataset.url;
            $("#c_fw").value = b.dataset.fw;
            if ($("#c_sha") && b.dataset.sha) $("#c_sha").value = b.dataset.sha;
          });
        });
      } catch (e) { $("#fwList").innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`; }

      $("#c_send").addEventListener("click", async () => {
        const url = ($("#c_url").value || "").trim();
        const fw = ($("#c_fw").value || "").trim();
        const sha = ($("#c_sha").value || "").trim();
        const notes = ($("#c_notes").value || "").trim();
        const adminsRaw = ($("#c_admins").value || "").trim();
        const target_admins = adminsRaw ? adminsRaw.split(/[ ,;\n]+/).filter(Boolean) : ["*"];
        if (!url || !fw) { toast("请填写固件版本和 URL", "err"); return; }
        if (!confirm(`确认发起 OTA 活动？目标 admin: ${target_admins.join(", ") || "ALL"}`)) return;
        try {
          const r = await api("/ota/campaigns", { method: "POST", body: { fw_version: fw, url, sha256: sha || undefined, notes, target_admins } });
          toast(`活动已创建：${r.campaign_id}，目标 admin ${r.target_admins.length} 个`, "ok");
          $("#c_url").value = ""; $("#c_fw").value = ""; $("#c_sha").value = ""; $("#c_notes").value = ""; $("#c_admins").value = "";
          loadCampaigns();
        } catch (e) { toast(e.message || e, "err"); }
      });
    }

    $("#camp_reload").addEventListener("click", loadCampaigns);
    loadCampaigns();
  });

  function renderPolicyPanel(username, p) {
    const row = (k, label, locked) => `
      <label class="checkbox"><input type="checkbox" data-k="${k}" ${p[k] ? "checked" : ""} ${locked ? "disabled" : ""}/><span>${escapeHtml(label)}</span></label>`;
    return `
      <div class="stack">
        <p class="muted" style="margin:0">调整 <strong>${escapeHtml(username)}</strong> 的能力（user 角色适用）。</p>
        <div class="row">
          ${row("can_alert", "允许警报 (触发/批量/取消)")}
          ${row("can_send_command", "允许下发命令")}
          ${row("can_claim_device", "允许认领设备")}
          ${row("can_manage_users", "允许管理用户（user 级别不生效）", true)}
          ${row("can_backup_restore", "允许备份/恢复（user 级别不生效）", true)}
        </div>
        <div class="row" style="justify-content:flex-end">
          <button class="btn js-save" type="button">保存</button>
        </div>
      </div>`;
  }

  // ------------------------------------------------------------------ boot
  async function boot() {
    initTheme();

    $("#menuBtn").addEventListener("click", () => toggleNav());
    $("#sidebarClose").addEventListener("click", () => toggleNav(false));
    $("#sidebarBackdrop").addEventListener("click", () => toggleNav(false));
    $("#themeBtn").addEventListener("click", () => {
      setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("#logoutBtn").addEventListener("click", () => {
      setToken(""); state.me = null; location.hash = "#/login"; renderAuthState();
    });
    $("#refreshBtn").addEventListener("click", () => renderRoute());

    if (getToken()) await loadMe();
    await loadHealth();
    if (!location.hash) location.hash = state.me ? "#/overview" : "#/login";
    else renderRoute();
    clearHealthPollTimer();
    healthPollTimer = setInterval(tickHealthIfVisible, 30000);
    document.addEventListener("visibilitychange", () => {
      document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
      if (document.visibilityState === "hidden") {
        if (window.__evSSE) {
          try { window.__evSSE.close(); } catch (_) {}
          window.__evSSE = null;
          const live = document.getElementById("evLive");
          if (live) {
            live.textContent = "已暂停";
            live.className = "badge offline";
          }
        }
        return;
      }
      tickHealthIfVisible();
      if (typeof window.__eventsStreamResume === "function") {
        try { window.__eventsStreamResume(); } catch (_) {}
      }
    });
    document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
