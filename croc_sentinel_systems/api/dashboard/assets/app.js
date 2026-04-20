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

  /** Sidebar: grouped by function (paths unchanged). */
  const NAV_GROUPS = [
    {
      title: "Dashboard",
      items: [
        { id: "overview", label: "Overview", ico: "◎", path: "#/overview", min: "user" },
      ],
    },
    {
      title: "Monitoring",
      items: [
        { id: "signals", label: "Signals", ico: "◉", path: "#/signals", min: "user" },
        { id: "events", label: "Events", ico: "≈", path: "#/events", min: "user" },
      ],
    },
    {
      title: "Field ops",
      items: [
        { id: "alerts", label: "Siren", ico: "!", path: "#/alerts", min: "user" },
        { id: "activate", label: "Activate device", ico: "+", path: "#/activate", min: "admin" },
      ],
    },
    {
      title: "Firmware",
      items: [
        { id: "ota", label: "OTA", ico: "↑", path: "#/ota", min: "admin" },
      ],
    },
    {
      title: "Governance",
      items: [
        { id: "audit", label: "Audit", ico: "≡", path: "#/audit", min: "admin" },
        { id: "admin", label: "Admin & users", ico: "☼", path: "#/admin", min: "admin" },
      ],
    },
  ];

  const ROLE_WEIGHT = { user: 1, admin: 2, superadmin: 3 };

  // ------------------------------------------------------------------ state
  const state = {
    me: null,
    mqttConnected: false,
    health: null,
    overviewCache: null,
  };

  /** Route redirect timer (signup / activate → login); cleared on navigation. */
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

  /** Cleared when leaving Events; used to resume SSE when tab visible again. */
  window.__eventsStreamResume = null;

  let healthPollTimer = null;
  /** Overview device search debounce. */
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

  /** Default ceiling so a stuck reverse-proxy / API cannot leave the SPA on “Loading…” forever. */
  const DEFAULT_API_TIMEOUT_MS = 30000;
  /** Route-level async guard: any page render taking too long fails fast. */
  const ROUTE_RENDER_TIMEOUT_MS = 15000;

  /**
   * fetch() with AbortController timeout. opts.timeoutMs: number ms, false = no limit.
   */
  async function fetchWithDeadline(url, init, timeoutMs) {
    const limit = timeoutMs === false ? 0 : (timeoutMs != null ? timeoutMs : DEFAULT_API_TIMEOUT_MS);
    if (limit <= 0) return fetch(url, init || {});
    const ac = new AbortController();
    const tid = setTimeout(() => ac.abort(), limit);
    try {
      return await fetch(url, Object.assign({}, init || {}, { signal: ac.signal }));
    } catch (e) {
      if (e && e.name === "AbortError") {
        throw new Error("Request timed out — check API reachability, Nginx proxy, and browser Network tab.");
      }
      throw e;
    } finally {
      clearTimeout(tid);
    }
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
  function isOnline(d) {
    if (typeof d.is_online === "boolean") return d.is_online;
    return Date.now() - Date.parse(d.updated_at || 0) < OFFLINE_MS;
  }

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
    // Only send Authorization when non-empty — some stacks mis-handle "Authorization: ".
    const headers = Object.assign({}, opts.headers || {});
    if (token) headers.Authorization = "Bearer " + token;
    let body = opts.body;
    if (body && typeof body === "object" && !(body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    const r = await fetchWithDeadline(
      apiBase() + path,
      { method: opts.method || "GET", headers, body },
      opts.timeoutMs,
    );
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

  async function apiOr(path, fallback, opts) {
    try {
      return await api(path, opts);
    } catch (e) {
      return (typeof fallback === "function") ? fallback(e) : fallback;
    }
  }

  async function login(username, password) {
    const r = await fetchWithDeadline(
      apiBase() + "/auth/login",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      },
      25000,
    );
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
      // Keep bootstrap snappy when API is degraded; fail fast and render login.
      state.me = await api("/auth/me", { timeoutMs: 8000 });
    } catch (e) {
      state.me = null;
    }
    renderAuthState();
  }

  async function loadHealth() {
    try {
      // Public endpoint — do not use api() (no Authorization) so bad/expired JWT
      // never affects probes and we never trip the global 401 handler here.
      const r = await fetchWithDeadline(apiBase() + "/health", { method: "GET" }, 5000);
      if (!r.ok) throw new Error(String(r.status));
      const h = await r.json();
      state.mqttConnected = !!h.mqtt_connected;
      state.health = h;
    } catch {
      state.mqttConnected = false;
      state.health = null;
    }
    renderMqttDot();
    renderHealthPills();
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
    renderHealthPills();
  }

  function renderNav() {
    const nav = $("#nav");
    if (!nav) return;
    if (!state.me) { nav.innerHTML = ""; return; }
    const hash = location.hash || "#/overview";
    const parts = [];
    for (const g of NAV_GROUPS) {
      const items = g.items.filter((n) => hasRole(n.min));
      if (items.length === 0) continue;
      parts.push(`<div class="nav-section">${escapeHtml(g.title)}</div>`);
      for (const n of items) {
        const active = hash.startsWith(n.path) ? ` aria-current="page"` : "";
        parts.push(
          `<a href="${n.path}"${active}><span class="nav-ico">${n.ico}</span>${escapeHtml(n.label)}</a>`,
        );
      }
    }
    nav.innerHTML = parts.join("");
  }

  function renderHealthPills() {
    const el = $("#healthPills");
    if (!el) return;
    if (!state.me || !state.health) {
      el.innerHTML = "";
      return;
    }
    const sm = state.health.smtp || {};
    const tg = state.health.telegram || {};
    const smtpOk = !!sm.configured && !!sm.worker_running;
    const tgOn = !!tg.enabled;
    const tgOk = tgOn && !!tg.worker_running;
    const tgErr = String(tg.last_error || "").trim();
    const smtpTitle = sm.configured
      ? (smtpOk ? "SMTP worker running — OTP mail can be sent" : "SMTP configured but worker not running — check API logs")
      : "SMTP not configured — set SMTP_HOST (and auth) for email OTP";
    const tgTitle = tgOn
      ? (tgOk
        ? (tgErr ? `Telegram worker up — last API error: ${tgErr}` : "Telegram worker running — events at min_level+ are queued")
        : "Telegram enabled but worker not running — check API logs")
      : "Telegram disabled — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS (numeric chat id; start a chat with the bot first)";
    el.innerHTML = `
      <span class="health-pill ${smtpOk ? "ok" : sm.configured ? "warn" : "off"}" title="${escapeHtml(smtpTitle)}">SMTP</span>
      <span class="health-pill ${tgOk ? "ok" : tgOn ? "warn" : "off"}" title="${escapeHtml(tgTitle)}">TG</span>`;
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
    if (!view) return;
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
    document.body.dataset.layout = publicRoutes.has(routeId) ? "auth" : "app";
    const handler = routes[routeId] || routes["overview"];
    try {
      view.innerHTML = `<div class="route-loading card" aria-busy="true" role="status">
        <span class="sr-only">Loading page</span>
        <div class="route-loading__head"></div>
        <div class="route-loading__lines">
          <span class="route-loading__bar route-loading__bar--90"></span>
          <span class="route-loading__bar route-loading__bar--72"></span>
          <span class="route-loading__bar route-loading__bar--84"></span>
        </div>
      </div>`;
      const swap = async () => {
        await handler(view, args);
      };
      // Do not wrap `swap()` in `document.startViewTransition`: handlers often await
      // network I/O before finishing; the View Transition API then hits a DOM-update
      // timeout and rejects. (Also avoids races where a later route replaces #view while
      // an older handler is still awaiting.)
      await Promise.race([
        swap(),
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error("Page render timed out. Please retry.")), ROUTE_RENDER_TIMEOUT_MS);
        }),
      ]);
      renderNav();
      renderHealthPills();
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
      <div class="auth-page" role="main">
        <div class="auth-card" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Sign in</h1>
            <p class="auth-card__lead">Croc Sentinel — fleet alarms, devices &amp; OTA</p>
          </header>
          <form class="auth-card__body" id="loginForm" autocomplete="on">
            <label class="field">
              <span>Username</span>
              <input name="username" autocomplete="username" required placeholder="e.g. admin" />
            </label>
            <label class="field field--spaced">
              <span>Password</span>
              <input name="password" type="password" autocomplete="current-password" required placeholder="••••••••" />
            </label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="submit" id="loginSubmit">Sign in</button>
            </div>
            <p class="auth-card__msg muted" id="loginMsg" aria-live="polite"></p>
            <nav class="auth-card__links" aria-label="Other sign-in options">
              <a class="auth-link" href="#/register">Create admin account</a>
              <a class="auth-link" href="#/account-activate">Activate with email code</a>
              <a class="auth-link" href="#/forgot-password">Forgot password <span class="auth-link__hint">(offline RSA)</span></a>
            </nav>
          </form>
        </div>
      </div>`;
    const form = $("#loginForm", view);
    const card = view.querySelector("[data-auth-card]");
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const data = new FormData(form);
      const msg = $("#loginMsg", view);
      const btn = $("#loginSubmit", view);
      const label = btn ? btn.textContent : "Sign in";
      msg.textContent = "";
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Signing in…";
      }
      try {
        await login(data.get("username"), data.get("password"));
        await loadMe();
        await loadHealth();
        location.hash = "#/overview";
      } catch (e) {
        msg.textContent = String(e.message || e);
        if (card) {
          card.classList.remove("auth-shake");
          void card.offsetWidth;
          card.classList.add("auth-shake");
          setTimeout(() => card.classList.remove("auth-shake"), 500);
        }
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = label;
        }
      }
    });
  });

  // Forgot password — offline RSA decrypt flow
  registerRoute("forgot-password", async (view) => {
    setCrumb("Forgot password");
    document.body.dataset.auth = "none";
    let enabled = true;
    try {
      const r = await fetch(apiBase() + "/auth/forgot/enabled");
      const j = await r.json();
      enabled = !!j.enabled;
    } catch { enabled = false; }
    view.innerHTML = `
      <div class="auth-page" role="main">
        <div class="auth-card auth-card--wide auth-card--prose" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Account recovery</h1>
            <p class="auth-card__lead">Offline RSA — private key never sent to the server</p>
          </header>
          <div class="auth-card__body">
          <p class="muted auth-card__prose">
            Offline RSA recovery: after <strong>Get blob</strong> you receive <span class="mono">recovery_blob_hex</span>
            (long hex, length ≈ 2×<span class="mono">blob_byte_len</span>). Copy the <strong>entire</strong> string — no line breaks.
            Decrypt offline with <span class="mono">password_recovery_offline/decrypt_recovery_blob.py</span> and <span class="mono">private.pem</span>,
            paste the one-line JSON below, then set a new password.
          </p>
          ${enabled ? "" : `<p class="badge revoked" style="margin:10px 0">Server has no <span class="mono">PASSWORD_RECOVERY_PUBLIC_KEY_*</span> — recovery disabled.</p>`}
          <div id="fpStep1">
            <label class="field"><span>Username</span><input id="fp_user" autocomplete="username" /></label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="button" id="fp_go" ${enabled ? "" : "disabled"}>Get recovery blob</button>
              <a class="auth-link auth-link--center" href="#/login">Back to sign in</a>
            </div>
            <p class="auth-card__msg muted" id="fp_msg1" aria-live="polite"></p>
          </div>
          <div id="fpStep2" style="display:none">
            <label class="field"><span>recovery_blob_hex</span>
              <textarea id="fp_blob" readonly rows="6" class="mono" style="width:100%;font-size:11px"></textarea>
            </label>
            <p class="muted" id="fp_blob_hint" style="margin-top:6px;font-size:12px"></p>
            <p class="muted" id="fp_meta"></p>
            <label class="field field--spaced"><span>Decrypted JSON (one line)</span>
              <textarea id="fp_plain" rows="3" placeholder='{"jti":"...","u":"...","s":"...","e":...}' style="width:100%"></textarea>
            </label>
            <label class="field field--spaced"><span>New password (≥8)</span><input id="fp_p1" type="password" autocomplete="new-password" /></label>
            <label class="field field--spaced"><span>Confirm password</span><input id="fp_p2" type="password" autocomplete="new-password" /></label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="button" id="fp_done">Update password</button>
              <button class="btn secondary btn-tap btn-block" type="button" id="fp_back">Back</button>
            </div>
            <p class="auth-card__msg muted" id="fp_msg2" aria-live="polite"></p>
          </div>
          </div>
        </div>
      </div>`;
    const m1 = $("#fp_msg1"), m2 = $("#fp_msg2");
    $("#fp_go").addEventListener("click", async () => {
      m1.textContent = "";
      const username = $("#fp_user").value.trim();
      if (!username) { m1.textContent = "Enter username"; return; }
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
            ? `Hex length ${hexLen} (expected 2×${bl}=${2 * Number(bl)}). Copy all of it.`
            : `Hex length ${hexLen}. Copy the full blob.`;
        $("#fp_meta").textContent = `TTL ~ ${((d.ttl_seconds || 0) / 3600).toFixed(1)} h · raw bytes ${bl != null ? bl : "—"}`;
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
      if (!recovery_plain || !password) { m2.textContent = "Enter decrypted JSON and password"; return; }
      if (password !== password_confirm) { m2.textContent = "Passwords do not match"; return; }
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
        m2.textContent = "Password updated. You can sign in now.";
        toast("Password updated", "ok");
      } catch (e) { m2.textContent = String(e.message || e); }
    });
  });

  // Public admin signup
  registerRoute("register", async (view) => {
    setCrumb("Register admin");
    document.body.dataset.auth = "none";
    view.innerHTML = `
      <div class="auth-page" role="main">
        <div class="auth-card auth-card--wide" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Create admin</h1>
            <p class="auth-card__lead">Email verification · creates an <strong>admin</strong> account</p>
          </header>
          <div class="auth-card__body">
            <p class="auth-card__note muted">Superadmin is created on the server. If signup approval is on, a superadmin must activate you before login.</p>
            <ol class="auth-steps" aria-label="Steps">
              <li id="r_step_ind1" class="is-active"><span class="auth-steps__n">1</span><span class="auth-steps__t">Your details</span></li>
              <li id="r_step_ind2"><span class="auth-steps__n">2</span><span class="auth-steps__t">Email code</span></li>
            </ol>
            <div id="rStep1">
              <label class="field"><span>Username</span><input id="r_user" autocomplete="username" placeholder="2–64 chars, letters · digits · ._-"/></label>
              <label class="field field--spaced"><span>Password</span><input id="r_pass" type="password" autocomplete="new-password" placeholder="At least 8 characters"/></label>
              <label class="field field--spaced"><span>Email</span><input id="r_email" type="email" autocomplete="email" placeholder="you@company.com"/></label>
              <div class="auth-card__submit">
                <button class="btn btn-tap btn-block" type="button" id="r_start">Send verification code</button>
                <a class="auth-link auth-link--center" href="#/login">Already have an account</a>
              </div>
              <p class="auth-card__msg muted" id="r_msg1" aria-live="polite"></p>
            </div>
            <div id="rStep2" style="display:none">
              <p class="auth-card__note">We sent a code to <strong class="mono" id="r_shown_email"></strong>. Check inbox and spam.</p>
              <label class="field field--spaced"><span>Verification code</span><input id="r_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code" placeholder="6–12 digits"/></label>
              <div class="auth-card__submit">
                <button class="btn btn-tap btn-block" type="button" id="r_verify">Complete signup</button>
                <button class="btn secondary btn-tap btn-block" type="button" id="r_resend">Resend code</button>
                <button class="btn ghost btn-tap btn-block" type="button" id="r_back_step">Edit details</button>
              </div>
              <p class="auth-card__msg muted" id="r_msg2" aria-live="polite"></p>
            </div>
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
      if (!body.username || !body.password || !body.email) { m1.textContent = "Username, password, and email required"; return; }
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
          m2.innerHTML = `<span class="badge online">OK</span> Awaiting superadmin approval before login.`;
        } else {
          m2.innerHTML = `<span class="badge online">OK</span> Redirecting to sign in…`;
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
      if (!username) { m2.textContent = "Complete step 1 first"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/code/resend", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, channel: "email", purpose: "signup" }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        m2.textContent = "Code resent";
      } catch (e) { m2.textContent = String(e.message || e); }
    });
  });

  // Account activation (admin-created users arrive here)
  registerRoute("account-activate", async (view) => {
    setCrumb("Activate account");
    document.body.dataset.auth = "none";
    view.innerHTML = `
      <div class="auth-page" role="main">
        <div class="auth-card auth-card--wide" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Activate account</h1>
            <p class="auth-card__lead">Use the code from your invitation email</p>
          </header>
          <div class="auth-card__body">
            <p class="auth-card__note muted">An administrator created your user. Enter your <strong>username</strong> and the <strong>email code</strong> below.</p>
            <label class="field"><span>Username</span><input id="a_user" autocomplete="username" placeholder="Your username"/></label>
            <label class="field field--spaced"><span>Email code</span><input id="a_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code" placeholder="From email"/></label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="button" id="a_submit">Activate</button>
              <button class="btn secondary btn-tap btn-block" type="button" id="a_resend">Resend code</button>
              <a class="auth-link auth-link--center" href="#/login">Back to sign in</a>
            </div>
            <p class="auth-card__msg muted" id="a_msg" aria-live="polite"></p>
          </div>
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
        msg.innerHTML = `<span class="badge online">Activated</span> Redirecting to sign in…`;
        scheduleRouteRedirect(3000, "#/login");
      } catch (e) { msg.textContent = String(e.message || e); }
    });
    $("#a_resend").addEventListener("click", async () => {
      msg.textContent = "";
      const username = $("#a_user").value.trim();
      if (!username) { msg.textContent = "Enter username first"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/code/resend", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, channel: "email", purpose: "activate" }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        msg.textContent = "Resend requested — check inbox and spam.";
      } catch (e) { msg.textContent = String(e.message || e); }
    });
  });

  // Overview
  registerRoute("overview", async (view) => {
    setCrumb("Overview");
    const [ovRes, listRes] = await Promise.allSettled([
      api("/dashboard/overview", { timeoutMs: 8000 }),
      api("/devices", { timeoutMs: 8000 }),
    ]);
    let ov = (ovRes.status === "fulfilled" && ovRes.value) ? ovRes.value : null;
    let list = (listRes.status === "fulfilled" && listRes.value) ? listRes.value : null;
    if (!ov || !list) {
      const cached = state.overviewCache;
      if (cached && cached.ov && cached.list) {
        ov = ov || cached.ov;
        list = list || cached.list;
        toast("Overview is partially loaded from cache; refreshing in background.", "warn");
      }
    }
    if (!ov) ov = { presence: {}, throughput: {}, total_devices: 0, alarms_24h: 0, mqtt_connected: false };
    if (!list) list = { items: [] };
    if (ovRes.status !== "fulfilled" || listRes.status !== "fulfilled") {
      const err = ovRes.status !== "fulfilled" ? ovRes.reason : listRes.reason;
      toast(`Overview request slowed down: ${String((err && err.message) || err || "unknown error")}`, "warn");
    }
    state.overviewCache = { ov, list, ts: Date.now() };
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
      ["Online", online, "recent MQTT + online (status / heartbeat / ack / event ts)"],
      ["Offline", offline, ">90s no traffic or last status says offline"],
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
          <input id="q" placeholder="Filter id / name / group / zone / fw" class="grow right" />
        </div>
        <div class="divider"></div>
        <div class="device-grid" id="devGrid"></div>
      </section>`;

    const renderList = () => {
      const grid = document.getElementById("devGrid");
      if (!grid) return;
      const q = ($("#q").value || "").toLowerCase().trim();
      const rows = devices.filter((d) => !q || [d.device_id, d.display_label, d.notification_group, d.zone, d.fw, d.board_profile, d.chip_target].join(" ").toLowerCase().includes(q));
      grid.innerHTML = rows.length === 0
        ? `<p class="muted">No matching devices.</p>`
        : rows.map((d) => {
          const on = isOnline(d);
          const primary = escapeHtml(d.display_label || d.device_id || "unknown");
          const subId = d.display_label
            ? `<div class="device-id-sub mono">${escapeHtml(d.device_id || "")}</div>`
            : "";
          return `<a class="device-card" href="#/devices/${encodeURIComponent(d.device_id)}" style="text-decoration:none;color:inherit">
            <h3><div class="device-primary-name">${primary}</div>${subId}</h3>
            <div><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
              ${d.notification_group ? `<span class="chip">${escapeHtml(d.notification_group)}</span>` : ""}
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

    const [d, msgs] = await Promise.all([
      api(`/devices/${encodeURIComponent(id)}`),
      api(`/devices/${encodeURIComponent(id)}/messages?limit=25`).catch(() => ({ items: [] })),
    ]);
    setCrumb(d.display_label ? `Device · ${d.display_label}` : `Device · ${id}`);
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
    const netT = String(s.net_type || d.net_type || "");
    const wifiSsidDd = netT === "wifi"
      ? ((s.wifi_ssid != null && String(s.wifi_ssid).length > 0)
        ? escapeHtml(String(s.wifi_ssid))
        : `<span class="muted">Not associated</span>`)
      : `<span class="muted">N/A (${escapeHtml(netT || "—")})</span>`;
    const wifiChDd = (netT === "wifi" && s.wifi_channel != null && Number(s.wifi_channel) > 0)
      ? escapeHtml(String(s.wifi_channel))
      : "—";
    const sharePanel = state.me && state.me.role === "superadmin" ? `
      <div class="card" id="sharePanel">
        <div class="row">
          <h3 style="margin:0">Sharing</h3>
          <span class="muted">Grant or revoke per-account access</span>
          <button class="btn secondary right" id="shareRefresh">Refresh</button>
        </div>
        <div class="divider"></div>
        <div class="inline-form" style="margin-top:10px">
          <label class="field grow"><span>Grantee username</span>
            <input id="shareUser" placeholder="admin_x or user_x" />
          </label>
          <label class="field"><span>View</span>
            <input id="shareCanView" type="checkbox" checked />
          </label>
          <label class="field"><span>Operate</span>
            <input id="shareCanOperate" type="checkbox" />
          </label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn btn-tap" id="shareGrant">Grant / Update</button>
          </div>
        </div>
        <div id="shareList" style="margin-top:12px"></div>
      </div>
    ` : "";
    view.innerHTML = `
      <div class="card">
        <div class="row" style="align-items:flex-start;flex-wrap:wrap;gap:10px">
          <div class="device-page-head" style="flex:1;min-width:0">
            <div class="device-primary-name">${escapeHtml(d.display_label || id)}</div>
            ${d.display_label ? `<div class="device-id-sub mono">${escapeHtml(id)}</div>` : ""}
          </div>
          <span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
          <span class="chip">${escapeHtml(reasonEn[reason] || reason)}</span>
          ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
          <a href="#/overview" class="btn ghost right">← Overview</a>
        </div>
        <div class="divider"></div>
        <div style="margin-bottom:12px;padding:12px 14px;border:1px dashed var(--border-strong);border-radius:var(--radius-sm);background:var(--bg-muted)">
          <h3 style="margin:0 0 8px;font-size:13px;color:var(--text-muted)">Notifications</h3>
          <p class="muted" style="margin:0 0 10px">Used as the prefix for emails, Telegram, and in-app summaries for this device.</p>
          <div class="row" style="gap:10px;align-items:flex-end;flex-wrap:wrap">
            <label class="field grow"><span>Display name</span>
              <input id="dispLabel" value="${escapeHtml(d.display_label || "")}" maxlength="80" />
            </label>
            <label class="field grow"><span>Notification group</span>
              <input id="notifGroup" value="${escapeHtml(d.notification_group || "")}" maxlength="80" placeholder="e.g. Warehouse A" />
            </label>
            <button class="btn secondary btn-tap" type="button" id="saveProfile">Save</button>
          </div>
        </div>
        <dl class="kv">
          <dt>Firmware</dt><dd class="mono">${escapeHtml(d.fw || "—")}</dd>
          <dt>Chip</dt><dd class="mono">${escapeHtml(d.chip_target || "—")}</dd>
          <dt>Board</dt><dd class="mono">${escapeHtml(d.board_profile || "—")}</dd>
          <dt>Network</dt><dd class="mono">${escapeHtml(d.net_type || "—")} · ${escapeHtml(s.ip || "—")}</dd>
          <dt>Wi‑Fi SSID</dt><dd>${wifiSsidDd}</dd>
          <dt>Wi‑Fi channel</dt><dd>${wifiChDd}</dd>
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
      ${sharePanel}

      <div class="card" id="wifiCtlCard">
        <h3>Wi‑Fi (device)</h3>
        <p class="muted">SSID / channel come from the last <span class="mono">status</span> report (STA). Enter a <strong>2.4&nbsp;GHz</strong> SSID and password manually — credentials are stored in device NVS as the <strong>first</strong> preferred network, then the device reboots. Production builds often leave compile-time <span class="mono">WIFI_SSID</span> slots empty and rely on this field or factory burn.</p>
        ${can("can_send_command") ? `
        <div class="inline-form" style="margin-top:10px">
          <label class="field grow"><span>New SSID</span><input id="wifiNewSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz network name" /></label>
          <label class="field grow"><span>Password</span><input id="wifiNewPass" type="password" maxlength="64" autocomplete="new-password" placeholder="empty if open network" /></label>
          <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:8px">
            <button class="btn btn-tap" type="button" id="wifiApplyBtn">Save & reboot</button>
            <button class="btn danger btn-tap" type="button" id="wifiClearBtn">Clear saved Wi‑Fi & reboot</button>
          </div>
        </div>
        <p class="muted" id="wifiScanStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span>.</p>`}
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

    $("#saveProfile").addEventListener("click", async () => {
      try {
        await api(`/devices/${encodeURIComponent(id)}/profile`, {
          method: "PATCH",
          body: {
            display_label: ($("#dispLabel").value || "").trim(),
            notification_group: ($("#notifGroup").value || "").trim(),
          },
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

    const waitForCmdAck = async (expectedCmd) => {
      for (let i = 0; i < 36; i++) {
        await new Promise((r) => setTimeout(r, 500));
        const d2 = await api(`/devices/${encodeURIComponent(id)}`);
        const a = d2.last_ack_json || {};
        if (a.cmd === expectedCmd && typeof a.ok === "boolean") {
          return a;
        }
      }
      return null;
    };

    const wifiApplyBtn = $("#wifiApplyBtn");
    if (wifiApplyBtn) {
      wifiApplyBtn.addEventListener("click", async () => {
        const ssid = ($("#wifiNewSsid").value || "").trim();
        const password = $("#wifiNewPass").value || "";
        const st = $("#wifiScanStatus");
        if (!ssid) { toast("Enter SSID", "err"); return; }
        if (!confirm("Save Wi‑Fi on device and reboot? You may lose contact until it joins the new network.")) return;
        try {
          if (st) st.textContent = "Sending wifi_config…";
          await api(`/devices/${encodeURIComponent(id)}/commands`, { method: "POST", body: { cmd: "wifi_config", params: { ssid, password } } });
          if (st) st.textContent = "Waiting for device ack (then reboot)…";
          const a = await waitForCmdAck("wifi_config");
          if (a) {
            if (st) st.textContent = a.ok ? String(a.detail || "Saved.") : String(a.detail || "wifi_config rejected");
            toast(a.ok ? "Wi‑Fi saved on device; rebooting." : (a.detail || "wifi_config rejected"), a.ok ? "ok" : "err");
          } else {
            if (st) st.textContent = "No ack yet — device may still reboot; check Events.";
            toast("Command sent; no ack seen yet.", "");
          }
        } catch (e) { toast(e.message || e, "err"); if (st) st.textContent = String(e.message || e); }
      });
    }
    const wifiClearBtn = $("#wifiClearBtn");
    if (wifiClearBtn) {
      wifiClearBtn.addEventListener("click", async () => {
        const st = $("#wifiScanStatus");
        if (!confirm("Clear device-stored Wi‑Fi override and reboot? It will fall back to compile-time APs in firmware (if any) or remain offline until you apply new credentials.")) return;
        try {
          if (st) st.textContent = "Sending wifi_clear…";
          await api(`/devices/${encodeURIComponent(id)}/commands`, { method: "POST", body: { cmd: "wifi_clear", params: {} } });
          if (st) st.textContent = "Waiting for device ack…";
          const a = await waitForCmdAck("wifi_clear");
          if (a) {
            if (st) st.textContent = String(a.detail || (a.ok ? "Cleared." : "wifi_clear failed"));
            toast(a.ok ? "Wi‑Fi override cleared; rebooting." : (a.detail || "wifi_clear failed"), a.ok ? "ok" : "err");
          } else {
            if (st) st.textContent = "No ack yet — device may still reboot.";
            toast("wifi_clear sent; no ack seen yet.", "");
          }
        } catch (e) { toast(e.message || e, "err"); if (st) st.textContent = String(e.message || e); }
      });
    }

    const shareListEl = $("#shareList");
    const renderShares = async () => {
      if (!shareListEl) return;
      shareListEl.innerHTML = `<p class="muted">Loading shares…</p>`;
      try {
        const r = await api(`/admin/devices/${encodeURIComponent(id)}/shares`, { timeoutMs: 8000 });
        const items = r.items || [];
        shareListEl.innerHTML = `
          <div class="table-wrap"><table class="t">
            <thead><tr><th>User</th><th>Role</th><th>View</th><th>Operate</th><th>Granted by</th><th>Granted at</th><th>Status</th><th></th></tr></thead>
            <tbody>${
              items.length === 0
                ? `<tr><td colspan="8" class="muted">No shares</td></tr>`
                : items.map((it) => `
                  <tr>
                    <td class="mono">${escapeHtml(it.grantee_username || "")}</td>
                    <td>${escapeHtml(it.grantee_role || "—")}</td>
                    <td>${it.can_view ? "yes" : "no"}</td>
                    <td>${it.can_operate ? "yes" : "no"}</td>
                    <td class="mono">${escapeHtml(it.granted_by || "")}</td>
                    <td>${escapeHtml(fmtTs(it.granted_at))}</td>
                    <td>${it.revoked_at ? `<span class="badge offline">revoked</span>` : `<span class="badge online">active</span>`}</td>
                    <td>${it.revoked_at ? "" : `<button class="btn ghost shareRevokeBtn" data-user="${escapeHtml(it.grantee_username || "")}">Revoke</button>`}</td>
                  </tr>
                `).join("")
            }</tbody>
          </table></div>
        `;
        $$(".shareRevokeBtn", shareListEl).forEach((btn) => {
          btn.addEventListener("click", async () => {
            const u = btn.getAttribute("data-user") || "";
            if (!u) return;
            if (!confirm(`Revoke share for ${u}?`)) return;
            try {
              await api(`/admin/devices/${encodeURIComponent(id)}/share/${encodeURIComponent(u)}`, { method: "DELETE" });
              toast("Share revoked", "ok");
              await renderShares();
            } catch (e) { toast(e.message || e, "err"); }
          });
        });
      } catch (e) {
        shareListEl.innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`;
      }
    };
    const shareGrantBtn = $("#shareGrant");
    if (shareGrantBtn) {
      shareGrantBtn.addEventListener("click", async () => {
        const grantee = ($("#shareUser").value || "").trim();
        const canView = !!$("#shareCanView").checked;
        const canOperate = !!$("#shareCanOperate").checked;
        if (!grantee) { toast("Enter grantee username", "err"); return; }
        if (!canView && !canOperate) { toast("Select view and/or operate", "err"); return; }
        try {
          await api(`/admin/devices/${encodeURIComponent(id)}/share`, {
            method: "POST",
            body: { grantee_username: grantee, can_view: canView, can_operate: canOperate },
          });
          toast("Share granted", "ok");
          await renderShares();
        } catch (e) { toast(e.message || e, "err"); }
      });
    }
    const shareRefreshBtn = $("#shareRefresh");
    if (shareRefreshBtn) {
      shareRefreshBtn.addEventListener("click", () => renderShares());
      renderShares();
    }
  });

  // Alerts
  registerRoute("alerts", async (view) => {
    setCrumb("Siren");
    const enabled = can("can_alert");
    let devicesLoadErr = "";
    const list = await apiOr("/devices", (e) => {
      devicesLoadErr = String((e && e.message) || e || "load failed");
      return { items: [] };
    }, { timeoutMs: 8000 });
    const devices = list.items || [];

    view.innerHTML = `
      <div class="card">
        <h2>Bulk siren</h2>
        <p class="muted">MQTT <span class="mono">siren_on</span> / <span class="mono">siren_off</span>. Requires <span class="mono">can_alert</span>.</p>
        ${enabled ? "" : `<p class="badge revoked">No can_alert — ask admin (Policies).</p>`}
        ${devicesLoadErr ? `<p class="badge offline">Device list fallback: ${escapeHtml(devicesLoadErr)}</p>` : ""}
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
      const lab = d.display_label ? `${escapeHtml(d.display_label)}` : escapeHtml(d.device_id);
      const serial = d.display_label ? ` · ${escapeHtml(d.device_id)}` : "";
      const grp = d.notification_group ? `[${escapeHtml(d.notification_group)}] ` : "";
      const z = d.zone ? ` · ${escapeHtml(d.zone)}` : "";
      return `<option value="${escapeHtml(d.device_id)}">${grp}${lab}${serial}${z}</option>`;
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
    setCrumb("Activate device");
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">Admins only.</p></div>`; return; }
    const canClaim = can("can_claim_device");

    view.innerHTML = `
      <div class="card">
        <h2 style="margin-top:0">Claim a device</h2>
        <p class="muted">
          1) Power the board and wait until it is on the network.<br>
          2) Scan the label QR or paste the serial (<span class="mono">SN-…</span>) or full <span class="mono">CROC|…</span> string.<br>
          3) Tap <strong>Identify</strong> — you will see whether it is claimable, already claimed, offline, blocked, or unknown.
        </p>
        ${canClaim ? "" : `<p class="badge revoked" style="margin-top:6px">Your role does not have <span class="mono">can_claim_device</span>. Ask an admin.</p>`}
        <div class="inline-form" style="margin-top:10px">
          <label class="field wide"><span>QR payload or serial</span>
            <input id="idn_input" placeholder="SN-XXXXXXXXXXXXXXXX or CROC|SN-…|…|…" autocomplete="off"/>
          </label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn secondary btn-tap" id="idn_go" ${canClaim ? "" : "disabled"}>Identify</button>
          </div>
        </div>
        <div id="idnResult" style="margin-top:14px"></div>
      </div>

      <div class="card">
        <div class="row">
          <h3 style="margin:0">Recently seen (pending claim)</h3>
          <span class="muted">From MQTT <span class="mono">bootstrap.register</span></span>
          <button class="btn secondary right" id="reload">Refresh</button>
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
          <h4 style="margin-top:0">Confirm claim</h4>
          <div class="inline-form">
            <label class="field"><span>device_id (usually the serial)</span><input id="c_id" value="${escapeHtml(serial)}"/></label>
            <label class="field"><span>mac_nocolon</span><input id="c_mac" value="${escapeHtml(mac)}"/></label>
            <label class="field"><span>zone</span><input id="c_zone" value="all"/></label>
            <label class="field wide"><span>qr_code (optional)</span><input id="c_qr" value="${escapeHtml(qr || "")}"/></label>
            <div class="row wide" style="justify-content:flex-end">
              <button class="btn btn-tap" id="c_submit">Claim device</button>
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
          toast("Device claimed", "ok");
          renderRoute();
        } catch (e) { toast(e.message || e, "err"); }
      });
    };

    $("#idn_go").addEventListener("click", async () => {
      resultBox.innerHTML = `<p class="muted">Identifying…</p>`;
      const raw = ($("#idn_input").value || "").trim();
      if (!raw) { resultBox.innerHTML = `<p class="muted">Enter serial or QR payload</p>`; return; }
      const body = raw.startsWith("CROC|") ? { qr_code: raw } : { serial: raw.toUpperCase() };
      try {
        const r = await api("/provision/identify", { method: "POST", body });
        const kv = (k, v) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(v)}</dd>`;
        switch (r.status) {
          case "ready":
            resultBox.innerHTML = `${drawBadge("ok", "Ready to claim")}
              <dl class="kv">${kv("Serial", r.serial)}${kv("MAC", r.mac_nocolon)}${kv("Firmware", r.fw || "—")}${kv("Last seen", r.last_seen_at || "—")}</dl>
              <p>${escapeHtml(r.message)}</p>`;
            showClaimForm(r.serial, r.mac_nocolon, raw.startsWith("CROC|") ? raw : "");
            break;
          case "already_registered":
            const canSeeOwner = !!(state.me && state.me.role === "superadmin");
            const ownerKv = canSeeOwner ? kv("Owner admin", r.owner_admin || "—") : "";
            const byYou = !!r.by_you;
            resultBox.innerHTML = `${drawBadge("err", byYou ? "Already yours" : "Already registered")}
              <dl class="kv">${kv("Serial", r.serial)}${kv("device_id", r.device_id)}${ownerKv}${kv("Claimed at", r.claimed_at)}</dl>
              <p class="muted">${escapeHtml(r.message)}</p>
              ${byYou ? `<a class="btn secondary" href="#/devices/${encodeURIComponent(r.device_id)}">Open device</a>` : ""}`;
            break;
          case "offline":
            resultBox.innerHTML = `${drawBadge("", "Waiting for device")}
              <dl class="kv">${kv("Serial", r.serial)}${r.mac_hint ? kv("Factory MAC", r.mac_hint) : ""}</dl>
              <p>${escapeHtml(r.message)}</p>`;
            break;
          case "blocked":
            resultBox.innerHTML = `${drawBadge("err", "Factory blocked")}<p>${escapeHtml(r.message)}</p>`;
            break;
          case "unknown_serial":
            resultBox.innerHTML = `${drawBadge("err", "Unknown serial")}<p>${escapeHtml(r.message)}</p>`;
            break;
          default:
            resultBox.innerHTML = `<p class="muted">Unknown status: ${escapeHtml(r.status)}</p>`;
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

    let pendingErr = "";
    const data = await apiOr("/provision/pending", (e) => {
      pendingErr = String((e && e.message) || e || "load failed");
      return { items: [] };
    }, { timeoutMs: 8000 });
    const items = data.items || [];
    const pendListEl = view.querySelector("#pendList");
    if (!pendListEl) return;
    pendListEl.innerHTML = `
      <div class="table-wrap"><table class="t">
        <thead><tr><th>MAC</th><th>Serial / proposed ID</th><th>QR</th><th>Firmware</th><th>Last seen</th></tr></thead>
        <tbody>${items.length === 0 ? `<tr><td colspan="5" class="muted">${pendingErr ? "Load failed (retry with Refresh)." : "None"}</td></tr>` :
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
    setCrumb("Events");
    const me = state.me || { username: "", role: "" };
    const isSuper = me.role === "superadmin";
    const scopeLabel = isSuper ? "Global (superadmin)" : (me.role === "admin" ? `My tenant · ${escapeHtml(me.username)}` : "Parent tenant");

    view.innerHTML = `
      <div class="card">
        <div class="row between" style="flex-wrap:wrap;gap:10px">
          <div>
            <h2 style="margin:0">Event center</h2>
            <p class="muted" style="margin:4px 0 0">Scope: ${scopeLabel} · Superadmin sees all; admin sees tenant; users see related + warn+.</p>
          </div>
          <div class="row" style="gap:8px;align-items:center">
            <span id="evLive" class="badge offline" title="Live stream">Offline</span>
            <button class="btn sm secondary" id="evPause">Pause</button>
            <button class="btn sm secondary" id="evClear">Clear</button>
          </div>
        </div>
        <div class="divider"></div>
        <div class="inline-form" style="margin-bottom:10px">
          <label class="field"><span>Min level</span>
            <select id="evLevel">
              <option value="">All</option>
              <option value="debug">debug+</option>
              <option value="info" selected>info+</option>
              <option value="warn">warn+</option>
              <option value="error">error+</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label class="field"><span>Category</span>
            <select id="evCategory">
              <option value="">All</option>
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
          <label class="field"><span>Device ID</span><input id="evDevice" placeholder="SN-… or id" /></label>
          <label class="field wide"><span>Search</span><input id="evQ" placeholder="summary / actor / event_type" /></label>
          <div class="row wide" style="justify-content:flex-end;gap:8px;flex-wrap:wrap">
            <button class="btn sm secondary" id="evApply">Apply filters</button>
            <button class="btn sm" id="evReload">Last 200</button>
            <button class="btn sm secondary" id="evStats">By device (7d)</button>
            <button class="btn sm secondary" id="evCsv">Export CSV</button>
          </div>
        </div>
      </div>
      <div id="evStatsBox" class="card" style="margin-top:12px;display:none">
        <h3 style="margin:0 0 8px">Events per device (7 days)</h3>
        <div id="evStatsInner" class="muted">—</div>
      </div>
      <div class="card" style="margin-top:12px">
        <div id="evList" class="events-list muted">Connecting…</div>
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
        ${detailTxt ? `<details class="ev-detail"><summary class="muted">Details</summary><pre class="code">${escapeHtml(detailTxt)}</pre></details>` : ""}
      </div>`;
    }
    function flushEvRender() {
      const listEl = document.getElementById("evList");
      if (!listEl) return;
      if (buffer.length === 0) {
        listEl.innerHTML = `<p class="muted">No events.</p>`;
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
        const r = await api("/events?" + p.toString(), { timeoutMs: 8000 });
        buffer = (r.items || []).slice();
        if (window.__pendingEvListRaf) {
          cancelAnimationFrame(window.__pendingEvListRaf);
          window.__pendingEvListRaf = 0;
        }
        flushEvRender();
      } catch (e) {
        const listEl = document.getElementById("evList");
        if (listEl) listEl.innerHTML = `<p class="badge offline">${escapeHtml(e.message || e)}</p>`;
        toast(e.message || e, "err");
      }
    }

    function closeStream() {
      if (window.__evSSE) { try { window.__evSSE.close(); } catch {} window.__evSSE = null; }
      $("#evLive").textContent = "Offline"; $("#evLive").className = "badge offline";
    }
    function openStream() {
      closeStream();
      const p = currentFilters();
      p.set("token", getToken());
      p.set("backlog", String(Math.min(100, BUFFER_MAX - buffer.length)));
      const url = apiBase() + "/events/stream?" + p.toString();
      const es = new EventSource(url);
      window.__evSSE = es;
      es.onopen = () => { $("#evLive").textContent = "Live"; $("#evLive").className = "badge online"; };
      es.onerror = () => {
        $("#evLive").textContent = "Reconnecting…"; $("#evLive").className = "badge offline";
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
      $("#evPause").textContent = paused ? "Resume" : "Pause";
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
        const r = await api("/events/stats/by-device?hours=168&limit=200", { timeoutMs: 8000 });
        const items = r.items || [];
        $("#evStatsBox").style.display = "block";
        if (items.length === 0) {
          $("#evStatsInner").innerHTML = "<p class='muted'>No rows with device_id.</p>";
          return;
        }
        $("#evStatsInner").innerHTML = `<div class="table-wrap"><table class="t"><thead><tr><th>Device</th><th>Count</th></tr></thead><tbody>${
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
        toast("CSV downloaded", "ok");
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
    setCrumb("Audit");
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">Admins only.</p></div>`; return; }
    view.innerHTML = `
      <div class="card">
        <div class="row">
          <h2 style="margin:0">Audit log</h2>
          <label class="field" style="max-width:180px"><span>actor</span><input id="f_actor" /></label>
          <label class="field" style="max-width:180px"><span>action prefix</span><input id="f_action" placeholder="device / user / command" /></label>
          <label class="field" style="max-width:180px"><span>target</span><input id="f_target" /></label>
          <button class="btn secondary right" id="f_reload">Query</button>
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
          ? `<p class="muted">No rows.</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>Time</th><th>actor</th><th>action</th><th>target</th><th>detail</th></tr></thead>
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
    setCrumb("Admin");
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">Admins only.</p></div>`; return; }
    const isSuper = state.me.role === "superadmin";
    let admins = [];
    if (isSuper) {
      try { admins = (await api("/auth/admins", { timeoutMs: 8000 })).items || []; } catch { admins = []; }
    }

    view.innerHTML = `
      <div class="card">
        <h2>Users</h2>
        <p class="muted">${isSuper
          ? "Superadmin: create admin/user, assign manager_admin and policies."
          : "Admin: manage users under you and toggle their capabilities."}</p>
        <p class="muted" style="margin-top:8px">Registration OTP email uses <span class="mono">SMTP_*</span> in server <span class="mono">.env</span>; set <span class="mono">SMTP_FROM</span> to a valid address (or leave blank to use <span class="mono">SMTP_USERNAME</span>). Telegram alerts need <span class="mono">TELEGRAM_BOT_TOKEN</span> and <span class="mono">TELEGRAM_CHAT_IDS</span>; restart the API after changing those. Status: top bar pills (from <span class="mono">/health</span>).</p>
        <div class="row right-end" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
          <button class="btn btn-tap" id="showCreate" type="button">New user</button>
          <button class="btn secondary btn-tap" id="reloadUsers" type="button">Refresh</button>
        </div>
        <div class="divider"></div>
        <div id="userTable"></div>
      </div>

      <div class="card" id="createPanel" style="display:none">
        <h3>New user</h3>
        <div class="inline-form">
          <label class="field"><span>Username</span><input id="u_name" autocomplete="off" /></label>
          <label class="field"><span>Password (min 8)</span><input id="u_pass" type="password" autocomplete="new-password" /></label>
          <label class="field"><span>Role</span><select id="u_role">
            ${isSuper
              ? `<option value="user">user</option><option value="admin">admin</option>`
              : `<option value="user">user</option>`}
          </select></label>
          <label class="field" id="u_mgr_wrap" ${isSuper ? "" : 'style="display:none"'}>
            <span>Manager admin</span>
            <select id="u_mgr">${admins.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join("")}</select>
          </label>
          <label class="field"><span>Email (required)</span><input id="u_email" type="email" autocomplete="off"/></label>
          <label class="field"><span>Tenant (optional)</span><input id="u_tenant" /></label>
          <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
            <button class="btn ghost btn-tap" id="u_cancel" type="button">Cancel</button>
            <button class="btn btn-tap" id="u_submit" type="button">Create & send activation email</button>
          </div>
          <p class="muted" style="margin:8px 0 0">
            New users start as <span class="mono">pending</span>. They must finish
            <a href="#/account-activate">Activate account</a> with the email code before sign-in.
          </p>
        </div>
      </div>

      ${isSuper ? `<div class="card">
        <h3>Pending admin signups</h3>
        <p class="muted">Public registration + email verified; awaiting your approval.</p>
        <div id="pendAdmins"></div>
      </div>` : ""}

      <div class="card">
        <h3>Alert email recipients</h3>
        <p class="muted">Inbox list for alarm emails when SMTP is configured on the server.</p>
        <div id="smtpStatus" class="row" style="gap:6px"></div>
        <div class="divider"></div>
        <div class="inline-form">
          <label class="field wide"><span>Email</span><input id="r_email" type="email" autocomplete="off" placeholder="you@company.com"/></label>
          <label class="field"><span>Label</span><input id="r_label" autocomplete="off" placeholder="on-call"/></label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn" id="r_add">Add</button>
            <button class="btn ghost" id="r_test">Send test email</button>
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
        <h3>Database backup / restore</h3>
        <p class="muted">Uses <span class="mono">/admin/backup/export</span> and <span class="mono">/admin/backup/import</span>: full SQLite encrypted to <span class="mono">.enc</span>. Import writes <span class="mono">*.restored</span> — follow ops runbook to swap files.</p>
        <label class="field" style="max-width:420px">
          <span>Encryption key <span class="muted">X-Backup-Encryption-Key</span></span>
          <input id="bk_key" type="password" autocomplete="off" />
        </label>
        <div class="row" style="margin-top:10px">
          <button class="btn" id="bk_export">Export .enc</button>
          <input type="file" id="bk_file" accept=".enc,application/octet-stream" />
          <button class="btn secondary" id="bk_import">Upload & decrypt</button>
        </div>
      </div>` : ""}`;

    const $v = (sel) => $(sel, view);

    // users
    const loadUsers = async () => {
      try {
        const d = await api("/auth/users", { timeoutMs: 8000 });
        const users = d.items || [];
        const userTableEl = $v("#userTable");
        if (!userTableEl) return;
        userTableEl.innerHTML = users.length === 0
          ? `<p class="muted">No users.</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>User</th><th>Role</th><th>manager</th><th>tenant</th><th>Created</th><th></th></tr></thead>
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
                    ${isUser ? `<button class="btn sm secondary js-pol" data-u="${escapeHtml(u.username)}">Policy</button>` : ""}
                    ${self ? "" : `<button class="btn sm danger js-del" data-u="${escapeHtml(u.username)}">Delete</button>`}
                  </td>
                </tr><tr class="sub" style="display:none" data-pol-row="${escapeHtml(u.username)}"><td colspan="6"></td></tr>`;
              }).join("")}</tbody></table></div>`;
      } catch (e) {
        const userTableEl = $v("#userTable");
        if (userTableEl) userTableEl.innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`;
      }
    };

    $v("#reloadUsers").addEventListener("click", loadUsers);
    $v("#showCreate").addEventListener("click", () => {
      $v("#createPanel").style.display = "";
      $v("#createPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $v("#u_cancel").addEventListener("click", () => { $v("#createPanel").style.display = "none"; });
    $v("#u_submit").addEventListener("click", async () => {
      const body = {
        username: $v("#u_name").value.trim(),
        password: $v("#u_pass").value,
        role: $v("#u_role").value,
      };
      if (!body.username || !body.password) { toast("Username and password required", "err"); return; }
      const email = $v("#u_email").value.trim();
      if (!email) { toast("Email required for activation", "err"); return; }
      body.email = email;
      const tenant = $v("#u_tenant").value.trim(); if (tenant) body.tenant = tenant;
      if (isSuper && body.role === "user") body.manager_admin = $v("#u_mgr").value;
      try {
        const resp = await api("/auth/users", { method: "POST", body });
        toast(`Created: ${resp.message || "activation email sent"}`, "ok");
        $v("#createPanel").style.display = "none";
        $v("#u_name").value = ""; $v("#u_pass").value = ""; $v("#u_tenant").value = "";
        $v("#u_email").value = "";
        loadUsers();
      } catch (e) { toast(e.message || e, "err"); }
    });

    const openPolicy = async (username, trRow) => {
      const cell = trRow.querySelector("td");
      cell.innerHTML = `<span class="muted">Loading…</span>`;
      trRow.style.display = "";
      try {
          const p = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { timeoutMs: 8000 });
        cell.innerHTML = renderPolicyPanel(username, p);
        cell.querySelector(".js-save").addEventListener("click", async () => {
          const body = {};
          cell.querySelectorAll("input[type=checkbox][data-k]").forEach((i) => body[i.dataset.k] = !!i.checked);
          try {
            const r = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { method: "PUT", body });
            toast(`Policy updated for ${username}`, "ok");
            cell.innerHTML = renderPolicyPanel(username, r.policy || r);
            cell.querySelector(".js-save").addEventListener("click", () => openPolicy(username, trRow));
          } catch (e) { toast(e.message || e, "err"); }
        });
      } catch (e) { cell.innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`; }
    };

    $v("#userTable").addEventListener("click", async (ev) => {
      const t = ev.target.closest("button");
      if (!t) return;
      const u = t.dataset.u;
      if (t.classList.contains("js-del")) {
        if (!confirm(`Delete user ${u}?`)) return;
        try { await api(`/auth/users/${encodeURIComponent(u)}`, { method: "DELETE" }); toast("Deleted", "ok"); loadUsers(); }
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
      $v("#bk_export").addEventListener("click", async () => {
        const key = ($v("#bk_key").value || "").trim();
        if (!key) { toast("Enter backup encryption key", "err"); return; }
        try {
          const r = await fetch(apiBase() + "/admin/backup/export", {
            headers: { Authorization: "Bearer " + getToken(), "X-Backup-Encryption-Key": key },
          });
          if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
          const blob = new Blob([await r.arrayBuffer()], { type: "application/octet-stream" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob); a.download = "sentinel-backup.enc"; a.click();
          URL.revokeObjectURL(a.href);
          toast("Downloaded", "ok");
        } catch (e) { toast(e.message || e, "err"); }
      });
      $v("#bk_import").addEventListener("click", async () => {
        const key = ($v("#bk_key").value || "").trim();
        const f = $v("#bk_file").files[0];
        if (!key || !f) { toast("Pick a file and enter the encryption key", "err"); return; }
        const fd = new FormData(); fd.append("file", f, f.name || "sentinel-backup.enc");
        try {
          const r = await fetch(apiBase() + "/admin/backup/import", {
            method: "POST",
            headers: { Authorization: "Bearer " + getToken(), "X-Backup-Encryption-Key": key },
            body: fd,
          });
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(`${r.status} ${j.detail || ""}`);
          toast("Written: " + (j.written_path || "done"), "ok");
        } catch (e) { toast(e.message || e, "err"); }
      });
    }

    // SMTP status + recipients
    const loadSmtpStatus = async () => {
      try {
        const s = await api("/admin/smtp/status", { timeoutMs: 8000 });
        const smtpEl = $v("#smtpStatus");
        if (!smtpEl) return;
        const okBadge = s.enabled
          ? `<span class="badge online">SMTP on</span>`
          : `<span class="badge offline">SMTP off</span>`;
        const last = s.last_error ? `<span class="chip" title="last error">${escapeHtml(s.last_error)}</span>` : "";
        smtpEl.innerHTML = `${okBadge}
          <span class="chip">host: ${escapeHtml(s.host || "—")}:${escapeHtml(String(s.port || "—"))}</span>
          <span class="chip">mode: ${escapeHtml(s.mode || "—")}</span>
          <span class="chip">from: ${escapeHtml(s.sender || "—")}</span>
          <span class="chip">sent: ${s.sent_count || 0}</span>
          <span class="chip">failed: ${s.failed_count || 0}</span>
          <span class="chip">queue: ${s.queue_size ?? 0}/${s.queue_max ?? ""}</span>${last}`;
      } catch (e) {
        const smtpEl = $v("#smtpStatus");
        if (!smtpEl) return;
        smtpEl.innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`;
      }
    };
    const loadRecipients = async () => {
      try {
        const d = await api("/admin/alert-recipients", { timeoutMs: 8000 });
        const items = d.items || [];
        const listEl = $v("#recipientList");
        if (!listEl) return;
        listEl.innerHTML = items.length === 0
          ? `<p class="muted">No recipients yet.</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>Email</th><th>Label</th><th>Enabled</th><th>Tenant</th><th></th></tr></thead>
              <tbody>${items.map((r) => `
                <tr>
                  <td class="mono">${escapeHtml(r.email)}</td>
                  <td>${escapeHtml(r.label || "—")}</td>
                  <td>${r.enabled ? `<span class="badge online">On</span>` : `<span class="badge offline">Off</span>`}</td>
                  <td class="mono">${escapeHtml(r.owner_admin || "")}</td>
                  <td>
                    <button class="btn sm secondary js-rtoggle" data-id="${r.id}" data-en="${r.enabled ? 1 : 0}">${r.enabled ? "Disable" : "Enable"}</button>
                    <button class="btn sm danger js-rdel" data-id="${r.id}">Delete</button>
                  </td>
                </tr>`).join("")}</tbody></table></div>`;
      } catch (e) {
        const listEl = $v("#recipientList");
        if (!listEl) return;
        listEl.innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`;
      }
    };
    $v("#r_add").addEventListener("click", async () => {
      const email = ($v("#r_email").value || "").trim();
      const label = ($v("#r_label").value || "").trim();
      if (!email) { toast("Enter email", "err"); return; }
      try {
        await api("/admin/alert-recipients", { method: "POST", body: { email, label } });
        $v("#r_email").value = ""; $v("#r_label").value = "";
        toast("Added", "ok");
        loadRecipients();
      } catch (e) { toast(e.message || e, "err"); }
    });
    $v("#r_test").addEventListener("click", async () => {
      const email = ($v("#r_email").value || "").trim();
      if (!email) { toast("Enter recipient email first", "err"); return; }
      try {
        await api("/admin/smtp/test", { method: "POST", body: { to: email } });
        toast("SMTP test sent", "ok");
        loadSmtpStatus();
      } catch (e) { toast(e.message || e, "err"); }
    });
    const loadTgStatus = async () => {
      try {
        const t = await api("/admin/telegram/status", { timeoutMs: 8000 });
        const tgEl = $v("#tgStatus");
        if (!tgEl) return;
        const badge = t.enabled
          ? `<span class="badge online">enabled</span>`
          : `<span class="badge offline">disabled</span>`;
        const wk = t.worker_running ? "yes" : "no";
        const th = t.token_hint ? `<span class="chip mono" title="Token prefix/suffix only">${escapeHtml(t.token_hint)}</span>` : "";
        const modErr = t.status_module_error
          ? `<p class="badge revoked" style="margin-top:8px">Telegram module failed — see <span class="mono">last_error</span> and API logs.</p>`
          : "";
        const le = (t.last_error || "").trim()
          ? `<p class="muted" style="margin-top:8px;word-break:break-word"><strong>Last error:</strong> ${escapeHtml(t.last_error)}</p>`
          : "";
        tgEl.innerHTML = `${badge}
          ${th}
          <span class="chip">worker: ${wk}</span>
          <span class="chip">chats: ${t.chats ?? 0}</span>
          <span class="chip">min_level: ${escapeHtml(t.min_level || "")}</span>
          <span class="chip">queue: ${t.queue_size ?? 0}</span>${modErr}${le}`;
      } catch (e) {
        const tgEl = $v("#tgStatus");
        if (!tgEl) return;
        tgEl.innerHTML = `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`;
      }
    };
    $v("#tgTest").addEventListener("click", async () => {
      try {
        const r = await api("/admin/telegram/test", { method: "POST", body: { text: "Croc Sentinel UI test" } });
        toast(r.detail || "ok", "ok");
        loadTgStatus();
      } catch (e) { toast(e.message || e, "err"); }
    });
    $v("#recipientList").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      const id = b.dataset.id;
      if (b.classList.contains("js-rdel")) {
        if (!confirm("Remove this recipient?")) return;
        try { await api(`/admin/alert-recipients/${id}`, { method: "DELETE" }); toast("Removed", "ok"); loadRecipients(); }
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
        const d = await api("/auth/signup/pending", { timeoutMs: 8000 });
        const items = d.items || [];
        const pendEl = $v("#pendAdmins");
        if (!pendEl) return;
        pendEl.innerHTML = items.length === 0
          ? `<p class="muted">No pending signups.</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>Username</th><th>Email</th><th>Submitted</th><th>Email OK</th><th></th></tr></thead>
              <tbody>${items.map((u) => `<tr>
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td class="mono">${escapeHtml(u.email || "—")}</td>
                <td>${escapeHtml(fmtTs(u.created_at))}</td>
                <td>${u.email_verified_at ? "✓" : "—"}</td>
                <td>
                  <button class="btn sm js-ok" data-u="${escapeHtml(u.username)}">Approve</button>
                  <button class="btn sm danger js-reject" data-u="${escapeHtml(u.username)}">Reject</button>
                </td>
              </tr>`).join("")}</tbody></table></div>`;
      } catch (e) {
        const pendEl = $v("#pendAdmins");
        if (!pendEl) return;
        pendEl.innerHTML = `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`;
      }
    };
    if (isSuper) {
      $v("#pendAdmins").addEventListener("click", async (ev) => {
        const b = ev.target.closest("button"); if (!b) return;
        const u = b.dataset.u;
        if (b.classList.contains("js-ok")) {
          try { await api(`/auth/signup/approve/${encodeURIComponent(u)}`, { method: "POST" }); toast("Approved", "ok"); loadPendAdmins(); loadUsers(); }
          catch (e) { toast(e.message || e, "err"); }
        } else if (b.classList.contains("js-reject")) {
          if (!confirm(`Reject and delete signup for ${u}?`)) return;
          try { await api(`/auth/signup/reject/${encodeURIComponent(u)}`, { method: "POST" }); toast("Rejected", "ok"); loadPendAdmins(); }
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
        <div class="row" style="flex-wrap:wrap;align-items:flex-end;gap:12px">
          <div style="flex:1;min-width:200px">
            <h2 style="margin:0">Signal log</h2>
            <p class="muted" style="margin:6px 0 0">Device alarms and dashboard/API siren events. Group comes from device notification settings.</p>
          </div>
          <label class="field" style="max-width:140px;margin:0"><span>Hours</span><input id="sig_hours" type="number" value="168" min="1" max="720"/></label>
          <button class="btn secondary btn-tap" id="sig_reload">Refresh</button>
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
              <thead><tr><th>When (UTC)</th><th>What</th><th>Where</th><th>Device</th><th>Group</th><th>Name</th><th>Who</th><th>Fan-out</th><th>Email</th></tr></thead>
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
                  <td>${escapeHtml(a.notification_group || "—")}</td>
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
      { accepted: "Accepted", declined: "Declined", rolled_back: "Rolled back" }[myDec.action] || myDec.action
    ) : (me.role === "superadmin" ? "—" : "Pending");
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
              ? `<button class="btn sm js-accept" data-id="${escapeHtml(c.id)}">Accept</button>
                 <button class="btn sm secondary js-decline" data-id="${escapeHtml(c.id)}">Decline</button>`
              : ""}
          ${(myDec && myDec.action === "accepted")
              ? `<button class="btn sm danger js-rollback" data-id="${escapeHtml(c.id)}">Rollback</button>`
              : ""}
          <button class="btn sm secondary js-detail" data-id="${escapeHtml(c.id)}">Detail</button>
        </td>
      </tr>`;
  }

  registerRoute("ota", async (view) => {
    setCrumb("OTA");
    const me = state.me || { username: "", role: "" };
    if (!hasRole("admin")) { view.innerHTML = `<div class="card"><p class="muted">OTA is available to admin and above.</p></div>`; return; }
    const isSuper = me.role === "superadmin";

    view.innerHTML = `
      ${isSuper ? `
      <div class="card">
        <h2>New OTA campaign</h2>
        <p class="muted">
          Superadmin sets firmware version + download URL. Each admin sees the campaign as
          <strong>pending</strong>; on <strong>Accept</strong> the server HEAD-checks the URL then dispatches OTA to that admin’s devices.
          Failed devices roll back automatically.
        </p>
        <div id="fwList" class="muted">Loading firmware list…</div>
        <div class="divider"></div>
        <div class="inline-form" style="margin-top:10px">
          <label class="field"><span>Firmware version *</span><input id="c_fw" placeholder="2.2.0" /></label>
          <label class="field wide"><span>Download URL *</span><input id="c_url" placeholder="https://cdn.example.com/sentinel-v2.2.0.bin" /></label>
          <label class="field"><span>SHA-256 (optional)</span><input id="c_sha" placeholder="64 hex chars" /></label>
          <label class="field wide"><span>Target admins (empty = all)</span>
            <input id="c_admins" placeholder="admin-a, admin-b or leave blank" />
          </label>
          <label class="field wide"><span>Notes</span><input id="c_notes" maxlength="500" /></label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn danger btn-tap" id="c_send">Create campaign</button>
          </div>
        </div>
      </div>` : ""}
      <div class="card">
        <div class="row between">
          <h2 style="margin:0">Campaigns</h2>
          <button class="btn sm secondary" id="camp_reload">Refresh</button>
        </div>
        <div id="campList" class="muted" style="margin-top:8px">Loading…</div>
      </div>
      <div id="campDetail"></div>`;

    async function loadCampaigns() {
      try {
        const r = await api("/ota/campaigns");
        const list = r.items || [];
        if (list.length === 0) {
          $("#campList").innerHTML = `<p class="muted">No OTA campaigns.</p>`;
          return;
        }
        $("#campList").innerHTML = `<div class="table-wrap"><table class="t">
          <thead><tr><th>ID</th><th>Version</th><th>URL</th><th>State</th><th>Progress</th><th>My decision</th><th>Created</th><th></th></tr></thead>
          <tbody>${list.map((c) => renderOtaCampaignRow(c, me)).join("")}</tbody>
        </table></div>`;

        view.querySelectorAll(".js-accept").forEach((b) => b.addEventListener("click", async () => {
          if (!confirm("Accept upgrade? The server will verify the URL then push to all devices you own.")) return;
          try {
            const r2 = await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}/accept`, { method: "POST", body: {} });
            toast(`Dispatched ${r2.dispatched}/${r2.target_count} · verify: ${r2.verify}`, "ok");
            loadCampaigns();
          } catch (e) { toast(e.message || e, "err"); }
        }));
        view.querySelectorAll(".js-decline").forEach((b) => b.addEventListener("click", async () => {
          if (!confirm("Decline this upgrade?")) return;
          try { await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}/decline`, { method: "POST", body: {} }); loadCampaigns(); }
          catch (e) { toast(e.message || e, "err"); }
        }));
        view.querySelectorAll(".js-rollback").forEach((b) => b.addEventListener("click", async () => {
          if (!confirm("Rollback? Upgraded devices will be pushed back to the previous firmware.")) return;
          try { const r2 = await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}/rollback`, { method: "POST", body: {} }); toast(`Rolled back ${r2.rolled_back} device(s)`, "ok"); loadCampaigns(); }
          catch (e) { toast(e.message || e, "err"); }
        }));
        view.querySelectorAll(".js-detail").forEach((b) => b.addEventListener("click", async () => {
          try {
            const c = await api(`/ota/campaigns/${encodeURIComponent(b.dataset.id)}`);
            $("#campDetail").innerHTML = `<div class="card">
              <h3>Campaign ${escapeHtml(c.id)}</h3>
              <p class="muted">FW ${escapeHtml(c.fw_version)} · ${escapeHtml(c.state)} · created ${escapeHtml(c.created_at)}</p>
              <p class="mono" style="word-break:break-all">${escapeHtml(c.url)}</p>
              <h4 style="margin:12px 0 4px">Device runs</h4>
              <div class="table-wrap"><table class="t">
                <thead><tr><th>admin</th><th>Device</th><th>Prev fw</th><th>Target fw</th><th>State</th><th>Error</th><th>Finished</th></tr></thead>
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
          ? `<p class="muted">No .bin files under ${escapeHtml(fw.dir || "/opt/sentinel/firmware")}.</p>`
          : `<div class="table-wrap"><table class="t">
              <thead><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Modified</th><th></th></tr></thead>
              <tbody>${fw.items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.name)}</td>
                  <td>${(it.size / 1024).toFixed(1)} KB</td>
                  <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(it.sha256 || "—")}</td>
                  <td>${escapeHtml(fmtTs(it.mtime))}</td>
                  <td>${it.download_url ? `<button class="btn sm secondary js-use" data-url="${escapeHtml(it.download_url)}" data-fw="${escapeHtml(it.name.replace(/\\.bin$/i, ""))}" data-sha="${escapeHtml(it.sha256 || "")}">Use in form</button>` : ""}</td>
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
        if (!url || !fw) { toast("Firmware version and URL required", "err"); return; }
        if (!confirm(`Create OTA campaign? Target admins: ${target_admins.join(", ") || "ALL"}`)) return;
        try {
          const r = await api("/ota/campaigns", { method: "POST", body: { fw_version: fw, url, sha256: sha || undefined, notes, target_admins } });
          toast(`Campaign ${r.campaign_id} · ${r.target_admins.length} admin(s)`, "ok");
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
        <p class="muted" style="margin:0">Capabilities for <strong>${escapeHtml(username)}</strong> (user role).</p>
        <div class="row">
          ${row("can_alert", "Alarms (device + bulk + cancel)")}
          ${row("can_send_command", "Send device commands")}
          ${row("can_claim_device", "Claim / provision devices")}
          ${row("can_manage_users", "Manage users (N/A for user role)", true)}
          ${row("can_backup_restore", "Backup / restore (N/A for user role)", true)}
        </div>
        <div class="row" style="justify-content:flex-end">
          <button class="btn js-save" type="button">Save</button>
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

    document.addEventListener("click", (ev) => {
      const b = ev.target.closest(".btn-tap");
      if (!b || b.disabled) return;
      try {
        if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        if (typeof navigator !== "undefined" && navigator.vibrate) navigator.vibrate(10);
      } catch (_) {}
    }, true);

    await (getToken() ? loadMe() : Promise.resolve());
    if (!location.hash) location.hash = state.me ? "#/overview" : "#/login";
    else renderRoute();
    // Do not block first render on health probes.
    loadHealth().catch(() => {});
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
            live.textContent = "Paused";
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
