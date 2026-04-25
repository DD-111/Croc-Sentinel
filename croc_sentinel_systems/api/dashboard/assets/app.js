/* Croc Sentinel Console — IIFE bundle; edit src/ + npm run build */
"use strict";
(() => {
  // src/routes/manifest.js
  var ROUTES = Object.freeze([
    // -------------------------------------------------------------- public auth
    { id: "login", hash: "#/login", public: true },
    { id: "forgot-password", hash: "#/forgot-password", public: true },
    { id: "register", hash: "#/register", public: true },
    { id: "account-activate", hash: "#/account-activate", public: true },
    // -------------------------------------------------------------- account
    { id: "account", hash: "#/account", min: "user", group: "Account & admin", label: "Account", ico: "\u25CD" },
    // -------------------------------------------------------------- dashboard
    { id: "overview", hash: "#/overview", min: "user", group: "Dashboard", label: "Overview", ico: "\u25CE" },
    { id: "devices", hash: "#/devices", min: "user", group: "Dashboard", label: "All devices", ico: "\u25A2" },
    { id: "site", hash: "#/site", min: "superadmin", group: "Dashboard", label: "Site", ico: "\u2301" },
    // Deep link only (no nav entry): #/group/:key
    { id: "group", hash: "#/group", min: "user" },
    // -------------------------------------------------------------- monitoring
    { id: "signals", hash: "#/signals", min: "user", group: "Monitoring", label: "Signals", ico: "\u25C9", aliases: ["#/alarm-log"] },
    { id: "events", hash: "#/events", min: "user", group: "Monitoring", label: "Events", ico: "\u2248" },
    { id: "ota", hash: "#/ota", min: "superadmin", group: "Monitoring", label: "OTA (ops)", ico: "\u2191" },
    // -------------------------------------------------------------- alerts/fleet
    { id: "alerts", hash: "#/alerts", min: "user", group: "Alerts & fleet", label: "Siren", ico: "!" },
    { id: "activate", hash: "#/activate", min: "admin", group: "Alerts & fleet", label: "Activate device", ico: "+" },
    // -------------------------------------------------------------- admin
    { id: "telegram", hash: "#/telegram", min: "user", group: "Account & admin", label: "Telegram", ico: "\u2706" },
    { id: "audit", hash: "#/audit", min: "admin", group: "Account & admin", label: "Audit", ico: "\u2261" },
    { id: "admin", hash: "#/admin", min: "admin", group: "Account & admin", label: "Admin & users", ico: "\u263C" }
  ]);
  var GROUP_ORDER = ["Dashboard", "Monitoring", "Alerts & fleet", "Account & admin"];
  function buildNavGroups() {
    const byTitle = {};
    for (const r of ROUTES) {
      if (!r.group || !r.label) continue;
      const g = byTitle[r.group] || (byTitle[r.group] = { title: r.group, items: [] });
      g.items.push({
        id: r.id,
        label: r.label,
        ico: r.ico || "",
        path: r.hash,
        min: r.min || "user"
      });
    }
    return GROUP_ORDER.map((t) => byTitle[t]).concat(Object.keys(byTitle).filter((t) => !GROUP_ORDER.includes(t)).map((t) => byTitle[t])).filter(Boolean);
  }
  var PUBLIC_ROUTE_IDS = Object.freeze(new Set(ROUTES.filter((r) => r.public).map((r) => r.id)));
  var ROUTE_ALIASES = Object.freeze(
    ROUTES.reduce(
      (acc, r) => {
        if (Array.isArray(r.aliases)) {
          for (const a of r.aliases) acc[String(a)] = r.id;
        }
        return acc;
      },
      /** @type {Record<string, string>} */
      {}
    )
  );

  // src/lib/constants.js
  var LS = {
    token: "croc.token",
    user: "croc.user",
    role: "croc.role",
    zones: "croc.zones",
    theme: "croc.theme",
    sidebarCollapsed: "croc.sidebar.collapsed"
  };
  try {
    const _m = "croc.auth.migrate_cookie_v1";
    if (!localStorage.getItem(_m)) {
      localStorage.removeItem(LS.token);
      localStorage.setItem(_m, "1");
    }
  } catch (_) {
  }
  var OFFLINE_MS = 90 * 1e3;
  var DEFAULT_REMOTE_SIREN_MS = 18e4;
  var DEFAULT_PANIC_FANOUT_MS = 3e5;
  var NAV_GROUPS = buildNavGroups();
  var ROLE_WEIGHT = { user: 1, admin: 2, superadmin: 3 };

  // src/lib/dom.js
  var _lastHtmlByEl = /* @__PURE__ */ new WeakMap();
  var $ = (sel, root) => (root || document).querySelector(sel);
  var $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  function escapeHtml(v) {
    return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function parseHtmlToFragment(html) {
    const src = String(html ?? "");
    const frag = document.createDocumentFragment();
    if (!src.trim()) return frag;
    const doc = new DOMParser().parseFromString("<!DOCTYPE html><body>" + src + "</body>", "text/html");
    const b = doc.body;
    while (b.firstChild) frag.appendChild(b.firstChild);
    return frag;
  }
  function setChildMarkup(el, html) {
    if (!el) return;
    el.replaceChildren(parseHtmlToFragment(String(html ?? "")));
  }
  function prependChildMarkup(el, html) {
    if (!el) return;
    const frag = parseHtmlToFragment(html);
    const ref = el.firstChild;
    while (frag.firstChild) el.insertBefore(frag.firstChild, ref);
  }
  function appendChildMarkup(el, html) {
    if (!el) return;
    el.append(parseHtmlToFragment(html));
  }
  function setHtmlIfChanged(el, html) {
    if (!el) return false;
    const next = String(html == null ? "" : html);
    const prev = _lastHtmlByEl.has(el) ? _lastHtmlByEl.get(el) : null;
    if (prev === next) return false;
    el.replaceChildren(parseHtmlToFragment(next));
    _lastHtmlByEl.set(el, next);
    return true;
  }
  function setTextIfChanged(el, txt) {
    if (!el) return false;
    const next = String(txt == null ? "" : txt);
    if (el.textContent === next) return false;
    el.textContent = next;
    return true;
  }
  function hx(strings, ...values) {
    let out = "";
    for (let i = 0; i < strings.length; i++) {
      out += strings[i];
      if (i < values.length) out += escapeHtml(values[i]);
    }
    return out;
  }
  function mountView(el, html) {
    if (!el) return;
    el.replaceChildren(parseHtmlToFragment(String(html == null ? "" : html)));
  }

  // src/lib/sse.js
  function parseSseFields(block) {
    let eventName = "message";
    const dataLines = [];
    const lines = String(block || "").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line === "" || line.startsWith(":")) continue;
      const ci = line.indexOf(":");
      const field = ci === -1 ? line : line.slice(0, ci);
      let value = ci === -1 ? "" : line.slice(ci + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "event") eventName = value;
      else if (field === "data") dataLines.push(value);
    }
    return { event: eventName, data: dataLines.join("\n") };
  }
  var SSE_PARSE_BUF_MAX = 262144;
  async function pumpSseBody(reader, signal, onFrame) {
    const dec = new TextDecoder();
    let buf = "";
    while (!signal.aborted) {
      let chunk;
      try {
        chunk = await reader.read();
      } catch (_) {
        break;
      }
      const { done, value } = chunk || {};
      if (done) break;
      buf += dec.decode(value, { stream: true });
      if (buf.length > SSE_PARSE_BUF_MAX) {
        const cut = buf.lastIndexOf("\n\n", buf.length - 65536);
        buf = cut > 0 ? buf.slice(cut + 2) : "";
      }
      for (; ; ) {
        const m = buf.match(/\r?\n\r?\n/);
        if (!m) break;
        const idx = m.index || 0;
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + m[0].length);
        if (!String(raw || "").trim()) continue;
        const fields = parseSseFields(raw);
        if (fields.event === "ping") onFrame("ping", fields.data);
        else onFrame("message", fields.data);
      }
    }
  }

  // src/lib/format.js
  var MY_TZ = "Asia/Kuala_Lumpur";
  var MY_OFFSET_HINT = "(UTC+08:00)";
  function fmtTs(v) {
    if (!v) return "\u2014";
    const t = typeof v === "number" ? v > 1e12 ? v : v * 1e3 : Date.parse(v);
    if (!Number.isFinite(t)) return String(v);
    const d = new Date(t);
    const base = new Intl.DateTimeFormat("en-CA", {
      timeZone: MY_TZ,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(d).replace(",", "");
    return `${base} ${MY_OFFSET_HINT}`;
  }
  function fmtRel(v) {
    if (!v) return "\u2014";
    const t = Date.parse(v);
    if (!Number.isFinite(t)) return String(v);
    const diff = Date.now() - t;
    if (diff < 6e4) return "just now";
    if (diff < 36e5) return `${Math.floor(diff / 6e4)}m ago`;
    if (diff < 864e5) return `${Math.floor(diff / 36e5)}h ago`;
    return `${Math.floor(diff / 864e5)}d ago`;
  }
  function maskPlatform(_raw) {
    return "e**********";
  }
  function auditActionPrefix(action) {
    const s = String(action || "").trim();
    const i = s.indexOf(".");
    return i > 0 ? s.slice(0, i) : s || "other";
  }
  function auditDetailDedupedRows(detail, actor, target) {
    if (!detail || typeof detail !== "object" || Array.isArray(detail)) return [];
    const a = String(actor || "").trim();
    const t = String(target || "").trim();
    const rows = [];
    for (const [k, raw] of Object.entries(detail)) {
      if (raw == null || raw === "") continue;
      const str = typeof raw === "object" ? JSON.stringify(raw) : String(raw);
      if (!str.trim()) continue;
      if (str === a && /^(actor|username|user|owner|owner_admin|created_by)$/i.test(k)) continue;
      if (t && str === t && /^(target|device_id|deviceId|source_id)$/i.test(k)) continue;
      let display = str;
      if (display.length > 220) display = `${display.slice(0, 217)}\u2026`;
      rows.push({ k, v: display });
    }
    return rows;
  }
  function eventDetailDedupedRows(detail, e) {
    if (!detail || typeof detail !== "object" || Array.isArray(detail)) return [];
    const actor = String(e && e.actor || "").trim();
    const target = String(e && e.target || "").trim();
    const dev = String(e && e.device_id || "").trim();
    const owner = String(e && e.owner_admin || "").trim();
    const rows = [];
    for (const [k, raw] of Object.entries(detail)) {
      if (raw == null || raw === "") continue;
      const str = typeof raw === "object" ? JSON.stringify(raw) : String(raw);
      if (!str.trim()) continue;
      if (str === actor && /^(actor|username|user|owner_admin|created_by)$/i.test(k)) continue;
      if (target && str === target && /^(target)$/i.test(k)) continue;
      if (dev && str === dev && /^(device_id|deviceId|source_id|device)$/i.test(k)) continue;
      if (owner && str === owner && /^(owner_admin|owner)$/i.test(k)) continue;
      if (str === target && /^(target|device_id|deviceId)$/i.test(k)) continue;
      let display = str;
      if (display.length > 220) display = `${display.slice(0, 217)}\u2026`;
      rows.push({ k, v: display });
    }
    return rows;
  }
  function messagePayloadRows(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return [];
    const rows = [];
    for (const [k, raw] of Object.entries(payload)) {
      if (raw == null || raw === "") continue;
      if (String(k || "").startsWith("_")) continue;
      if (/^(ts|timestamp|nonce|seq|message_id|msg_id)$/i.test(String(k || ""))) continue;
      const str = typeof raw === "object" ? JSON.stringify(raw) : String(raw);
      if (!str.trim()) continue;
      let display = str;
      if (display.length > 200) display = `${display.slice(0, 197)}\u2026`;
      rows.push({ k, v: display });
    }
    return rows;
  }
  function auditChipClass(action) {
    const p = auditActionPrefix(action);
    const map = {
      alarm: "audit-pfx-alarm",
      provision: "audit-pfx-prov",
      factory: "audit-pfx-factory",
      telegram: "audit-pfx-tg",
      auth: "audit-pfx-auth",
      admin: "audit-pfx-admin",
      user: "audit-pfx-user",
      command: "audit-pfx-cmd",
      mqtt: "audit-pfx-sys",
      device: "audit-pfx-dev",
      ota: "audit-pfx-ota",
      bulk: "audit-pfx-cmd",
      remote: "audit-pfx-alarm",
      signal: "audit-pfx-alarm",
      schedule: "audit-pfx-sys",
      login: "audit-pfx-auth",
      signup: "audit-pfx-auth"
    };
    return map[p] || "audit-pfx-other";
  }

  // src/lib/api.js
  var DEFAULT_API_TIMEOUT_MS = 45e3;
  var ROUTE_RENDER_TIMEOUT_MS = 9e4;
  function apiBase() {
    const lp = location.port || "";
    if (lp === "8088" || lp === "18088" || lp === "18999") {
      return location.origin;
    }
    const m = document.querySelector('meta[name="croc-api-base"]');
    const raw = m && m.getAttribute("content") != null ? String(m.getAttribute("content")).trim() : "";
    if (raw.toLowerCase().startsWith("http")) {
      return raw.replace(/\/$/, "");
    }
    if (raw && raw !== "/") {
      const p = (raw.startsWith("/") ? raw : `/${raw}`).replace(/\/$/, "");
      return location.origin + p;
    }
    return location.origin;
  }
  async function fetchWithDeadline(url, init, timeoutMs) {
    const baseInit = Object.assign({ credentials: "include" }, init || {});
    const limit = timeoutMs === false ? 0 : timeoutMs != null ? timeoutMs : DEFAULT_API_TIMEOUT_MS;
    if (limit <= 0) return fetch(url, baseInit);
    const ac = new AbortController();
    const tid = setTimeout(() => ac.abort(), limit);
    try {
      return await fetch(url, Object.assign({}, baseInit, { signal: ac.signal }));
    } catch (e) {
      if (e && e.name === "AbortError") {
        throw new Error(
          `Request timed out after ${limit} ms \u2014 API slow or unreachable. Check browser Network tab, Nginx \`proxy_connect_timeout\` / \`proxy_read_timeout\`, and upstream service.`
        );
      }
      throw e;
    } finally {
      clearTimeout(tid);
    }
  }
  function _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  function _isTransientFetchError(err) {
    const s = String(err && err.message || err || "").toLowerCase();
    return s.includes("timed out") || s.includes("networkerror") || s.includes("failed to fetch") || s.includes("load failed") || s.includes("temporarily unavailable");
  }
  function _isRetryableHttpStatus(code) {
    return code === 408 || code === 425 || code === 429 || code === 502 || code === 503 || code === 504;
  }
  function _isWriteMethod(m) {
    const x = String(m || "GET").toUpperCase();
    return x !== "GET" && x !== "HEAD" && x !== "OPTIONS";
  }

  // src/lib/csrf.js
  var CSRF_COOKIE_NAME = (function() {
    const m = document.querySelector('meta[name="croc-csrf-cookie"]');
    return (m && m.getAttribute("content") || "sentinel_csrf").trim() || "sentinel_csrf";
  })();
  var CSRF_HEADER_NAME = (function() {
    const m = document.querySelector('meta[name="croc-csrf-header"]');
    return (m && m.getAttribute("content") || "X-CSRF-Token").trim() || "X-CSRF-Token";
  })();
  var _csrfTokenMemory = "";
  function _readCsrfCookie() {
    try {
      const all = String(document.cookie || "");
      const parts = all.split(/;\s*/);
      for (let i = 0; i < parts.length; i++) {
        const idx = parts[i].indexOf("=");
        if (idx <= 0) continue;
        if (parts[i].slice(0, idx) === CSRF_COOKIE_NAME) {
          return decodeURIComponent(parts[i].slice(idx + 1));
        }
      }
    } catch (_) {
    }
    return "";
  }
  function getCsrfToken() {
    if (_csrfTokenMemory) return _csrfTokenMemory;
    const c = _readCsrfCookie();
    if (c) _csrfTokenMemory = c;
    return _csrfTokenMemory;
  }
  function setCsrfToken(t) {
    _csrfTokenMemory = String(t || "");
  }
  async function refreshCsrfToken() {
    try {
      const r = await fetchWithDeadline(apiBase() + "/auth/csrf", { method: "GET" }, 12e3);
      if (r && r.ok) {
        const j = await r.json().catch(() => ({}));
        if (j && j.csrf_token) {
          setCsrfToken(String(j.csrf_token));
          return _csrfTokenMemory;
        }
      }
    } catch (_) {
    }
    const c = _readCsrfCookie();
    if (c) _csrfTokenMemory = c;
    return _csrfTokenMemory;
  }
  function _isCsrfRejection(status, bodyText) {
    if (Number(status) !== 403) return false;
    const t = String(bodyText || "");
    if (t.indexOf("csrf_invalid") >= 0) return true;
    try {
      const j = JSON.parse(t);
      const code = j && (j.code || j.detail);
      if (typeof code === "string" && code.toLowerCase().indexOf("csrf") >= 0) return true;
    } catch (_) {
    }
    return false;
  }

  // src/lib/auth-chrome.js
  function authSiteFooterHtml() {
    return `
      <footer class="site-footer site-footer--auth" aria-label="Page footer">
        <div class="site-footer__row site-footer__row--auth">
          <div class="site-footer__brand site-footer__brand--company" role="group" aria-label="ESA">
            <div class="site-footer__wordmark" lang="en">ESA</div>
          </div>
          <p class="site-footer__legal">CROC AI</p>
        </div>
      </footer>`;
  }
  function authAsideHtml(kind) {
    const m = {
      login: {
        t: "Operations console",
        d: "Role-scoped monitoring, OTA, and device control in one place.",
        items: ["Audit-ready events", "Per-tenant device boundaries", "Real-time health"]
      },
      register: {
        t: "Admin workspace",
        d: "Email verification, then sign in to manage your fleet.",
        items: ["Isolated tenant data", "Verification + cooldown", "No shared MQTT bleed"]
      },
      recovery: {
        t: "Account recovery",
        d: "We send a one-time code to the email on file for this account.",
        items: ["Match username to email", "Code from your inbox", "Set a new password here"]
      },
      activate: {
        t: "Activate access",
        d: "An administrator created your user \u2014 confirm with the email we sent you.",
        items: ["One-time code", "Same inbox as the invite", "Then use Sign in"]
      }
    };
    const c = m[kind] || m.login;
    return `
      <aside class="auth-surface__side" aria-label="ESA">
        <div class="auth-surface__side-main">
        <div class="auth-surface__side-content">
          <div class="auth-surface__company" lang="en">
            <p class="auth-surface__company-eyebrow">Secured platform provider</p>
            <p class="auth-surface__wordmark" translate="no">ESA</p>
            <p class="auth-surface__company-line" lang="en">Private, secured operations and tenant-safe edge access \u2014 one platform.</p>
            <p class="auth-surface__product-line" translate="no"><span class="auth-surface__product-name">Croc Sentinel</span> <span class="auth-surface__product-role">fleet console</span></p>
          </div>
          <h2 class="auth-surface__headline">${c.t}</h2>
          <p class="auth-surface__lede">${c.d}</p>
          <ul class="auth-surface__bullets" role="list">
            ${c.items.map((x) => `<li>${x}</li>`).join("")}
          </ul>
        </div>
        </div>
        <div class="auth-surface__side-foot" role="group" aria-label="Partners">
          <div class="auth-surface__partner-logos">
            <img class="auth-surface__partner-logo" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="" data-partner-slot="1" loading="lazy" decoding="async" />
            <img class="auth-surface__partner-logo" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="" data-partner-slot="2" loading="lazy" decoding="async" />
            <img class="auth-surface__partner-logo" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="" data-partner-slot="3" loading="lazy" decoding="async" />
          </div>
        </div>
      </aside>`;
  }

  // src/virtual-console.js
  function getToken() {
    return localStorage.getItem(LS.token) || "";
  }
  function setToken(t) {
    t ? localStorage.setItem(LS.token, t) : localStorage.removeItem(LS.token);
    if (!t) {
      _groupMetaSyncChain = Promise.resolve();
    }
  }
  function roleWeight(r) {
    return ROLE_WEIGHT[r] || 0;
  }
  function hasRole(min) {
    return state.me && roleWeight(state.me.role) >= roleWeight(min);
  }
  function can(cap) {
    return !!(state.me && state.me.policy && state.me.policy[cap]);
  }
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
    el._t = setTimeout(() => {
      el.className = "toast";
    }, 3200);
  }
  async function boot() {
    initTheme();
    $("#menuBtn").addEventListener("click", () => toggleNav());
    $("#sidebarBackdrop").addEventListener("click", () => toggleNav(false));
    const railT = document.getElementById("sidebarRailToggle");
    if (railT) railT.addEventListener("click", () => toggleSidebarRail());
    window.addEventListener("resize", syncNavForViewport);
    window.addEventListener("orientationchange", syncNavForViewport);
    $("#themeBtn").addEventListener("click", () => {
      setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("#logoutBtn").addEventListener("click", async () => {
      try {
        await fetchWithDeadline(apiBase() + "/auth/logout", { method: "POST" }, 12e3);
      } catch (_) {
      }
      setToken("");
      state.me = null;
      clearHealthPollTimer();
      location.hash = "#/login";
      renderAuthState();
    });
    $("#refreshBtn").addEventListener("click", () => renderRoute());
    document.addEventListener("click", (ev) => {
      const b = ev.target.closest(".btn-tap");
      if (!b || b.disabled) return;
      try {
        if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        if (typeof navigator !== "undefined" && navigator.vibrate) navigator.vibrate(10);
      } catch (_) {
      }
    }, true);
    await loadMe();
    syncNavForViewport();
    try {
      applySidebarRail();
    } catch (_) {
    }
    if (!location.hash) location.hash = state.me ? "#/overview" : "#/login";
    else renderRoute();
    await loadHealth().catch(() => {
    });
    window.addEventListener("online", () => {
      loadHealth().catch(() => {
      });
      tickHealthIfVisible();
      if (typeof window.__eventsStreamResume === "function") {
        try {
          if (!window.__evSSE || window.__evSSE.readyState === EventSource.CLOSED) {
            window.__eventsStreamResume();
          } else {
            syncEventsLiveBadge();
          }
        } catch (_) {
        }
      }
    });
    document.addEventListener("visibilitychange", () => {
      document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
      if (document.visibilityState === "hidden") {
        const live = document.getElementById("evLive");
        if (live && window.__evSSE && window.__evSSE.readyState === EventSource.OPEN) {
          live.textContent = "Background";
          live.className = "badge neutral";
          live.title = "Stream stays connected in background";
        }
        return;
      }
      tickHealthIfVisible();
      syncEventsLiveBadge();
      if (typeof window.__eventsStreamResume === "function") {
        try {
          if (!window.__evSSE || window.__evSSE.readyState === EventSource.CLOSED) {
            window.__eventsStreamResume();
          }
        } catch (_) {
        }
      }
    });
    document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
  }
  document.addEventListener("DOMContentLoaded", boot);
  var state = {
    me: null,
    mqttConnected: false,
    health: null,
    overviewCache: null,
    routeSeq: 0
  };
  var GROUP_CARD_TENANT_SEP = "";
  function normalizeGroupKeyStr(v) {
    return String(v == null ? "" : v).trim();
  }
  function canonicalGroupKey(v) {
    let s = normalizeGroupKeyStr(v);
    if (!s) return "";
    try {
      s = s.normalize("NFC");
    } catch (_) {
    }
    return s.replace(/\s+/g, " ");
  }
  function groupCardMetaKey(groupKey, tenantOwner) {
    const gk = canonicalGroupKey(groupKey);
    if (!gk) return "";
    if (state.me && state.me.role === "superadmin") {
      const o = String(tenantOwner || "").trim();
      return `${o || "__unowned__"}${GROUP_CARD_TENANT_SEP}${gk}`;
    }
    return gk;
  }
  function parseGroupMetaKey(metaKey) {
    const mk = String(metaKey || "");
    if (state.me && state.me.role === "superadmin" && mk.includes(GROUP_CARD_TENANT_SEP)) {
      const i = mk.indexOf(GROUP_CARD_TENANT_SEP);
      let tenantOwner = mk.slice(0, i).trim();
      if (tenantOwner === "__unowned__") tenantOwner = "";
      return { tenantOwner, groupKey: canonicalGroupKey(mk.slice(i + 1)) };
    }
    return { tenantOwner: "", groupKey: canonicalGroupKey(mk) };
  }
  function buildGroupSlotsFromDeviceList(devList) {
    const acc = /* @__PURE__ */ new Map();
    const isSuper = state.me && state.me.role === "superadmin";
    for (const d of Array.isArray(devList) ? devList : []) {
      const gk = canonicalGroupKey(d && d.notification_group);
      if (!gk) continue;
      const tenant = isSuper ? String(d.owner_admin || "").trim() : "";
      const mk = groupCardMetaKey(gk, tenant);
      if (!acc.has(mk)) acc.set(mk, { metaKey: mk, groupKey: gk, tenantOwner: tenant });
    }
    return Array.from(acc.values()).sort((a, b) => {
      const c = a.groupKey.localeCompare(b.groupKey);
      return c !== 0 ? c : a.tenantOwner.localeCompare(b.tenantOwner);
    });
  }
  function groupApiQueryOwner(tenantOwner) {
    const o = String(tenantOwner || "").trim();
    if (!(state.me && state.me.role === "superadmin" && o)) return "";
    return `owner_admin=${encodeURIComponent(o)}`;
  }
  function groupApiSuffixWithOwner(pathSuffix, tenantOwner) {
    const q = groupApiQueryOwner(tenantOwner);
    if (!q) return pathSuffix;
    const join = pathSuffix.includes("?") ? "&" : "?";
    return `${pathSuffix}${join}${q}`;
  }
  function groupMetaStorageKey() {
    return state.me && state.me.username ? `croc.group.meta.v2.${state.me.username}` : "croc.group.meta.v2.anon";
  }
  function reconcileGroupMetaForDevice(deviceId, newGroupKey, ownerHint) {
    try {
      const k = groupMetaStorageKey();
      const raw = localStorage.getItem(k);
      const meta = raw ? JSON.parse(raw) : {};
      if (!meta || typeof meta !== "object") return;
      const id = String(deviceId || "");
      for (const gk of Object.keys(meta)) {
        const m = meta[gk];
        if (!m || !Array.isArray(m.device_ids)) continue;
        const fil = m.device_ids.filter((x) => String(x) !== id);
        if (fil.length !== m.device_ids.length) {
          if (fil.length) meta[gk] = { ...m, device_ids: fil };
          else delete meta[gk];
        }
      }
      const ng = canonicalGroupKey(newGroupKey);
      if (ng) {
        const ck = groupCardMetaKey(ng, ownerHint);
        if (!ck) return;
        if (!meta[ck] || typeof meta[ck] !== "object") {
          meta[ck] = { display_name: ng, owner_name: "", phone: "", email: "", device_ids: [] };
        }
        const s = new Set((meta[ck].device_ids || []).map(String));
        s.add(id);
        meta[ck].device_ids = Array.from(s);
      }
      localStorage.setItem(k, JSON.stringify(meta));
    } catch (_) {
    }
  }
  function removeDeviceIdFromAllGroupMeta(deviceId) {
    reconcileGroupMetaForDevice(deviceId, "");
  }
  function syncGroupMetaWithDevices(meta, devices) {
    if (!meta || typeof meta !== "object") return meta;
    const list = Array.isArray(devices) ? devices : [];
    const isSuper = state.me && state.me.role === "superadmin";
    const notifMap = /* @__PURE__ */ new Map();
    for (const d of list) {
      const g = canonicalGroupKey(d && d.notification_group);
      if (!g) continue;
      const ck = groupCardMetaKey(g, isSuper ? d.owner_admin : "");
      if (!notifMap.has(ck)) notifMap.set(ck, []);
      notifMap.get(ck).push(String(d.device_id));
    }
    for (const [ck, ids] of notifMap.entries()) {
      const prev = meta[ck] && typeof meta[ck] === "object" ? meta[ck] : {};
      let dn = prev.display_name && String(prev.display_name).trim() || "";
      if (!dn) {
        const gOnly = isSuper && ck.includes(GROUP_CARD_TENANT_SEP) ? ck.slice(ck.indexOf(GROUP_CARD_TENANT_SEP) + 1) : ck;
        dn = gOnly;
      }
      meta[ck] = {
        display_name: dn,
        owner_name: prev.owner_name != null ? String(prev.owner_name) : "",
        phone: prev.phone != null ? String(prev.phone) : "",
        email: prev.email != null ? String(prev.email) : "",
        device_ids: ids
      };
    }
    for (const g of Object.keys(meta)) {
      if (!notifMap.has(g)) delete meta[g];
    }
    return meta;
  }
  var _groupMetaSyncTimer = null;
  var _groupMetaSyncChain = Promise.resolve();
  function syncGroupMetaFromServer() {
    if (!state.me) {
      return _groupMetaSyncChain;
    }
    _groupMetaSyncChain = _groupMetaSyncChain.then(async () => {
      if (!state.me) return;
      const r = await api("/devices", { timeoutMs: 18e3, retries: 1 });
      let meta = {};
      try {
        const raw = localStorage.getItem(groupMetaStorageKey());
        meta = raw ? JSON.parse(raw) : {};
      } catch (_) {
        meta = {};
      }
      if (!meta || typeof meta !== "object") meta = {};
      syncGroupMetaWithDevices(meta, r && r.items || []);
      localStorage.setItem(groupMetaStorageKey(), JSON.stringify(meta));
    }).catch(() => {
    });
    return _groupMetaSyncChain;
  }
  function scheduleSyncGroupMetaFromServer() {
    if (!state.me) return;
    if (_groupMetaSyncTimer) clearTimeout(_groupMetaSyncTimer);
    _groupMetaSyncTimer = setTimeout(() => {
      _groupMetaSyncTimer = null;
      void syncGroupMetaFromServer();
    }, 400);
  }
  var routeRedirectTimer = null;
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
  window.__eventsStreamResume = null;
  var healthPollTimer = null;
  var overviewFilterDebounce = null;
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
  var HEALTH_POLL_SLOW_MS = 12e3;
  var HEALTH_POLL_FAST_MS = 3500;
  function armHealthPoll() {
    clearHealthPollTimer();
    if (!state.me) return;
    const fast = state.mqttConnected === false;
    const ms = fast ? HEALTH_POLL_FAST_MS : HEALTH_POLL_SLOW_MS;
    healthPollTimer = setInterval(tickHealthIfVisible, ms);
  }
  function syncEventsLiveBadge() {
    const live = document.getElementById("evLive");
    if (!live || !window.__evSSE) return;
    const es = window.__evSSE;
    if (es.readyState === EventSource.OPEN) {
      live.textContent = "Live";
      live.className = "badge online";
      live.title = "Live stream connected";
    } else if (es.readyState === EventSource.CONNECTING) {
      live.textContent = "Reconnecting\u2026";
      live.className = "badge offline";
      live.title = "SSE reconnecting";
    }
  }
  async function api(path, opts) {
    opts = opts || {};
    const token = getToken();
    const headers = Object.assign({}, opts.headers || {});
    if (token) headers.Authorization = "Bearer " + token;
    let body = opts.body;
    if (body && typeof body === "object" && !(body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    const method = String(opts.method || "GET").toUpperCase();
    if (_isWriteMethod(method) && !token && !headers[CSRF_HEADER_NAME]) {
      const ctok = getCsrfToken();
      if (ctok) headers[CSRF_HEADER_NAME] = ctok;
    }
    const retryable = opts.retryable != null ? !!opts.retryable : method === "GET" || method === "HEAD";
    const retries = Number.isFinite(Number(opts.retries)) ? Math.max(0, Number(opts.retries)) : retryable ? 2 : 0;
    let csrfRetry = 0;
    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const r = await fetchWithDeadline(
          apiBase() + path,
          { method, headers, body },
          opts.timeoutMs
        );
        if (r.status === 401) {
          setToken("");
          setCsrfToken("");
          state.me = null;
          try {
            await fetchWithDeadline(apiBase() + "/auth/logout", { method: "POST" }, 8e3);
          } catch (_) {
          }
          if (location.hash !== "#/login") location.hash = "#/login";
          throw new Error("401 Unauthorized or session expired");
        }
        if (!r.ok) {
          if (_isWriteMethod(method) && csrfRetry === 0 && Number(r.status) === 403) {
            const t403 = await r.clone().text().catch(() => "");
            if (_isCsrfRejection(403, t403)) {
              csrfRetry = 1;
              const fresh = await refreshCsrfToken();
              if (fresh) {
                headers[CSRF_HEADER_NAME] = fresh;
                attempt--;
                continue;
              }
            }
          }
          if (retryable && attempt < retries && _isRetryableHttpStatus(Number(r.status))) {
            await _sleep(250 * 2 ** attempt);
            continue;
          }
          const t = await r.text().catch(() => "");
          let msg;
          try {
            const j = JSON.parse(t);
            let d = j.detail;
            if (Array.isArray(d)) {
              d = d.map((x) => x && x.msg ? x.msg : String(x)).join("; ");
            }
            msg = d || t;
          } catch {
            msg = t;
          }
          throw new Error(`${r.status} ${msg || r.statusText}`);
        }
        const ct = r.headers.get("content-type") || "";
        if (ct.includes("application/json")) return r.json();
        if (opts.raw) return r;
        return r.text();
      } catch (e) {
        lastErr = e;
        if (retryable && attempt < retries && _isTransientFetchError(e)) {
          await _sleep(250 * 2 ** attempt);
          continue;
        }
        throw e;
      }
    }
    throw lastErr || new Error("request failed");
  }
  async function apiOr(path, fallback, opts) {
    try {
      return await api(path, opts);
    } catch (e) {
      return typeof fallback === "function" ? fallback(e) : fallback;
    }
  }
  function isGroupRouteMissingError(err) {
    const msg = String(err && err.message || err || "");
    return msg.includes("404") || msg.includes("405") || msg.includes("501");
  }
  function groupTriggerPayloadFromSettings(gs) {
    const s = gs || {};
    const delay_seconds = Number(s.delay_seconds || 0);
    const trigger_duration_ms = Number(s.trigger_duration_ms || DEFAULT_REMOTE_SIREN_MS);
    return {
      trigger_mode: delay_seconds > 0 ? "delay" : "continuous",
      trigger_duration_ms,
      delay_seconds,
      reboot_self_check: !!s.reboot_self_check
    };
  }
  async function runGroupApplyOnAction(ctx) {
    const { groupKey, ownerAdmin, payload, apiCaps, saveApiCaps, tryApplyRoute, applyFallback } = ctx;
    if (apiCaps && apiCaps.apply && typeof tryApplyRoute === "function") {
      try {
        return await tryApplyRoute(groupKey, ownerAdmin);
      } catch (e) {
        if (isGroupRouteMissingError(e)) {
          apiCaps.apply = false;
          if (typeof saveApiCaps === "function") saveApiCaps(apiCaps);
          return await applyFallback(groupKey, ownerAdmin, payload);
        }
        throw e;
      }
    }
    return await applyFallback(groupKey, ownerAdmin, payload);
  }
  async function runGroupDeleteAction(ctx) {
    const { groupKey, ownerAdmin, apiCaps, saveApiCaps, tryDeletePostRoute, tryDeleteRoute, clearFallback } = ctx;
    if (apiCaps && apiCaps.delete === false) return await clearFallback(groupKey, ownerAdmin);
    try {
      return await tryDeletePostRoute(groupKey, ownerAdmin);
    } catch (e) {
      if (!isGroupRouteMissingError(e)) throw e;
      try {
        return await tryDeleteRoute(groupKey, ownerAdmin);
      } catch (e2) {
        if (isGroupRouteMissingError(e2)) {
          if (apiCaps) apiCaps.delete = false;
          if (typeof saveApiCaps === "function" && apiCaps) saveApiCaps(apiCaps);
          return await clearFallback(groupKey, ownerAdmin);
        }
        throw e2;
      }
    }
  }
  async function grantShareMatrix(deviceIds, usernames, perms, onProgress) {
    const dids = (Array.isArray(deviceIds) ? deviceIds : []).map((x) => String(x || "").trim()).filter(Boolean);
    const users = (Array.isArray(usernames) ? usernames : []).map((x) => String(x || "").trim()).filter(Boolean);
    const canView = !!(perms && perms.can_view);
    const canOperate = !!(perms && perms.can_operate);
    if (!dids.length) throw new Error("No devices selected");
    if (!users.length) throw new Error("No users selected");
    if (!canView && !canOperate) throw new Error("No sharing permission selected");
    const total = dids.length * users.length;
    let ok = 0;
    let fail = 0;
    let idx = 0;
    for (const did of dids) {
      for (const user of users) {
        idx += 1;
        try {
          await api(`/admin/devices/${encodeURIComponent(did)}/share`, {
            method: "POST",
            body: { grantee_username: user, can_view: canView, can_operate: canOperate }
          });
          ok += 1;
        } catch {
          fail += 1;
        }
        if (typeof onProgress === "function") onProgress({ idx, total, ok, fail, device_id: did, username: user });
      }
    }
    return { total, ok, fail };
  }
  var _apiGetCache = /* @__PURE__ */ new Map();
  var _apiGetInflight = /* @__PURE__ */ new Map();
  var _API_GET_CACHE_MAX_KEYS = 48;
  function _apiGetCacheSet(path, data) {
    const p = String(path || "");
    _apiGetCache.set(p, { t: Date.now(), data });
    while (_apiGetCache.size > _API_GET_CACHE_MAX_KEYS) {
      let oldestK = null;
      let oldestT = Infinity;
      for (const [k, v] of _apiGetCache.entries()) {
        if (v && v.t < oldestT) {
          oldestT = v.t;
          oldestK = k;
        }
      }
      if (oldestK != null) _apiGetCache.delete(oldestK);
      else break;
    }
  }
  async function apiGetCached(path, opts, ttlMs) {
    const ttl = ttlMs != null ? ttlMs : 4500;
    const ent = _apiGetCache.get(path);
    const now = Date.now();
    if (ent && now - ent.t < ttl) return ent.data;
    if (_apiGetInflight.has(path)) return _apiGetInflight.get(path);
    const p = (async () => {
      const data2 = await api(path, opts);
      _apiGetCacheSet(path, data2);
      return data2;
    })();
    _apiGetInflight.set(path, p);
    let data;
    try {
      data = await p;
    } finally {
      if (_apiGetInflight.get(path) === p) _apiGetInflight.delete(path);
    }
    return data;
  }
  function bustApiGetCachedPrefix(prefix) {
    const p = String(prefix || "");
    for (const k of _apiGetCache.keys()) {
      if (!p || k.startsWith(p)) _apiGetCache.delete(k);
    }
  }
  function bustDeviceListCaches() {
    bustApiGetCachedPrefix("/devices");
    bustApiGetCachedPrefix("/dashboard/overview");
    scheduleSyncGroupMetaFromServer();
  }
  function normalizeFwLabel(s) {
    return String(s == null ? "" : s).trim().toLowerCase().replace(/^v+/, "");
  }
  function firmwareHintStillValid(devFw, hint) {
    if (!hint || !hint.update_available) return false;
    const t = normalizeFwLabel(hint.to_version);
    const c = normalizeFwLabel(devFw);
    if (c && t && c === t) return false;
    return true;
  }
  var FW_HINT_DLG_VER = "4";
  async function openGlobalFwHintDialog(hint, ctx) {
    ctx = ctx || {};
    if (!hint || !hint.update_available) return;
    if (ctx.deviceId) {
      try {
        const row = await api(`/devices/${encodeURIComponent(ctx.deviceId)}`, { timeoutMs: 16e3 });
        if (row && row.fw != null) ctx = Object.assign({}, ctx, { currentFw: String(row.fw) });
        const h2 = row && row.firmware_hint;
        if (!h2 || !h2.update_available || !firmwareHintStillValid(row && row.fw, h2)) {
          toast("Firmware is up to date.", "ok");
          try {
            bustDeviceListCaches();
          } catch (_) {
          }
          return;
        }
        hint = h2;
      } catch (_) {
        if (!firmwareHintStillValid(ctx.currentFw, hint)) {
          toast("Firmware is up to date.", "ok");
          return;
        }
      }
    } else if (!firmwareHintStillValid(ctx.currentFw, hint)) {
      toast("Firmware is up to date.", "ok");
      return;
    }
    let dlg = document.getElementById("crocFwHintDialog");
    if (!dlg || dlg.dataset.crocFwDlgVer !== FW_HINT_DLG_VER) {
      if (dlg) dlg.remove();
      dlg = document.createElement("dialog");
      dlg.id = "crocFwHintDialog";
      dlg.dataset.crocFwDlgVer = FW_HINT_DLG_VER;
      dlg.className = "croc-fw-hint-dlg";
      dlg.setAttribute("aria-label", "Firmware update");
      dlg.innerHTML = `
      <div class="croc-fw-hint-dlg__form">
        <h3 class="croc-fw-hint-dlg__title">Firmware update</h3>
        <div class="croc-fw-hint-dlg__compare" id="crocFwHintCompare" aria-live="polite"></div>
        <p class="croc-fw-hint-dlg__release-label" id="crocFwHintRelLabel" style="display:none">Package notes (from .bin / sidecar)</p>
        <pre class="croc-fw-hint-dlg__release" id="crocFwHintRelease" style="display:none"></pre>
        <p class="croc-fw-hint-dlg__preflight muted" id="crocFwHintPreflight" style="margin:10px 0 0;min-height:1.2em"></p>
        <div class="row" style="justify-content:flex-end;margin-top:14px;gap:8px;flex-wrap:wrap">
          <button type="button" class="btn secondary btn-tap" id="crocFwHintClose">Close</button>
          <button type="button" class="btn btn-tap" id="crocFwHintDoOta" style="display:none">Send OTA</button>
        </div>
      </div>`;
      document.body.appendChild(dlg);
    }
    const curFw = String(ctx.currentFw != null ? ctx.currentFw : "").trim() || "\u2014";
    const newFw = String(hint.to_version || "\u2014").trim() || "\u2014";
    const toFile = String(hint.to_file || "").trim();
    const serverNotes = String(hint.release_notes || "").trim();
    const relEl = document.getElementById("crocFwHintRelease");
    const relLab = document.getElementById("crocFwHintRelLabel");
    if (relEl) {
      if (serverNotes) {
        relEl.textContent = serverNotes;
        relEl.style.display = "block";
      } else {
        relEl.textContent = "";
        relEl.style.display = "none";
      }
    }
    if (relLab) relLab.style.display = serverNotes ? "block" : "none";
    const cmp = document.getElementById("crocFwHintCompare");
    if (cmp) {
      cmp.innerHTML = `<span class="croc-fw-hint-dlg__ver mono" title="Current">${escapeHtml(curFw)}</span><span class="croc-fw-hint-dlg__ver-arrow" aria-hidden="true">\u2192</span><span class="croc-fw-hint-dlg__ver mono croc-fw-hint-dlg__ver--new" title="New">${escapeHtml(newFw)}</span>`;
    }
    const pre = document.getElementById("crocFwHintPreflight");
    if (pre) {
      if (!ctx.deviceId || !can("can_send_command")) {
        pre.textContent = "Open a device with command permission to send OTA in one step.";
      } else if (ctx.canOperateThisDevice === false) {
        pre.textContent = "No operate permission on this device \u2014 OTA disabled.";
      } else {
        pre.textContent = "Send OTA verifies your session, firmware URL (server probe with OTA token), and operate access.";
      }
    }
    const closeBtn = document.getElementById("crocFwHintClose");
    if (closeBtn) {
      closeBtn.onclick = () => {
        try {
          dlg.close();
        } catch (_) {
        }
      };
    }
    const did = String(ctx.deviceId || "").trim();
    const knownNoOperate = ctx.canOperateThisDevice === false;
    const otaBtn = document.getElementById("crocFwHintDoOta");
    if (otaBtn) {
      const show = !!(did && can("can_send_command") && !knownNoOperate);
      otaBtn.style.display = show ? "inline-flex" : "none";
      otaBtn.disabled = false;
      otaBtn.onclick = async () => {
        const url = String(hint.download_url || "").trim();
        const fw = String(hint.to_version || "").trim();
        if (!did || !url || !fw) {
          toast("Missing device or download information.", "err");
          return;
        }
        let fresh = null;
        try {
          fresh = await api(`/devices/${encodeURIComponent(did)}`, { timeoutMs: 16e3 });
        } catch (_) {
        }
        if (fresh) {
          const h3 = fresh.firmware_hint;
          if (!firmwareHintStillValid(fresh.fw, h3) || !h3 || !h3.update_available) {
            toast("Firmware is already up to date.", "ok");
            try {
              bustDeviceListCaches();
            } catch (_) {
            }
            try {
              dlg.close();
            } catch (_) {
            }
            return;
          }
        }
        if (!confirm(`Send OTA to this device?

${did}

${curFw} \u2192 ${fw}`)) return;
        otaBtn.disabled = true;
        if (pre) pre.textContent = "Checking\u2026";
        try {
          if (!state.me) {
            throw new Error("Not signed in or session expired");
          }
          let canOp = true;
          if (ctx.canOperateThisDevice !== true) {
            const row = await api(`/devices/${encodeURIComponent(did)}`, { timeoutMs: 2e4 });
            canOp = !!(row && row.can_operate);
          } else {
            canOp = true;
          }
          if (!canOp) {
            throw new Error("No operate permission on this device");
          }
          const probe = await api(`/ota/firmware-reachability?name=${encodeURIComponent(toFile)}`, { timeoutMs: 25e3 });
          if (!probe || !probe.ok) {
            const det = probe && probe.detail ? String(probe.detail) : "probe failed";
            throw new Error(`Firmware URL probe failed: ${det}`);
          }
          if (pre) pre.textContent = "Sending OTA command\u2026";
          await api(`/devices/${encodeURIComponent(did)}/commands`, {
            method: "POST",
            body: { cmd: "ota", params: { url, fw } }
          });
          toast("OTA command sent", "ok");
          try {
            bustDeviceListCaches();
          } catch (_) {
          }
          dlg.close();
        } catch (e) {
          const msg = e && e.message ? String(e.message) : String(e);
          if (pre) pre.textContent = msg;
          toast(msg, "err");
        } finally {
          otaBtn.disabled = false;
        }
      };
    }
    if (typeof dlg.showModal === "function") dlg.showModal();
  }
  function syncDevicePageFirmwareHint(view, dev, deviceIdForOta) {
    const hasUpd = !!(dev && dev.firmware_hint && dev.firmware_hint.update_available && firmwareHintStillValid(dev && dev.fw, dev.firmware_hint));
    const stEl = $("#devFwStatus", view);
    if (stEl) {
      stEl.textContent = hasUpd ? "Update available \xB7 \u6709\u66F4\u65B0" : "Up to date \xB7 \u5DF2\u662F\u6700\u65B0";
      stEl.className = hasUpd ? "device-fw-state device-fw-state--update" : "device-fw-state device-fw-state--ok";
    }
    const hBtn = $("#devFwHintBtn", view);
    if (hBtn) {
      if (hasUpd) {
        hBtn.style.display = "inline-flex";
        hBtn.setAttribute("aria-pressed", "true");
        const h = dev.firmware_hint;
        const did = String(deviceIdForOta || dev && dev.device_id || "");
        const operate = !!(dev && dev.can_operate);
        hBtn.onclick = () => openGlobalFwHintDialog(h, {
          currentFw: String(dev && dev.fw != null ? dev.fw : ""),
          deviceId: did,
          canOperateThisDevice: operate
        });
      } else {
        hBtn.style.display = "none";
        hBtn.removeAttribute("aria-pressed");
        hBtn.onclick = null;
      }
    }
    const vEl = $("#devFwVer", view);
    if (vEl) vEl.textContent = String(dev && dev.fw != null && dev.fw !== "" ? dev.fw : "\u2014");
  }
  async function login(username, password) {
    const r = await fetchWithDeadline(
      apiBase() + "/auth/login",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      },
      DEFAULT_API_TIMEOUT_MS
    );
    const text = await r.text();
    if (!r.ok) {
      if (r.status === 429) {
        const ra = r.headers.get("Retry-After");
        let detail = "Too many sign-in attempts. Please wait and try again.";
        try {
          const j2 = JSON.parse(text);
          if (j2 && j2.detail) detail = String(j2.detail);
        } catch {
          if (text) detail = text;
        }
        if (ra && /^\d+$/.test(ra)) detail = `${detail} (retry after ${ra}s)`;
        throw new Error(detail);
      }
      throw new Error(`${r.status} ${text}`);
    }
    const j = JSON.parse(text);
    if (j.access_token) setToken(j.access_token);
    else setToken("");
    if (j.csrf_token) setCsrfToken(String(j.csrf_token));
    else setCsrfToken(_readCsrfCookie());
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
    if (state.me) {
      const ck = _readCsrfCookie();
      if (ck) setCsrfToken(ck);
      if (!getCsrfToken()) {
        try {
          await refreshCsrfToken();
        } catch (_) {
        }
      }
    } else {
      setCsrfToken("");
    }
    renderAuthState();
  }
  async function loadHealth() {
    try {
      const r = await fetchWithDeadline(apiBase() + "/health", { method: "GET" }, 12e3);
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
    armHealthPoll();
  }
  function renderAuthState() {
    if (!state.me) clearHealthPollTimer();
    document.body.dataset.auth = state.me ? "ok" : "none";
    const who = $("#who");
    if (state.me) {
      const u = String(state.me.username || "").trim() || "\u2014";
      const role = String(state.me.role || "").trim() || "\u2014";
      const zt = (state.me.zones || []).map((z) => String(z)).filter(Boolean).join(", ") || "\u2014";
      const initial = (u[0] || "?").toUpperCase();
      const av = String(state.me.avatar_url || "").trim();
      const avatarEl = av ? `<div class="who-card__avatar who-card__avatar--photo" aria-hidden="true"><img src="${escapeHtml(av)}" alt="" width="40" height="40" loading="lazy" decoding="async" referrerpolicy="no-referrer" /></div>` : `<div class="who-card__avatar" aria-hidden="true">${escapeHtml(initial)}</div>`;
      setChildMarkup(
        who,
        `<div class="who-card" title="${escapeHtml(u)}">` + avatarEl + `<div class="who-card__body"><div class="who-card__name">${escapeHtml(u)}</div><div class="who-card__meta"><span class="who-card__role">${escapeHtml(role)}</span><span class="who-card__zones" title="${escapeHtml(zt)}">${escapeHtml(zt)}</span></div></div></div>`
      );
      const im = who && who.querySelector(".who-card__avatar--photo img");
      if (im) {
        im.addEventListener(
          "error",
          function onAvErr() {
            im.removeEventListener("error", onAvErr);
            const w = im.closest(".who-card__avatar");
            if (w) {
              w.classList.remove("who-card__avatar--photo");
              w.textContent = initial;
            }
          },
          { once: true }
        );
      }
      if (who) {
        who.className = "who who--authed";
        who.setAttribute("role", "group");
        who.setAttribute("aria-label", "Account");
      }
    } else {
      if (who) {
        who.className = "who who--guest";
        who.textContent = "Signed out";
        who.removeAttribute("role");
        who.removeAttribute("aria-label");
        who.removeAttribute("title");
      }
    }
    renderNav();
    renderHealthPills();
    try {
      applySidebarRail();
    } catch (_) {
    }
  }
  function renderNav() {
    const nav = $("#nav");
    if (!nav) return;
    if (!state.me) {
      setHtmlIfChanged(nav, "");
      return;
    }
    const hash = location.hash || "#/overview";
    const hashNoQuery = hash.split("?")[0];
    const coreParts = [];
    for (const g of NAV_GROUPS) {
      const items = g.items.filter((n) => hasRole(n.min));
      if (items.length === 0) continue;
      coreParts.push(`<div class="nav-section">${escapeHtml(g.title)}</div>`);
      for (const n of items) {
        const active = (n.path === "#/devices" ? hashNoQuery === "#/devices" || hashNoQuery.startsWith("#/devices/") : n.path === "#/site" ? hashNoQuery === "#/site" : hash.startsWith(n.path)) ? ` aria-current="page"` : "";
        coreParts.push(
          `<a href="${n.path}"${active} title="${escapeHtml(n.label)}"><span class="nav-ico" aria-hidden="true">${n.ico}</span><span class="nav-label">${escapeHtml(n.label)}</span></a>`
        );
      }
    }
    setHtmlIfChanged(nav, `<div class="nav-core">${coreParts.join("")}</div>`);
  }
  function renderHealthPills() {
    const el = $("#healthPills");
    if (!el) return;
    if (!state.me || !state.health) {
      setHtmlIfChanged(el, "");
      return;
    }
    const sm = state.health.smtp || {};
    const tg = state.health.telegram || {};
    const mailOk = !!sm.configured && !!sm.worker_running;
    const tgOn = !!tg.enabled;
    const tgOk = tgOn && !!tg.worker_running;
    const tgErr = String(tg.last_error || "").trim();
    const mqConn = !!state.health.mqtt_connected;
    const mqQ = Number(state.health.mqtt_ingest_queue_depth || 0);
    const mqDrop = Number(state.health.mqtt_ingest_dropped || 0);
    const mqLastUp = String(state.health.mqtt_last_connect_at || "");
    const mqLastDown = String(state.health.mqtt_last_disconnect_at || "");
    const mqLastReason = String(state.health.mqtt_last_disconnect_reason || "");
    const mailTitle = sm.configured ? mailOk ? "Mail worker running \u2014 verification email can be sent" : "Mail channel configured but worker not running \u2014 check API logs" : "Mail channel not configured on server";
    const tgTitle = tgOn ? tgOk ? tgErr ? `Telegram worker up \u2014 last API error: ${tgErr}` : "Telegram worker running \u2014 events at min_level+ are queued" : "Telegram enabled but worker not running \u2014 check API logs" : "Telegram disabled \u2014 set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS (numeric chat id; start a chat with the bot first)";
    const mqttTitle = mqConn ? mqDrop > 0 ? `MQTT connected, but ingest dropped ${mqDrop} message(s); queue depth=${mqQ}. last_up=${mqLastUp ? fmtTs(mqLastUp) : "\u2014"}` : `MQTT connected; ingest queue depth=${mqQ}. last_up=${mqLastUp ? fmtTs(mqLastUp) : "\u2014"}` : `MQTT disconnected \u2014 check broker/TLS/network. last_down=${mqLastDown ? fmtTs(mqLastDown) : "\u2014"} reason=${mqLastReason || "\u2014"}`;
    setHtmlIfChanged(el, `
    <span class="health-pill ${mqConn ? mqDrop > 0 ? "warn" : "ok" : "off"}" title="${escapeHtml(mqttTitle)}">MQTT</span>
    <span class="health-pill ${mailOk ? "ok" : sm.configured ? "warn" : "off"}" title="${escapeHtml(mailTitle)}">MAIL</span>
    <span class="health-pill ${tgOk ? "ok" : tgOn ? "warn" : "off"}" title="${escapeHtml(tgTitle)}">TG</span>`);
  }
  function renderMqttDot() {
    const dot = $("#mqttDot");
    if (!dot) return;
    dot.className = "dot-status " + (state.mqttConnected ? "ok" : "bad");
    dot.title = state.mqttConnected ? "MQTT up" : "MQTT down";
  }
  function setCrumb(text) {
    const el = $("#crumb");
    if (el) el.textContent = text;
  }
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
  function applySidebarRail() {
    const m = window.matchMedia && window.matchMedia("(min-width: 901px)");
    if (!m || !m.matches) {
      try {
        document.body.removeAttribute("data-sidebar");
      } catch (_) {
      }
    } else {
      try {
        const c = localStorage.getItem(LS.sidebarCollapsed) === "1";
        if (c) document.body.setAttribute("data-sidebar", "collapsed");
        else document.body.removeAttribute("data-sidebar");
      } catch (_) {
        try {
          document.body.removeAttribute("data-sidebar");
        } catch (_2) {
        }
      }
    }
    const btn = document.getElementById("sidebarRailToggle");
    if (btn) {
      const isCol = document.body.getAttribute("data-sidebar") === "collapsed";
      btn.setAttribute("aria-label", isCol ? "Expand sidebar" : "Collapse sidebar");
      btn.setAttribute("aria-expanded", isCol ? "false" : "true");
      btn.setAttribute("title", isCol ? "Expand sidebar" : "Collapse sidebar");
      const svgL = '<svg class="sidebar-rail-toggle__icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>';
      const svgR = '<svg class="sidebar-rail-toggle__icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>';
      btn.innerHTML = isCol ? svgR : svgL;
    }
  }
  function toggleSidebarRail() {
    if (!window.matchMedia("(min-width: 901px)").matches) return;
    const cur = localStorage.getItem(LS.sidebarCollapsed) === "1";
    try {
      localStorage.setItem(LS.sidebarCollapsed, cur ? "0" : "1");
    } catch (_) {
    }
    applySidebarRail();
  }
  function syncNavForViewport() {
    try {
      if (window.matchMedia && window.matchMedia("(min-width: 901px)").matches) {
        document.body.dataset.nav = "";
      }
    } catch (_) {
    }
    try {
      applySidebarRail();
    } catch (_) {
    }
  }
  var routes = {};
  function registerRoute(id, handler) {
    routes[id] = handler;
  }
  function isRouteCurrent(seq) {
    return seq === state.routeSeq;
  }
  function clearRouteTickers() {
    const ticks = window.__routeTickers;
    if (!ticks) return;
    for (const t of ticks.values()) {
      try {
        clearTimeout(t);
      } catch (_) {
      }
    }
    ticks.clear();
  }
  function scheduleRouteTicker(routeSeq, key, fn, intervalMs) {
    window.__routeTickers = window.__routeTickers || /* @__PURE__ */ new Map();
    const ticks = window.__routeTickers;
    const k = String(key || "");
    let running = false;
    const run = async () => {
      if (!isRouteCurrent(routeSeq)) return;
      if (document.visibilityState !== "visible") {
        const tid2 = setTimeout(run, intervalMs);
        ticks.set(k, tid2);
        return;
      }
      if (running) {
        const tid2 = setTimeout(run, intervalMs);
        ticks.set(k, tid2);
        return;
      }
      running = true;
      try {
        await fn();
      } catch (_) {
      }
      running = false;
      if (!isRouteCurrent(routeSeq)) return;
      const tid = setTimeout(run, intervalMs);
      ticks.set(k, tid);
    };
    const old = ticks.get(k);
    if (old) {
      try {
        clearTimeout(old);
      } catch (_) {
      }
    }
    const first = setTimeout(run, intervalMs);
    ticks.set(k, first);
  }
  async function renderRoute() {
    const view = $("#view");
    if (!view) return;
    let hashFull = location.hash || "#/overview";
    let routeQuery = new URLSearchParams("");
    const qm = hashFull.indexOf("?");
    if (qm >= 0) {
      try {
        routeQuery = new URLSearchParams(hashFull.slice(qm + 1));
      } catch (_2) {
      }
      hashFull = hashFull.slice(0, qm);
    }
    window.__routeQuery = routeQuery;
    const [_, rawId, ...rest] = hashFull.split("/");
    const id = rawId || "overview";
    const args = rest;
    const routeSeq = ++state.routeSeq;
    clearRouteRedirectTimer();
    if (overviewFilterDebounce) {
      clearTimeout(overviewFilterDebounce);
      overviewFilterDebounce = null;
    }
    if (window.__pendingEvListRaf) {
      try {
        cancelAnimationFrame(window.__pendingEvListRaf);
      } catch (_2) {
      }
      window.__pendingEvListRaf = 0;
    }
    clearRouteTickers();
    if (window.__fpCooldownTimer) {
      try {
        clearInterval(window.__fpCooldownTimer);
      } catch (_2) {
      }
      window.__fpCooldownTimer = 0;
    }
    if (window.__evReconnectTimer) {
      try {
        clearTimeout(window.__evReconnectTimer);
      } catch (_2) {
      }
      window.__evReconnectTimer = 0;
    }
    if (window.__evFetchAbort) {
      try {
        window.__evFetchAbort.abort();
      } catch (_2) {
      }
      window.__evFetchAbort = null;
    }
    window.__eventsStreamResume = null;
    toggleNav(false);
    if (window.__evSSE) {
      try {
        window.__evSSE.close();
      } catch {
      }
      window.__evSSE = null;
    }
    const publicRoutes = PUBLIC_ROUTE_IDS;
    if (!state.me && !publicRoutes.has(id)) {
      location.hash = "#/login";
      return;
    }
    if (state.me && publicRoutes.has(id)) {
      location.hash = "#/overview";
      return;
    }
    const aliasHash = "#/" + id;
    const routeId = ROUTE_ALIASES[aliasHash] || id;
    document.body.dataset.layout = publicRoutes.has(routeId) ? "auth" : "app";
    try {
      applySidebarRail();
    } catch (_2) {
    }
    const handler = routes[routeId] || routes["overview"];
    try {
      mountView(view, `<div class="route-loading card" aria-busy="true" role="status">
      <span class="sr-only">Loading page</span>
      <div class="route-loading__head"></div>
      <div class="route-loading__lines">
        <span class="route-loading__bar route-loading__bar--90"></span>
        <span class="route-loading__bar route-loading__bar--72"></span>
        <span class="route-loading__bar route-loading__bar--84"></span>
      </div>
    </div>`);
      const swap = async () => {
        await handler(view, args, routeSeq);
      };
      await Promise.race([
        swap(),
        new Promise((_2, reject) => {
          setTimeout(() => reject(new Error("Page render timed out. Please retry.")), ROUTE_RENDER_TIMEOUT_MS);
        })
      ]);
      renderNav();
      renderHealthPills();
    } catch (e) {
      mountView(view, hx`<div class="card"><h2>Load failed</h2><p class="muted">${e.message || e}</p></div>`);
    }
  }
  window.addEventListener("hashchange", renderRoute);
  registerRoute("account-activate", async (view) => {
    setCrumb("Activate account");
    document.body.dataset.auth = "none";
    mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("activate")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner">
      <div class="auth-card auth-card--panel auth-card--wide" data-auth-card>
        <header class="auth-card__head">
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
      ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
    const msg = $("#a_msg");
    $("#a_submit").addEventListener("click", async () => {
      const body = {
        username: $("#a_user").value.trim(),
        email_code: $("#a_email_code").value.trim()
      };
      msg.textContent = "";
      try {
        const r = await fetch(apiBase() + "/auth/activate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        setChildMarkup(msg, `<span class="badge online">Activated</span> Redirecting to sign in\u2026`);
        scheduleRouteRedirect(1500, "#/login");
      } catch (e) {
        msg.textContent = String(e.message || e);
      }
    });
    $("#a_resend").addEventListener("click", async () => {
      msg.textContent = "";
      const username = $("#a_user").value.trim();
      if (!username) {
        msg.textContent = "Enter username first";
        return;
      }
      try {
        const r = await fetch(apiBase() + "/auth/code/resend", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, channel: "email", purpose: "activate" })
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        msg.textContent = "Resend requested \u2014 check inbox and spam.";
      } catch (e) {
        msg.textContent = String(e.message || e);
      }
    });
  });
  registerRoute("account", async (view) => {
    setCrumb("Account");
    if (!hasRole("user")) {
      mountView(view, `<div class="card"><p class="muted">Sign in required.</p></div>`);
      return;
    }
    const me = state.me || { username: "", role: "" };
    const avStored = String(me.avatar_url || "").trim();
    const uname0 = (String(me.username || "?").trim() || "?")[0].toUpperCase();
    const roleNorm = String(me.role || "").trim().toLowerCase();
    const deleteSection = (() => {
      if (roleNorm === "superadmin") {
        return `
    <div class="card">
      <h3>Delete account</h3>
      <p class="muted">Superadmin accounts cannot be removed through this console (API blocks self-deletion).</p>
    </div>`;
      }
      if (roleNorm === "admin") {
        return `
    <details class="card danger-zone">
      <summary style="cursor:pointer;font-weight:700">Danger zone \xB7 Close tenant</summary>
      <div style="margin-top:10px">
      <h3>Close tenant account</h3>
      <p class="muted" style="margin:0 0 10px">If you close this admin tenant:</p>
      <ul class="muted" style="margin:0 0 12px;padding-left:1.25em;line-height:1.55">
        <li><strong>Devices</strong> you own are <strong>factory-unclaimed</strong> (dashboard records removed; devices return to unregistered / reclaimable state).</li>
        <li><strong>Subordinate users</strong> created under your account are <strong>deleted</strong>.</li>
        <li>Your <strong>username</strong> and <strong>email</strong> become available for new registration.</li>
      </ul>
      <label class="checkbox" style="margin-bottom:12px;display:flex;gap:8px;align-items:flex-start">
        <input id="accAckTenant" type="checkbox" />
        <span>I understand all devices under this tenant will be released and sub-users removed.</span>
      </label>
      <p class="muted">Type <span class="mono">DELETE</span> and your password to confirm.</p>
      <label class="field"><span>Current password</span><input id="accDelPw" type="password" autocomplete="current-password"/></label>
      <label class="field field--spaced"><span>Type DELETE</span><input id="accDelText" placeholder="DELETE"/></label>
      <div class="row" style="justify-content:flex-end;margin-top:10px">
        <button class="btn danger" id="accDeleteSelf">Close tenant permanently</button>
      </div>
      </div>
    </details>`;
      }
      return `
    <details class="card danger-zone">
      <summary style="cursor:pointer;font-weight:700">Danger zone \xB7 Delete account</summary>
      <div style="margin-top:10px">
      <h3>Delete account</h3>
      <p class="muted">This action is irreversible. Type <span class="mono">DELETE</span> and confirm your password.</p>
      <label class="field"><span>Current password</span><input id="accDelPw" type="password" autocomplete="current-password"/></label>
      <label class="field field--spaced"><span>Type DELETE</span><input id="accDelText" placeholder="DELETE"/></label>
      <div class="row" style="justify-content:flex-end;margin-top:10px">
        <button class="btn danger" id="accDeleteSelf">Delete my account</button>
      </div>
      </div>
    </details>`;
    })();
    const previewInner = avStored ? `<img src="${escapeHtml(avStored)}" alt="" width="48" height="48" loading="lazy" decoding="async" referrerpolicy="no-referrer" />` : `<span class="account-avatar-fallback" aria-hidden="true">${escapeHtml(uname0)}</span>`;
    mountView(view, `
    <div class="card">
      <h2>My account</h2>
      <p class="muted">User: <span class="mono">${escapeHtml(me.username)}</span> \xB7 Role: <span class="mono">${escapeHtml(me.role)}</span></p>
    </div>
    <div class="card">
      <h3>Profile picture</h3>
      <p class="muted" style="margin:0 0 10px">Use an <strong>https</strong> image link you control (square works best). Shown in the left sidebar. If the image cannot load, your initial is used.</p>
      <div class="row" style="align-items:flex-end;flex-wrap:wrap;gap:12px">
        <label class="field" style="flex:1;min-width:200px;max-width:100%"><span>Image URL</span>
          <input id="accAvatarUrl" type="url" inputmode="url" placeholder="https://\u2026" value="${escapeHtml(avStored)}" autocomplete="off" />
        </label>
        <div class="account-avatar-preview" id="accAvatarPreview" aria-hidden="true">${previewInner}</div>
      </div>
      <div class="row" style="justify-content:flex-end;margin-top:10px;gap:8px;flex-wrap:wrap">
        <button class="btn secondary" type="button" id="accAvatarClear">Use initial only</button>
        <button class="btn" type="button" id="accAvatarSave">Save</button>
      </div>
    </div>
    <div class="card">
      <h3>Change password</h3>
      <label class="field"><span>Current password</span><input id="acc_old" type="password" autocomplete="current-password"/></label>
      <label class="field field--spaced"><span>New password</span><input id="acc_new1" type="password" autocomplete="new-password"/></label>
      <label class="field field--spaced"><span>Confirm new password</span><input id="acc_new2" type="password" autocomplete="new-password"/></label>
      <div class="row" style="justify-content:flex-end;margin-top:10px">
        <button class="btn" id="accChangePw">Update password</button>
      </div>
    </div>
    ${deleteSection}
  `);
    const accPre = $("#accAvatarPreview", view);
    const accUrl = $("#accAvatarUrl", view);
    const setAccPreview = () => {
      if (!accPre) return;
      const v = (accUrl && accUrl.value ? accUrl.value : "").trim();
      if (!v) {
        setChildMarkup(accPre, `<span class="account-avatar-fallback" aria-hidden="true">${escapeHtml(uname0)}</span>`);
        return;
      }
      setChildMarkup(
        accPre,
        `<img src="${escapeHtml(v)}" alt="" width="48" height="48" loading="lazy" decoding="async" referrerpolicy="no-referrer" />`
      );
      const g = accPre.querySelector("img");
      if (g) {
        g.addEventListener(
          "error",
          () => {
            setChildMarkup(
              accPre,
              `<span class="account-avatar-fallback account-avatar-fallback--err" title="Image failed to load" aria-hidden="true">${escapeHtml(uname0)}</span>`
            );
          },
          { once: true }
        );
      }
    };
    if (accUrl) {
      accUrl.addEventListener("input", () => setAccPreview());
      accUrl.addEventListener("change", () => setAccPreview());
    }
    $("#accAvatarClear", view).addEventListener("click", () => {
      if (accUrl) accUrl.value = "";
      setAccPreview();
    });
    $("#accAvatarSave", view).addEventListener("click", async () => {
      const v = (accUrl && accUrl.value ? accUrl.value : "").trim();
      try {
        const r = await api("/auth/me/profile", { method: "PATCH", body: { avatar_url: v } });
        if (state.me) state.me.avatar_url = r && r.avatar_url != null ? r.avatar_url : v;
        renderAuthState();
        toast(v ? "Profile picture saved" : "Using initial letter", "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    const accChangePwBtn = $("#accChangePw", view);
    if (accChangePwBtn) {
      accChangePwBtn.addEventListener("click", async () => {
        try {
          await api("/auth/me/password", {
            method: "PATCH",
            body: {
              current_password: $("#acc_old", view).value || "",
              new_password: $("#acc_new1", view).value || "",
              new_password_confirm: $("#acc_new2", view).value || ""
            }
          });
          toast("Password updated \u2014 please sign in again.", "ok");
          setToken("");
          state.me = null;
          clearHealthPollTimer();
          renderAuthState();
          location.hash = "#/login";
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
    const accDeleteSelfBtn = $("#accDeleteSelf", view);
    if (accDeleteSelfBtn) {
      accDeleteSelfBtn.addEventListener("click", async () => {
        if (roleNorm === "superadmin") return;
        const msg = roleNorm === "admin" ? "Close this admin tenant permanently? All owned devices will be factory-unclaimed and sub-users deleted." : "Delete your account permanently?";
        if (!confirm(msg)) return;
        if (roleNorm === "admin") {
          const ack = $("#accAckTenant", view);
          if (!ack || !ack.checked) {
            toast("Confirm the checklist: devices will be released and sub-users removed.", "err");
            return;
          }
        }
        try {
          const body = {
            password: $("#accDelPw", view).value || "",
            confirm_text: ($("#accDelText", view).value || "").trim(),
            acknowledge_admin_tenant_closure: roleNorm === "admin"
          };
          await api("/auth/me/delete", { method: "POST", body });
          toast(roleNorm === "admin" ? "Tenant closed" : "Account deleted", "ok");
          setToken("");
          state.me = null;
          clearHealthPollTimer();
          location.hash = "#/login";
          renderAuthState();
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
  });
  registerRoute("activate", async (view) => {
    setCrumb("Activate device");
    if (!hasRole("admin")) {
      mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`);
      return;
    }
    const canClaim = can("can_claim_device");
    mountView(view, `
    <div class="activate-shell">
      <section class="card activate-hero">
        <p class="activate-kicker">Field \xB7 Claim</p>
        <h2 class="activate-title">Claim device</h2>
        <p class="muted activate-lead">
          A serial appears as <strong>claimable</strong> only after the unit is <strong>powered and has contacted the server</strong>. Optionally save a <strong>target Wi\u2011Fi</strong> here (stored in this browser only); after claim we pre-fill the device page Wi\u2011Fi form for MQTT provisioning when online.
        </p>
        <ol class="activate-steps">
          <li><span class="n">1</span>Optional: save target Wi\u2011Fi (recommended)</li>
          <li><span class="n">2</span>Enter sticker serial or paste full <span class="mono">CROC|\u2026</span></li>
          <li><span class="n">3</span>Identify \u2192 if claimable, confirm and complete claim</li>
        </ol>
        ${canClaim ? "" : `<p class="badge revoked" style="margin-top:12px">Your account lacks <span class="mono">can_claim_device</span>; ask an administrator.</p>`}
      </section>

      <section class="card activate-main">
        <div class="activate-wifi-row">
          <button type="button" class="btn secondary btn-tap" style="width:100%" id="activateWifiOpenBtn">\u2460 Target Wi\u2011Fi (SSID / password)</button>
          <p class="muted activate-wifi-status" id="activateWifiStatus"></p>
        </div>
        <div class="inline-form activate-serial-block">
          <label class="field wide"><span>\u2461 Serial or full QR line (CROC|\u2026)</span>
            <input id="idn_input" class="activate-serial-input" placeholder="SN-\u2026 or paste full CROC|\u2026 line" autocomplete="off"/>
          </label>
          <div class="row wide activate-actions">
            <button class="btn btn-tap activate-id-btn" id="idn_go" ${canClaim ? "" : "disabled"}>\u2462 Identify</button>
          </div>
        </div>
        <div id="idnResult" class="activate-result"></div>
      </section>

      <dialog id="activateWifiDialog" class="activate-wifi-dlg">
        <form class="activate-wifi-dlg__inner" onsubmit="return false">
          <h3 class="activate-wifi-dlg__title">Target Wi\u2011Fi</h3>
          <p class="muted activate-wifi-dlg__lead">
            If the device has <strong>never been online</strong>, the server cannot push Wi\u2011Fi to it directly. SSID/password here are saved only in <strong>this browser</strong>; after claim, paste them into the device page for MQTT delivery. Leave password empty on open networks.
          </p>
          <label class="field wide"><span>SSID</span>
            <input type="text" id="activateDlgSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz network name" />
          </label>
          <label class="field wide"><span>Password</span>
            <input type="password" id="activateDlgPass" maxlength="64" autocomplete="new-password" placeholder="Empty if open network" />
          </label>
          <label class="field" style="margin-bottom:0"><span></span>
            <span><input type="checkbox" id="activateDlgShowPass" /> Show password</span>
          </label>
          <div class="activate-wifi-dlg__actions">
            <button type="button" class="btn ghost" id="activateWifiDlgClose">Close</button>
            <button type="button" class="btn" id="activateWifiDlgSave">Save to this browser</button>
            <button type="button" class="btn secondary" id="activateWifiDlgClear">Clear draft</button>
          </div>
        </form>
      </dialog>

      <section class="card activate-pending-card">
        <div class="row between" style="flex-wrap:wrap;gap:8px;align-items:center">
          <h3 style="margin:0">Recently reported (pending claim)</h3>
          <span class="muted" style="font-size:13px">MQTT <span class="mono">bootstrap.register</span></span>
          <button class="btn secondary btn-tap" id="reload">Refresh</button>
        </div>
        <div class="divider"></div>
        <div id="pendList"></div>
      </section>
    </div>`);
    const ACTIVATE_WIFI_STORE = "croc.activateWifiDraft.v1";
    const DEVICE_WIFI_PREFILL_KEY = "croc.deviceWifiPrefill.v1";
    const readWifiDraft = () => {
      try {
        const raw = sessionStorage.getItem(ACTIVATE_WIFI_STORE);
        const o = raw ? JSON.parse(raw) : null;
        if (o && typeof o.ssid === "string" && o.ssid.trim()) {
          return { ssid: o.ssid.trim(), password: typeof o.password === "string" ? o.password : "" };
        }
      } catch (_) {
      }
      return null;
    };
    const refreshWifiBanner = () => {
      const el = $("#activateWifiStatus", view);
      const d = readWifiDraft();
      if (!el) return;
      el.textContent = d ? `Saved target Wi\u2011Fi \u201C${d.ssid}\u201D. After claim we open the device page with Wi\u2011Fi (device) prefilled (requires device online to push).` : "Optionally save the Wi\u2011Fi you plan to use (this browser only), or skip and fill it later on the device page.";
    };
    const dlgWifi = $("#activateWifiDialog", view);
    const openActivateWifiDialog = () => {
      const d = readWifiDraft();
      const s = $("#activateDlgSsid", view);
      const p = $("#activateDlgPass", view);
      if (s) s.value = d ? d.ssid : "";
      if (p) p.value = d ? d.password : "";
      if (dlgWifi && typeof dlgWifi.showModal === "function") dlgWifi.showModal();
    };
    const closeActivateWifiDialog = () => {
      if (dlgWifi && typeof dlgWifi.close === "function") dlgWifi.close();
    };
    const wifiOpenBtn = $("#activateWifiOpenBtn", view);
    if (wifiOpenBtn) wifiOpenBtn.addEventListener("click", openActivateWifiDialog);
    const wifiSaveBtn = $("#activateWifiDlgSave", view);
    if (wifiSaveBtn) {
      wifiSaveBtn.addEventListener("click", () => {
        const ssid = ($("#activateDlgSsid", view).value || "").trim();
        const password = $("#activateDlgPass", view).value || "";
        if (!ssid) {
          toast("Enter Wi\u2011Fi name (SSID)", "err");
          return;
        }
        sessionStorage.setItem(ACTIVATE_WIFI_STORE, JSON.stringify({ ssid, password }));
        refreshWifiBanner();
        closeActivateWifiDialog();
        toast("Saved (this browser only)", "ok");
      });
    }
    const wifiClrDlg = $("#activateWifiDlgClear", view);
    if (wifiClrDlg) {
      wifiClrDlg.addEventListener("click", () => {
        sessionStorage.removeItem(ACTIVATE_WIFI_STORE);
        refreshWifiBanner();
        closeActivateWifiDialog();
        toast("Wi\u2011Fi draft cleared", "ok");
      });
    }
    const wifiClsDlg = $("#activateWifiDlgClose", view);
    if (wifiClsDlg) wifiClsDlg.addEventListener("click", closeActivateWifiDialog);
    const showPassEl = $("#activateDlgShowPass", view);
    if (showPassEl) {
      showPassEl.addEventListener("change", () => {
        const p = $("#activateDlgPass", view);
        if (p) p.type = showPassEl.checked ? "text" : "password";
      });
    }
    refreshWifiBanner();
    const resultBox = $("#idnResult");
    const drawBadge = (kind, label) => `<span class="badge ${kind === "ok" ? "online" : kind === "err" ? "offline" : ""}">${escapeHtml(label)}</span>`;
    const showClaimForm = (serial, mac, qr) => {
      const draft = readWifiDraft();
      const draftNote = draft ? `<p class="muted" style="margin:0 0 12px">Saved target Wi\u2011Fi <span class="mono">${escapeHtml(draft.ssid)}</span> \u2014 after claim we jump to the device page with Wi\u2011Fi (device) prefilled.</p>` : "";
      appendChildMarkup(
        resultBox,
        `
      <div class="card" style="margin-top:10px">
        <h4 style="margin-top:0">Confirm claim</h4>
        ${draftNote}
        <div class="inline-form">
          <label class="field"><span>device_id (usually serial)</span><input id="c_id" value="${escapeHtml(serial)}"/></label>
          <label class="field"><span>mac_nocolon</span><input id="c_mac" value="${escapeHtml(mac)}"/></label>
          <label class="field"><span>zone</span><input id="c_zone" value="all"/></label>
          <label class="field wide"><span>qr_code (optional)</span><input id="c_qr" value="${escapeHtml(qr || "")}"/></label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn btn-tap" id="c_submit">Confirm claim</button>
          </div>
        </div>
      </div>`
      );
      $("#c_submit").addEventListener("click", async () => {
        const body = {
          mac_nocolon: ($("#c_mac").value || "").trim().toUpperCase(),
          device_id: ($("#c_id").value || "").trim().toUpperCase(),
          zone: ($("#c_zone").value || "all").trim()
        };
        const q = ($("#c_qr").value || "").trim();
        if (q) body.qr_code = q;
        const preWifi = readWifiDraft();
        try {
          await api("/provision/claim", { method: "POST", body });
          const did = String(body.device_id || "").toUpperCase();
          if (preWifi && preWifi.ssid) {
            sessionStorage.setItem(
              DEVICE_WIFI_PREFILL_KEY,
              JSON.stringify({ device_id: did, ssid: preWifi.ssid, password: preWifi.password || "" })
            );
          }
          sessionStorage.removeItem(ACTIVATE_WIFI_STORE);
          refreshWifiBanner();
          toast("Claim completed", "ok");
          location.hash = `#/devices/${encodeURIComponent(did)}`;
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    };
    $("#idn_go").addEventListener("click", async () => {
      setChildMarkup(resultBox, `<p class="muted">Identifying\u2026</p>`);
      const raw = ($("#idn_input").value || "").trim();
      if (!raw) {
        setChildMarkup(resultBox, `<p class="muted">Enter serial or QR payload</p>`);
        return;
      }
      const body = raw.startsWith("CROC|") ? { qr_code: raw } : { serial: raw.toUpperCase() };
      try {
        const r = await api("/provision/identify", { method: "POST", body });
        const kv = (k, v) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(v)}</dd>`;
        switch (r.status) {
          case "ready":
            setChildMarkup(
              resultBox,
              `${drawBadge("ok", "Ready to claim")}
            <dl class="kv">${kv("Serial", r.serial)}${kv("MAC", r.mac_nocolon)}${kv("Firmware", r.fw || "\u2014")}${kv("Last seen", r.last_seen_at ? fmtTs(r.last_seen_at) : "\u2014")}</dl>
            <p>${escapeHtml(r.message)}</p>`
            );
            showClaimForm(r.serial, r.mac_nocolon, raw.startsWith("CROC|") ? raw : "");
            break;
          case "already_registered":
            const canSeeOwner = !!(state.me && state.me.role === "superadmin");
            const ownerKv = canSeeOwner ? kv("Owner admin", r.owner_admin || "\u2014") : "";
            const byYou = !!r.by_you;
            setChildMarkup(
              resultBox,
              `${drawBadge("err", byYou ? "Already yours" : "Already registered")}
            <dl class="kv">${kv("Serial", r.serial)}${kv("device_id", r.device_id)}${ownerKv}${kv("Claimed at", r.claimed_at ? fmtTs(r.claimed_at) : "\u2014")}</dl>
            <p class="muted">${escapeHtml(r.message)}</p>
            ${byYou ? `<a class="btn secondary" href="#/devices/${encodeURIComponent(r.device_id)}">Open device</a>` : ""}`
            );
            break;
          case "offline": {
            const dw = readWifiDraft();
            const draftNote = dw ? `<p class="muted" style="margin-top:10px">Saved Wi\u2011Fi on this machine: <strong>${escapeHtml(dw.ssid)}</strong>. After the unit is online and claimed, push credentials from the device page.</p>` : "";
            setChildMarkup(
              resultBox,
              `${drawBadge("", "Waiting for device")}
            <dl class="kv">${kv("Serial", r.serial)}${r.mac_hint ? kv("Factory MAC", r.mac_hint) : ""}</dl>
            <p>${escapeHtml(r.message)}</p>
            ${draftNote}
            <div class="activate-offline-actions">
              <button type="button" class="btn secondary btn-tap" id="activateOfflineWifiBtn">Edit target Wi\u2011Fi</button>
              <button type="button" class="btn btn-tap" id="idn_retry_offline">Powered & online \u2014 retry identify</button>
            </div>`
            );
            break;
          }
          case "blocked":
            setChildMarkup(resultBox, `${drawBadge("err", "Factory blocked")}<p>${escapeHtml(r.message)}</p>`);
            break;
          case "unknown_serial":
            setChildMarkup(resultBox, `${drawBadge("err", "Unknown serial")}<p>${escapeHtml(r.message)}</p>`);
            break;
          default:
            setChildMarkup(resultBox, `<p class="muted">Unknown status: ${escapeHtml(r.status)}</p>`);
        }
      } catch (e) {
        setChildMarkup(resultBox, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    });
    view.addEventListener("click", (ev) => {
      if (ev.target.closest("#activateOfflineWifiBtn")) {
        openActivateWifiDialog();
        return;
      }
      if (ev.target.closest("#idn_retry_offline")) {
        const go = $("#idn_go", view);
        if (go) go.click();
      }
    });
    $("#reload").addEventListener("click", () => renderRoute());
    try {
      const rq = window.__routeQuery || new URLSearchParams("");
      const pre = (rq.get("q") || rq.get("serial") || "").trim();
      if (pre) {
        const el = $("#idn_input");
        if (el) el.value = pre;
      }
    } catch (_) {
    }
    let pendingErr = "";
    const data = await apiOr("/provision/pending", (e) => {
      pendingErr = String(e && e.message || e || "load failed");
      return { items: [] };
    }, { timeoutMs: 16e3 });
    const items = data.items || [];
    const pendListEl = view.querySelector("#pendList");
    if (!pendListEl) return;
    setChildMarkup(
      pendListEl,
      `
    <div class="table-wrap"><table class="t">
      <thead><tr><th>MAC</th><th>Serial / proposed ID</th><th>QR</th><th>Firmware</th><th>Last seen</th></tr></thead>
      <tbody>${items.length === 0 ? `<tr><td colspan="5" class="muted">${pendingErr ? "Load failed (retry with Refresh)." : "None"}</td></tr>` : items.map((p) => `<tr>
          <td class="mono">${escapeHtml(p.mac_nocolon || p.mac || "")}</td>
          <td class="mono">${escapeHtml(p.proposed_device_id || "\u2014")}</td>
          <td class="mono">${escapeHtml(p.qr_code || "\u2014")}</td>
          <td>${escapeHtml(p.fw || "\u2014")}</td>
          <td>${escapeHtml(fmtTs(p.last_seen_at))}</td>
        </tr>`).join("")}</tbody>
    </table></div>`
    );
  });
  registerRoute("admin", async (view) => {
    setCrumb("Admin");
    if (!hasRole("admin")) {
      mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`);
      return;
    }
    const isSuper = state.me.role === "superadmin";
    let admins = [];
    if (isSuper) {
      try {
        admins = (await api("/auth/admins", { timeoutMs: 16e3 })).items || [];
      } catch {
        admins = [];
      }
    }
    mountView(view, `
    <div class="card">
      <h2>Users</h2>
      <p class="muted">${isSuper ? "Superadmin: create admin/user, assign manager_admin and policies." : "Admin: manage users under you and toggle their capabilities."}</p>
      <p class="muted" style="margin-top:8px">Registration and reset codes are sent via your configured mail channel on server <span class="mono">.env</span>. Telegram alerts need <span class="mono">TELEGRAM_BOT_TOKEN</span> and <span class="mono">TELEGRAM_CHAT_IDS</span>; restart the API after changing those. Status: top bar pills (from <span class="mono">/health</span>).</p>
      <div class="row right-end" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
        <button class="btn btn-tap" id="showCreate" type="button">New user</button>
        <button class="btn secondary btn-tap" id="reloadUsers" type="button">Refresh</button>
      </div>
      <div class="divider"></div>
      <div id="userTable"></div>
    </div>

    ${isSuper ? `<div class="card">
      <h3>Global sharing</h3>
      <p class="muted">Search all share grants, create/update a grant, or revoke directly.</p>
      <div class="inline-form">
        <label class="field"><span>Device ID</span><input id="gs_device" placeholder="SN-..." /></label>
        <label class="field"><span>Grantee</span><input id="gs_user" placeholder="admin_x / user_x" /></label>
        <label class="field"><span>View</span><input id="gs_view" type="checkbox" checked /></label>
        <label class="field"><span>Operate</span><input id="gs_operate" type="checkbox" /></label>
        <div class="row wide" style="justify-content:flex-end;gap:8px;flex-wrap:wrap">
          <button class="btn btn-tap" id="gs_grant" type="button">Grant / Update</button>
          <button class="btn secondary btn-tap" id="gs_query" type="button">Query</button>
          <label class="field" style="margin:0"><span>Include revoked</span><input id="gs_inc_rev" type="checkbox" /></label>
        </div>
      </div>
      <div id="gsList" style="margin-top:10px"></div>
    </div>` : ""}

    <div class="card" id="createPanel" style="display:none">
      <h3>New user</h3>
      <div class="inline-form">
        <label class="field"><span>Username</span><input id="u_name" autocomplete="off" /></label>
        <label class="field"><span>Password (min 8)</span><input id="u_pass" type="password" autocomplete="new-password" /></label>
        <label class="field"><span>Role</span><select id="u_role">
          ${isSuper ? `<option value="user">user</option><option value="admin">admin</option>` : `<option value="user">user</option>`}
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
      <p class="muted">Inbox list for alarm emails when mail channel is configured on the server.</p>
      <div id="smtpStatus" class="row" style="gap:6px"></div>
      <div class="divider"></div>
      <div class="inline-form">
        <label class="field wide"><span>Email</span><input id="r_email" type="email" autocomplete="off" placeholder="you@company.com"/></label>
        <label class="field"><span>Label</span><input id="r_label" autocomplete="off" placeholder="on-call"/></label>
        <div class="row wide" style="justify-content:flex-end">
          <button class="btn" id="r_add">Add</button>
          <button class="btn ghost" id="r_test">Send test mail</button>
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
      <div class="divider"></div>
      <h4 style="margin:0 0 8px">Command chat binding</h4>
      <p class="muted" style="margin:0 0 8px">User sends <span class="mono">/start</span> to bot, copies <span class="mono">chat_id</span>, then binds here. No password in Telegram.</p>
      <div class="inline-form">
        <label class="field"><span>chat_id</span><input id="tgBindChatId" placeholder="e.g. 2082431201 or -100xxxx" /></label>
        <label class="field"><span>Enabled</span><input id="tgBindEnabled" type="checkbox" checked /></label>
        <div class="row wide" style="justify-content:flex-end">
          <button class="btn" id="tgBindSelf" type="button">Bind this chat</button>
          <button class="btn secondary" id="tgReloadBindings" type="button">Refresh bindings</button>
        </div>
      </div>
      <div id="tgBindings" style="margin-top:10px"></div>
    </div>

    ${isSuper ? `<div class="card">
      <h3>Database backup / restore</h3>
      <p class="muted">Uses <span class="mono">/admin/backup/export</span> and <span class="mono">/admin/backup/import</span>: full SQLite encrypted to <span class="mono">.enc</span>. Import writes <span class="mono">*.restored</span> \u2014 follow ops runbook to swap files.</p>
      <label class="field" style="max-width:420px">
        <span>Encryption key <span class="muted">X-Backup-Encryption-Key</span></span>
        <input id="bk_key" type="password" autocomplete="off" />
      </label>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="bk_export">Export .enc</button>
        <input type="file" id="bk_file" accept=".enc,application/octet-stream" />
        <button class="btn secondary" id="bk_import">Upload & decrypt</button>
      </div>
    </div>` : ""}`);
    const $v = (sel) => $(sel, view);
    const loadUsers = async () => {
      try {
        const d = await api("/auth/users", { timeoutMs: 16e3 });
        const users = d.items || [];
        const userTableEl = $v("#userTable");
        if (!userTableEl) return;
        setChildMarkup(
          userTableEl,
          users.length === 0 ? `<p class="muted">No users.</p>` : `<div class="table-wrap"><table class="t">
            <thead><tr><th>User</th><th>Role</th><th>manager</th><th>tenant</th><th>Created</th><th></th></tr></thead>
            <tbody>${users.map((u) => {
            const isUser = u.role === "user";
            const isAdminRow = u.role === "admin";
            const self = u.username === (state.me && state.me.username);
            const closeTenantBtn = isSuper && isAdminRow && !self ? `<button type="button" class="btn sm danger js-close-admin" data-u="${escapeHtml(u.username)}">Close tenant</button>` : "";
            return `<tr>
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td><span class="chip">${escapeHtml(u.role)}</span></td>
                <td class="mono">${escapeHtml(u.manager_admin || "\u2014")}</td>
                <td class="mono">${escapeHtml(u.tenant || "\u2014")}</td>
                <td>${escapeHtml(fmtTs(u.created_at))}</td>
                <td>
                  <div class="table-actions">
                    <details class="toolbar-collapse">
                      <summary>Actions</summary>
                      <div class="table-actions">
                        ${isUser ? `<button type="button" class="btn sm secondary js-pol" data-u="${escapeHtml(u.username)}">Policy</button>` : ""}
                        ${closeTenantBtn}
                        ${self ? "" : isAdminRow ? "" : `<button type="button" class="btn sm danger js-del" data-u="${escapeHtml(u.username)}">Delete</button>`}
                      </div>
                    </details>
                  </div>
                </td>
              </tr><tr class="sub" style="display:none" data-pol-row="${escapeHtml(u.username)}"><td colspan="6"></td></tr>`;
          }).join("")}</tbody></table></div>`
        );
      } catch (e) {
        const userTableEl = $v("#userTable");
        if (userTableEl) setChildMarkup(userTableEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    };
    const loadGlobalShares = async () => {
      if (!isSuper) return;
      const listEl = $v("#gsList");
      if (!listEl) return;
      const qs = new URLSearchParams();
      const device = ($v("#gs_device").value || "").trim();
      const user = ($v("#gs_user").value || "").trim();
      if (device) qs.set("device_id", device);
      if (user) qs.set("grantee_username", user);
      if ($v("#gs_inc_rev") && $v("#gs_inc_rev").checked) qs.set("include_revoked", "true");
      qs.set("limit", "500");
      setChildMarkup(listEl, `<p class="muted">Loading shares\u2026</p>`);
      try {
        const d = await api("/admin/shares?" + qs.toString(), { timeoutMs: 16e3 });
        const items = d.items || [];
        setChildMarkup(
          listEl,
          items.length === 0 ? `<p class="muted">No matching shares.</p>` : `<div class="table-wrap"><table class="t">
            <thead><tr><th>Device</th><th>Owner</th><th>Grantee</th><th>Role</th><th>View</th><th>Operate</th><th>Granted by</th><th>Status</th><th></th></tr></thead>
            <tbody>${items.map((it) => `
              <tr>
                <td class="mono">${escapeHtml(it.device_id || "")}</td>
                <td class="mono">${escapeHtml(it.owner_admin || "\u2014")}</td>
                <td class="mono">${escapeHtml(it.grantee_username || "")}</td>
                <td>${escapeHtml(it.grantee_role || "\u2014")}</td>
                <td>${it.can_view ? "yes" : "no"}</td>
                <td>${it.can_operate ? "yes" : "no"}</td>
                <td class="mono">${escapeHtml(it.granted_by || "")}</td>
                <td>${it.revoked_at ? `<span class="badge offline">revoked</span>` : `<span class="badge online">active</span>`}</td>
                <td><div class="table-actions">${it.revoked_at ? "" : `<button class="btn sm danger js-gs-revoke" data-device="${escapeHtml(it.device_id || "")}" data-user="${escapeHtml(it.grantee_username || "")}">Revoke</button>`}</div></td>
              </tr>`).join("")}</tbody></table></div>`
        );
      } catch (e) {
        setChildMarkup(listEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    };
    $v("#reloadUsers").addEventListener("click", loadUsers);
    $v("#showCreate").addEventListener("click", () => {
      $v("#createPanel").style.display = "";
      $v("#createPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $v("#u_cancel").addEventListener("click", () => {
      $v("#createPanel").style.display = "none";
    });
    $v("#u_submit").addEventListener("click", async () => {
      const body = {
        username: $v("#u_name").value.trim(),
        password: $v("#u_pass").value,
        role: $v("#u_role").value
      };
      if (!body.username || !body.password) {
        toast("Username and password required", "err");
        return;
      }
      const email = $v("#u_email").value.trim();
      if (!email) {
        toast("Email required for activation", "err");
        return;
      }
      body.email = email;
      const tenant = $v("#u_tenant").value.trim();
      if (tenant) body.tenant = tenant;
      if (isSuper && body.role === "user") body.manager_admin = $v("#u_mgr").value;
      try {
        const resp = await api("/auth/users", { method: "POST", body });
        toast(`Created: ${resp.message || "activation email sent"}`, "ok");
        $v("#createPanel").style.display = "none";
        $v("#u_name").value = "";
        $v("#u_pass").value = "";
        $v("#u_tenant").value = "";
        $v("#u_email").value = "";
        loadUsers();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    if (isSuper) {
      $v("#gs_query").addEventListener("click", loadGlobalShares);
      $v("#gs_grant").addEventListener("click", async () => {
        const device = ($v("#gs_device").value || "").trim();
        const user = ($v("#gs_user").value || "").trim();
        const canView = !!$v("#gs_view").checked;
        const canOperate = !!$v("#gs_operate").checked;
        if (!device || !user) {
          toast("Device ID and grantee required", "err");
          return;
        }
        if (!canView && !canOperate) {
          toast("Select view and/or operate", "err");
          return;
        }
        try {
          await api(`/admin/devices/${encodeURIComponent(device)}/share`, {
            method: "POST",
            body: { grantee_username: user, can_view: canView, can_operate: canOperate }
          });
          toast("Share updated", "ok");
          loadGlobalShares();
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
      $v("#gsList").addEventListener("click", async (ev) => {
        const btn = ev.target.closest(".js-gs-revoke");
        if (!btn) return;
        const device = btn.dataset.device || "";
        const user = btn.dataset.user || "";
        if (!device || !user) return;
        if (!confirm(`Revoke ${user} from ${device}?`)) return;
        try {
          await api(`/admin/devices/${encodeURIComponent(device)}/share/${encodeURIComponent(user)}`, { method: "DELETE" });
          toast("Share revoked", "ok");
          loadGlobalShares();
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
      loadGlobalShares();
    }
    const openPolicy = async (username, trRow) => {
      const cell = trRow.querySelector("td");
      setChildMarkup(cell, `<span class="muted">Loading\u2026</span>`);
      trRow.style.display = "";
      try {
        const p = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { timeoutMs: 16e3 });
        setChildMarkup(cell, renderPolicyPanel(username, p));
        cell.querySelector(".js-save").addEventListener("click", async () => {
          const body = {};
          cell.querySelectorAll("input[type=checkbox][data-k]").forEach((i) => body[i.dataset.k] = !!i.checked);
          try {
            const r = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { method: "PUT", body });
            toast(`Policy updated for ${username}`, "ok");
            setChildMarkup(cell, renderPolicyPanel(username, r.policy || r));
            cell.querySelector(".js-save").addEventListener("click", () => openPolicy(username, trRow));
          } catch (e) {
            toast(e.message || e, "err");
          }
        });
      } catch (e) {
        setChildMarkup(cell, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
      }
    };
    $v("#userTable").addEventListener("click", async (ev) => {
      const t = ev.target.closest("button");
      if (!t) return;
      const u = t.dataset.u;
      if (t.classList.contains("js-del")) {
        if (!confirm(`Delete user ${u}?`)) return;
        try {
          await api(`/auth/users/${encodeURIComponent(u)}`, { method: "DELETE" });
          toast("Deleted", "ok");
          loadUsers();
        } catch (e) {
          toast(e.message || e, "err");
        }
      }
      if (t.classList.contains("js-pol")) {
        const row = view.querySelector(`tr[data-pol-row="${CSS.escape(u)}"]`);
        if (!row) return;
        if (row.style.display === "") {
          row.style.display = "none";
          return;
        }
        openPolicy(u, row);
      }
      if (t.classList.contains("js-close-admin")) {
        if (!isSuper) return;
        if (!u) return;
        if (!confirm(
          `Close admin tenant "${u}"?

\xB7 Devices: factory-unclaim all, OR transfer to another admin in the next prompt.
\xB7 All subordinate users under this admin will be deleted.
\xB7 That username and email are released for new signups.`
        )) return;
        const transfer = window.prompt(
          "Optional: target admin username to receive ALL this admin\u2019s devices (leave empty to unclaim every device):"
        );
        if (transfer === null) return;
        const transferTo = String(transfer).trim() || null;
        const confirmText = window.prompt("Type exactly: CLOSE TENANT");
        if (confirmText === null) return;
        if (String(confirmText).trim() !== "CLOSE TENANT") {
          toast("Confirmation must be exactly: CLOSE TENANT", "err");
          return;
        }
        try {
          const r = await api(`/auth/admins/${encodeURIComponent(u)}/close`, {
            method: "POST",
            body: { confirm_text: "CLOSE TENANT", transfer_devices_to: transferTo }
          });
          toast(
            `Tenant closed \u2014 unclaimed ${Number(r.devices_unclaimed || 0)}, transferred ${Number(r.devices_transferred || 0)}, removed ${Number(r.subordinate_users_deleted || 0)} user(s).`,
            "ok"
          );
          loadUsers();
        } catch (e) {
          toast(e.message || e, "err");
        }
      }
    });
    if (isSuper) {
      $v("#bk_export").addEventListener("click", async () => {
        const key = ($v("#bk_key").value || "").trim();
        if (!key) {
          toast("Enter backup encryption key", "err");
          return;
        }
        const btn = $v("#bk_export");
        const orig = btn ? btn.textContent : "";
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Exporting\u2026";
        }
        try {
          const _h = { "X-Backup-Encryption-Key": key };
          const _tb = getToken();
          if (_tb) _h.Authorization = "Bearer " + _tb;
          const r = await fetchWithDeadline(apiBase() + "/admin/backup/export", {
            method: "GET",
            credentials: "include",
            headers: _h
          }, 3e5);
          if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
          const blob = new Blob([await r.arrayBuffer()], { type: "application/octet-stream" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "sentinel-backup.enc";
          a.click();
          URL.revokeObjectURL(a.href);
          toast("Downloaded", "ok");
        } catch (e) {
          toast(e.message || e, "err");
        } finally {
          if (btn) {
            btn.disabled = false;
            btn.textContent = orig || "Export";
          }
        }
      });
      $v("#bk_import").addEventListener("click", async () => {
        const key = ($v("#bk_key").value || "").trim();
        const f = $v("#bk_file").files[0];
        if (!key || !f) {
          toast("Pick a file and enter the encryption key", "err");
          return;
        }
        const fd = new FormData();
        fd.append("file", f, f.name || "sentinel-backup.enc");
        const btn = $v("#bk_import");
        const orig = btn ? btn.textContent : "";
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Importing\u2026";
        }
        try {
          const _hi = { "X-Backup-Encryption-Key": key };
          const _ti = getToken();
          if (_ti) _hi.Authorization = "Bearer " + _ti;
          else {
            let _ctok = getCsrfToken();
            if (!_ctok) _ctok = await refreshCsrfToken();
            if (_ctok) _hi[CSRF_HEADER_NAME] = _ctok;
          }
          const r = await fetchWithDeadline(apiBase() + "/admin/backup/import", {
            method: "POST",
            credentials: "include",
            headers: _hi,
            body: fd
          }, 3e5);
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(`${r.status} ${j.detail || ""}`);
          toast("Written: " + (j.written_path || "done"), "ok");
        } catch (e) {
          toast(e.message || e, "err");
        } finally {
          if (btn) {
            btn.disabled = false;
            btn.textContent = orig || "Import";
          }
        }
      });
    }
    const loadSmtpStatus = async () => {
      try {
        const s = await api("/admin/smtp/status", { timeoutMs: 16e3 });
        const smtpEl = $v("#smtpStatus");
        if (!smtpEl) return;
        const okBadge = s.enabled ? `<span class="badge online">Mail on</span>` : `<span class="badge offline">Mail off</span>`;
        const last = s.last_error ? `<span class="chip" title="last error">${escapeHtml(s.last_error)}</span>` : "";
        setChildMarkup(
          smtpEl,
          `${okBadge}
        <span class="chip">host: ${escapeHtml(s.host || "\u2014")}:${escapeHtml(String(s.port || "\u2014"))}</span>
        <span class="chip">mode: ${escapeHtml(s.mode || "\u2014")}</span>
        <span class="chip">from: ${escapeHtml(s.sender || "\u2014")}</span>
        <span class="chip">sent: ${s.sent_count || 0}</span>
        <span class="chip">failed: ${s.failed_count || 0}</span>
        <span class="chip">queue: ${s.queue_size ?? 0}/${s.queue_max ?? ""}</span>${last}`
        );
      } catch (e) {
        const smtpEl = $v("#smtpStatus");
        if (!smtpEl) return;
        setChildMarkup(smtpEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
      }
    };
    const loadRecipients = async () => {
      try {
        const d = await api("/admin/alert-recipients", { timeoutMs: 16e3 });
        const items = d.items || [];
        const listEl = $v("#recipientList");
        if (!listEl) return;
        setChildMarkup(
          listEl,
          items.length === 0 ? `<p class="muted">No recipients yet.</p>` : `<div class="table-wrap"><table class="t">
            <thead><tr><th>Email</th><th>Label</th><th>Enabled</th><th>Tenant</th><th></th></tr></thead>
            <tbody>${items.map((r) => `
              <tr>
                <td class="mono">${escapeHtml(r.email)}</td>
                <td>${escapeHtml(r.label || "\u2014")}</td>
                <td>${r.enabled ? `<span class="badge online">On</span>` : `<span class="badge offline">Off</span>`}</td>
                <td class="mono">${escapeHtml(r.owner_admin || "")}</td>
                <td><div class="table-actions">
                  <button class="btn sm secondary js-rtoggle" data-id="${r.id}" data-en="${r.enabled ? 1 : 0}">${r.enabled ? "Disable" : "Enable"}</button>
                  <button class="btn sm danger js-rdel" data-id="${r.id}">Delete</button>
                </div></td>
              </tr>`).join("")}</tbody></table></div>`
        );
      } catch (e) {
        const listEl = $v("#recipientList");
        if (!listEl) return;
        setChildMarkup(listEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
      }
    };
    $v("#r_add").addEventListener("click", async () => {
      const email = ($v("#r_email").value || "").trim();
      const label = ($v("#r_label").value || "").trim();
      if (!email) {
        toast("Enter email", "err");
        return;
      }
      try {
        await api("/admin/alert-recipients", { method: "POST", body: { email, label } });
        $v("#r_email").value = "";
        $v("#r_label").value = "";
        toast("Added", "ok");
        loadRecipients();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $v("#r_test").addEventListener("click", async () => {
      const email = ($v("#r_email").value || "").trim();
      if (!email) {
        toast("Enter recipient email first", "err");
        return;
      }
      try {
        await api("/admin/smtp/test", { method: "POST", body: { to: email } });
        toast("Mail test sent", "ok");
        loadSmtpStatus();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    const loadTgStatus = async () => {
      try {
        const t = await api("/admin/telegram/status", { timeoutMs: 16e3 });
        const tgEl = $v("#tgStatus");
        if (!tgEl) return;
        const badge = t.enabled ? `<span class="badge online">enabled</span>` : `<span class="badge offline">disabled</span>`;
        const wk = t.worker_running ? "yes" : "no";
        const th = t.token_hint ? `<span class="chip mono" title="Token prefix/suffix only">${escapeHtml(t.token_hint)}</span>` : "";
        const modErr = t.status_module_error ? `<p class="badge revoked" style="margin-top:8px">Telegram module failed \u2014 see <span class="mono">last_error</span> and API logs.</p>` : "";
        const le = (t.last_error || "").trim() ? `<p class="muted" style="margin-top:8px;word-break:break-word"><strong>Last error:</strong> ${escapeHtml(t.last_error)}</p>` : "";
        setChildMarkup(
          tgEl,
          `${badge}
        ${th}
        <span class="chip">worker: ${wk}</span>
        <span class="chip">chats: ${t.chats ?? 0}</span>
        <span class="chip">min_level: ${escapeHtml(t.min_level || "")}</span>
        <span class="chip">queue: ${t.queue_size ?? 0}</span>${modErr}${le}`
        );
      } catch (e) {
        const tgEl = $v("#tgStatus");
        if (!tgEl) return;
        setChildMarkup(tgEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
      }
    };
    const loadTgBindings = async () => {
      const el = $v("#tgBindings");
      if (!el) return;
      setChildMarkup(el, `<p class="muted">Loading bindings\u2026</p>`);
      try {
        const d = await api("/admin/telegram/bindings", { timeoutMs: 16e3 });
        const items = d.items || [];
        setChildMarkup(
          el,
          items.length === 0 ? `<p class="muted">No bindings yet.</p>` : `<div class="table-wrap"><table class="t">
            <thead><tr><th>chat_id</th><th>username</th><th>enabled</th><th>updated</th><th></th></tr></thead>
            <tbody>${items.map((it) => `
              <tr>
                <td class="mono">${escapeHtml(it.chat_id || "")}</td>
                <td>${escapeHtml(it.username || "")}</td>
                <td>${it.enabled ? `<span class="badge online">on</span>` : `<span class="badge offline">off</span>`}</td>
                <td>${escapeHtml(fmtTs(it.updated_at || it.created_at))}</td>
                <td><div class="table-actions"><button class="btn sm danger js-tg-unbind" data-chat="${escapeHtml(String(it.chat_id || ""))}">Unbind</button></div></td>
              </tr>`).join("")}</tbody></table></div>`
        );
      } catch (e) {
        setChildMarkup(el, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
      }
    };
    $v("#tgTest").addEventListener("click", async () => {
      try {
        const r = await api("/admin/telegram/test", { method: "POST", body: { text: "Croc Sentinel UI test" } });
        toast(r.detail || "ok", "ok");
        loadTgStatus();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $v("#tgBindSelf").addEventListener("click", async () => {
      const chat_id = ($v("#tgBindChatId").value || "").trim();
      const enabled = !!$v("#tgBindEnabled").checked;
      if (!chat_id) {
        toast("Enter chat_id", "err");
        return;
      }
      try {
        await api("/admin/telegram/bind-self", { method: "POST", body: { chat_id, enabled } });
        toast("Chat bound", "ok");
        loadTgBindings();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $v("#tgReloadBindings").addEventListener("click", loadTgBindings);
    $v("#tgBindings").addEventListener("click", async (ev) => {
      const btn = ev.target.closest(".js-tg-unbind");
      if (!btn) return;
      const chat = btn.dataset.chat || "";
      if (!chat) return;
      if (!confirm(`Unbind chat ${chat}?`)) return;
      try {
        await api(`/admin/telegram/bindings/${encodeURIComponent(chat)}`, { method: "DELETE" });
        toast("Unbound", "ok");
        loadTgBindings();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $v("#recipientList").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button");
      if (!b) return;
      const id = b.dataset.id;
      if (b.classList.contains("js-rdel")) {
        if (!confirm("Remove this recipient?")) return;
        try {
          await api(`/admin/alert-recipients/${id}`, { method: "DELETE" });
          toast("Removed", "ok");
          loadRecipients();
        } catch (e) {
          toast(e.message || e, "err");
        }
      }
      if (b.classList.contains("js-rtoggle")) {
        const en = b.dataset.en === "1" ? 0 : 1;
        try {
          await api(`/admin/alert-recipients/${id}`, { method: "PATCH", body: { enabled: !!en } });
          loadRecipients();
        } catch (e) {
          toast(e.message || e, "err");
        }
      }
    });
    loadSmtpStatus();
    loadRecipients();
    loadTgStatus();
    loadTgBindings();
    const loadPendAdmins = async () => {
      if (!isSuper) return;
      try {
        const d = await api("/auth/signup/pending", { timeoutMs: 16e3 });
        const items = d.items || [];
        const pendEl = $v("#pendAdmins");
        if (!pendEl) return;
        setChildMarkup(
          pendEl,
          items.length === 0 ? `<p class="muted">No pending signups.</p>` : `<div class="table-wrap"><table class="t">
            <thead><tr><th>Username</th><th>Email</th><th>Submitted</th><th>Email OK</th><th></th></tr></thead>
            <tbody>${items.map((u) => `<tr>
              <td><strong>${escapeHtml(u.username)}</strong></td>
              <td class="mono">${escapeHtml(u.email || "\u2014")}</td>
              <td>${escapeHtml(fmtTs(u.created_at))}</td>
              <td>${u.email_verified_at ? "\u2713" : "\u2014"}</td>
              <td>
                <button class="btn sm js-ok" data-u="${escapeHtml(u.username)}">Approve</button>
                <button class="btn sm danger js-reject" data-u="${escapeHtml(u.username)}">Reject</button>
              </td>
            </tr>`).join("")}</tbody></table></div>`
        );
      } catch (e) {
        const pendEl = $v("#pendAdmins");
        if (!pendEl) return;
        setChildMarkup(pendEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    };
    if (isSuper) {
      $v("#pendAdmins").addEventListener("click", async (ev) => {
        const b = ev.target.closest("button");
        if (!b) return;
        const u = b.dataset.u;
        if (b.classList.contains("js-ok")) {
          try {
            await api(`/auth/signup/approve/${encodeURIComponent(u)}`, { method: "POST" });
            toast("Approved", "ok");
            loadPendAdmins();
            loadUsers();
          } catch (e) {
            toast(e.message || e, "err");
          }
        } else if (b.classList.contains("js-reject")) {
          if (!confirm(`Reject and delete signup for ${u}?`)) return;
          try {
            await api(`/auth/signup/reject/${encodeURIComponent(u)}`, { method: "POST" });
            toast("Rejected", "ok");
            loadPendAdmins();
          } catch (e) {
            toast(e.message || e, "err");
          }
        }
      });
      loadPendAdmins();
    }
    loadUsers();
  });
  registerRoute("alerts", async (view) => {
    setCrumb("Siren");
    const enabled = can("can_alert");
    mountView(view, `
    <div class="card">
      <h2>Bulk siren</h2>
      <p class="muted">MQTT <span class="mono">siren_on</span> / <span class="mono">siren_off</span>. Requires <span class="mono">can_alert</span>.</p>
      ${enabled ? "" : `<p class="badge revoked">No can_alert \u2014 ask admin (Policies).</p>`}
      <p id="alertsLoadMsg" class="muted" aria-live="polite">Loading device list\u2026</p>
      <div class="inline-form inline-form--bulk-siren" style="margin-top:12px">
        <label class="field"><span>Action</span>
          <select id="action"><option value="on">ON</option><option value="off">OFF</option></select>
        </label>
        <label class="field"><span>Duration (ms)</span>
          <input id="dur" type="number" value="${DEFAULT_REMOTE_SIREN_MS}" min="500" max="300000" step="1000" />
        </label>
        <label class="field wide"><span>Targets (empty = all visible)</span>
          <select id="targets" multiple size="6" disabled></select>
        </label>
        <div class="row wide" style="justify-content:flex-end">
          <button class="btn danger" id="fire" disabled>Run</button>
        </div>
      </div>
    </div>`);
    const sel = $("#targets");
    const fireBtn = $("#fire");
    const loadMsg = $("#alertsLoadMsg");
    let list;
    try {
      list = await apiGetCached("/devices", { timeoutMs: 16e3 }, 4e3);
      if (loadMsg) loadMsg.remove();
    } catch (e) {
      const detail = String(e && e.message || e || "load failed");
      if (loadMsg) {
        loadMsg.className = "badge offline";
        loadMsg.textContent = `Device list fallback: ${detail}`;
      }
      list = { items: [] };
    }
    const devices = list.items || [];
    setChildMarkup(sel, devices.map((d) => {
      const lab = d.display_label ? `${escapeHtml(d.display_label)}` : escapeHtml(d.device_id);
      const serial = d.display_label ? ` \xB7 ${escapeHtml(d.device_id)}` : "";
      const grp = d.notification_group ? `[${escapeHtml(d.notification_group)}] ` : "";
      const z = d.zone ? ` \xB7 ${escapeHtml(d.zone)}` : "";
      return `<option value="${escapeHtml(d.device_id)}">${grp}${lab}${serial}${z}</option>`;
    }).join(""));
    sel.disabled = false;
    if (enabled) fireBtn.disabled = false;
    fireBtn.addEventListener("click", async () => {
      const action = $("#action").value;
      const dur = parseInt($("#dur").value, 10) || DEFAULT_REMOTE_SIREN_MS;
      const ids = Array.from(sel.selectedOptions).map((o) => o.value);
      if (action === "on" && !confirm(`Siren ON for ${ids.length === 0 ? "ALL visible devices" : ids.length + " device(s)"}?`)) return;
      try {
        const r = await api("/alerts", { method: "POST", body: { action, duration_ms: dur, device_ids: ids } });
        toast(`${action === "on" ? "ON" : "OFF"} \u2192 ${r.sent_count} device(s)`, "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
  });
  registerRoute("audit", async (view, _args, routeSeq) => {
    setCrumb("Audit");
    if (!hasRole("admin")) {
      mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`);
      return;
    }
    mountView(view, `
    <div class="ui-shell card audit-page">
      <div class="ui-section-head">
        <div>
          <h2 class="ui-section-title">Audit</h2>
          <p class="ui-section-sub">Who did what, when \u2014 extra fields only when they add information beyond actor / target.</p>
        </div>
        <div class="ui-section-actions audit-filters">
          <label class="field compact"><span>Actor</span><input id="f_actor" type="search" autocomplete="off" placeholder="username" /></label>
          <label class="field compact"><span>Action</span><input id="f_action" type="search" autocomplete="off" placeholder="prefix e.g. provision" /></label>
          <label class="field compact"><span>Target</span><input id="f_target" type="search" autocomplete="off" placeholder="device or user" /></label>
          <button class="btn secondary btn-tap" id="f_reload" type="button">Apply</button>
        </div>
      </div>
      <div class="ui-status-strip" id="auditStrip">
        <span class="ui-status-item"><strong id="auditCount">\u2014</strong> entries</span>
        <span class="ui-status-item muted">Newest first \xB7 max 200</span>
      </div>
      <div class="divider"></div>
      <div id="auditList" class="audit-feed-wrap"><p class="muted">Loading\u2026</p></div>
    </div>`);
    const reload = async () => {
      const qs = new URLSearchParams();
      const elA = $("#f_actor", view);
      const elAc = $("#f_action", view);
      const elT = $("#f_target", view);
      const a = (elA && elA.value ? String(elA.value) : "").trim();
      const ac = (elAc && elAc.value ? String(elAc.value) : "").trim();
      const t = (elT && elT.value ? String(elT.value) : "").trim();
      if (a) qs.set("actor", a);
      if (ac) qs.set("action", ac);
      if (t) qs.set("target", t);
      qs.set("limit", "200");
      let d;
      try {
        d = await api("/audit?" + qs.toString(), { timeoutMs: 24e3 });
      } catch (e) {
        toast(e.message || e, "err");
        return;
      }
      if (!isRouteCurrent(routeSeq)) return;
      const items = d.items || [];
      const auditListEl = $("#auditList", view);
      const countEl = $("#auditCount", view);
      if (!auditListEl) return;
      if (countEl) setTextIfChanged(countEl, String(items.length));
      if (items.length === 0) {
        setHtmlIfChanged(auditListEl, `<p class="muted audit-empty">No matching entries.</p>`);
        return;
      }
      setHtmlIfChanged(auditListEl, `<div class="audit-feed">${items.map((e) => {
        const actor = e.actor || "";
        const tgt = e.target || "";
        const action = e.action || "";
        const extras = auditDetailDedupedRows(e.detail || {}, actor, tgt);
        const extrasHtml = extras.length ? `<div class="audit-extra">${extras.map(
          (row) => `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`
        ).join("")}</div>` : "";
        const tgtHtml = tgt ? `<span class="audit-target mono" title="target">${escapeHtml(tgt)}</span>` : `<span class="muted">\u2014</span>`;
        return `
        <article class="audit-item">
          <div class="audit-item-top">
            <div class="audit-time">
              <span class="audit-ts">${escapeHtml(fmtTs(e.created_at))}</span>
              <span class="muted audit-rel">${escapeHtml(fmtRel(e.created_at))}</span>
            </div>
            <span class="audit-action-chip ${auditChipClass(action)}" title="${escapeHtml(action)}">${escapeHtml(action)}</span>
          </div>
          <div class="audit-item-line">
            <span class="audit-actor">${escapeHtml(actor)}</span>
            <span class="audit-arrow" aria-hidden="true">\u2192</span>
            ${tgtHtml}
          </div>
          ${extrasHtml}
        </article>`;
      }).join("")}</div>`);
    };
    const onFilterKey = (ev) => {
      if (ev.key === "Enter") reload();
    };
    $("#f_reload", view).addEventListener("click", reload);
    const fa = $("#f_actor", view);
    const fac = $("#f_action", view);
    const ft = $("#f_target", view);
    if (fa) fa.addEventListener("keydown", onFilterKey);
    if (fac) fac.addEventListener("keydown", onFilterKey);
    if (ft) ft.addEventListener("keydown", onFilterKey);
    reload();
    scheduleRouteTicker(routeSeq, "audit-live-reload", reload, 12e3);
  });
  registerRoute("devices", async (view, args, routeSeq) => {
    const id = decodeURIComponent(args[0] || "");
    if (!id) {
      setCrumb("All devices");
      let allItems = [];
      const hintById = /* @__PURE__ */ new Map();
      const selectedIds = /* @__PURE__ */ new Set();
      const filteredItems = () => {
        const inp = $("#allDevFilter", view);
        const q = inp ? String(inp.value || "").trim().toLowerCase() : "";
        return allItems.filter((d2) => {
          if (!q) return true;
          const did = String(d2.device_id || "").toLowerCase();
          const nm = String(d2.display_label || "").toLowerCase();
          const grp = String(d2.notification_group || "").toLowerCase();
          const zn = String(d2.zone || "").toLowerCase();
          return did.includes(q) || nm.includes(q) || grp.includes(q) || zn.includes(q);
        });
      };
      const bulkBarState = () => {
        const c = selectedIds.size;
        const stat = $("#bulkSelStat", view);
        const grpBtn2 = $("#bulkApplyGroup", view);
        const zoBtn = $("#bulkApplyZone", view);
        const zcBtn = $("#bulkClearZone", view);
        const selVisBtn = $("#bulkSelectVisible", view);
        const clrBtn = $("#bulkClearSel", view);
        const totalVisible = filteredItems().length;
        if (stat) stat.textContent = `${c} selected \xB7 ${totalVisible} visible`;
        const disable = c === 0;
        if (grpBtn2) grpBtn2.disabled = disable;
        if (zoBtn) zoBtn.disabled = disable;
        if (zcBtn) zcBtn.disabled = disable;
        if (clrBtn) clrBtn.disabled = disable;
        if (selVisBtn) selVisBtn.disabled = totalVisible === 0;
      };
      const deviceListCard = (d2) => {
        const on = isOnline(d2);
        const did = String(d2.device_id || "");
        const checked = selectedIds.has(did);
        const hasLabel = !!(d2.display_label && String(d2.display_label).trim());
        const titleHtml = hasLabel ? `<div class="device-card__title-row"><span class="device-primary-name device-card__title-name">${escapeHtml(String(d2.display_label).trim())}</span><span class="device-card__sn mono" title="${escapeHtml(did)}">${escapeHtml(did)}</span></div>` : `<div class="device-card__title-row device-card__title-row--mono"><span class="device-primary-name mono device-card__sn" title="${escapeHtml(did)}">${escapeHtml(did || "unknown")}</span></div>`;
        const letter = escapeHtml((d2.display_label || d2.device_id || "?").slice(0, 1).toUpperCase());
        const spLine = d2.status_preview && d2.status_preview.line ? escapeHtml(String(d2.status_preview.line)) : "\u2014";
        const showOwnerTag = !!(d2.owner_admin && state.me && (state.me.role === "superadmin" || d2.is_shared));
        const scopeLead = d2.is_shared && d2.shared_by ? `<span class="device-card__meta-k">Shared</span><span class="device-card__meta-scope">${escapeHtml(String(d2.shared_by))}</span><span class="device-card__meta-sep" aria-hidden="true"> \xB7 </span>` : "";
        const needFw = !!(d2.firmware_hint && d2.firmware_hint.update_available && firmwareHintStillValid(d2.fw, d2.firmware_hint));
        const fwBlock = d2.fw ? `<div class="device-card__firmware"><span class="device-fw-inline" role="group" aria-label="Firmware"><span class="chip device-fw-chip" title="Reported firmware">v${escapeHtml(d2.fw)}</span>` + (needFw ? `<span class="device-fw-pill" title="Newer build on server / \u670D\u52A1\u5668\u4E0A\u6709\u8F83\u65B0\u7248\u672C">Update / \u6709\u66F4\u65B0</span><button type="button" class="btn sm secondary fw-hint-cta fw-hint-cta--sm js-fw-hint" data-did="${escapeHtml(did)}" title="View update details / \u67E5\u770B\u66F4\u65B0" aria-label="Firmware update">\u66F4\u65B0</button>` : "") + `</span></div>` : "";
        const listCorner = `<div class="device-card__corner-tr device-card__corner-tr--list-bulk" role="group" aria-label="Selection">` + (showOwnerTag ? `<span class="card-owner-tag" title="Owning admin / \u79DF\u6237">${escapeHtml(String(d2.owner_admin))}</span>` : "") + `<label class="device-card__pick-wrap muted"><input type="checkbox" class="bulk-dev-pick" data-device-id="${escapeHtml(did)}" ${checked ? "checked" : ""} /><span>Pick</span></label></div>`;
        return `<div class="device-card device-card--row-thumb${showOwnerTag ? " device-card--row-thumb--wide-pad" : ""}" style="position:relative">` + listCorner + `<a href="#/devices/${encodeURIComponent(d2.device_id)}" style="display:flex;gap:10px;text-decoration:none;color:inherit;flex:1;min-width:0"><div class="device-thumb device-thumb--list" aria-hidden="true">${letter}</div><div class="device-card--row-body"><h3 class="device-card__h3">${titleHtml}</h3><div class="device-card__status"><div class="device-card__pills"><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>` + (d2.zone ? `<span class="chip device-zone-chip">${escapeHtml(d2.zone)}</span>` : "") + (d2.is_shared ? `<span class="badge accent" title="shared device">shared</span>` : "") + `</div>${fwBlock}</div><div class="device-card__meta-compact meta"><div class="device-card__meta-row"><span class="device-card__meta-k">Live</span><span class="device-card__meta-v">${spLine}</span></div><div class="device-card__meta-row">${scopeLead}<span class="device-card__meta-k">Updated</span><span class="device-card__meta-v">${escapeHtml(fmtRel(d2.updated_at))}</span></div></div></div></a></div>`;
      };
      const applyFilter = () => {
        const items = filteredItems();
        const grid2 = $("#allDevicesGrid", view);
        if (!grid2) return;
        try {
          grid2.classList.remove("device-grid--skeleton");
          grid2.removeAttribute("aria-busy");
        } catch (_) {
        }
        if (allItems.length === 0) {
          setChildMarkup(grid2, `<p class="muted" style="padding:8px 0">No devices in your scope.</p>`);
          bulkBarState();
          return;
        }
        setChildMarkup(
          grid2,
          items.length === 0 ? `<p class="muted" style="padding:8px 0">No matches.</p>` : items.map(deviceListCard).join("")
        );
        bulkBarState();
      };
      const runBulkProfile = async (payload) => {
        if (!selectedIds.size) {
          toast("Select at least one device", "err");
          return;
        }
        const ids = Array.from(selectedIds.values());
        const r = await api("/devices/bulk/profile", {
          method: "POST",
          body: Object.assign({ device_ids: ids }, payload || {})
        });
        bustDeviceListCaches();
        toast(`Bulk done \xB7 ${Number(r.count || ids.length)} devices`, "ok");
        await loadDevicesAndHints();
      };
      const mergeFirmwareHintsObject = (raw) => {
        const o = raw && typeof raw === "object" ? raw : {};
        hintById.clear();
        for (const k of Object.keys(o)) hintById.set(k, o[k]);
        for (const it of allItems) {
          const k = String(it.device_id);
          const h = o[k];
          it.firmware_hint = h && h.update_available && firmwareHintStillValid(it.fw, h) ? h : null;
        }
      };
      const loadDevicesAndHints = async () => {
        if (!isRouteCurrent(routeSeq)) return;
        let r;
        try {
          r = await api("/devices", { timeoutMs: 2e4, retries: 2 });
        } catch (e) {
          if (isRouteCurrent(routeSeq)) toast(String(e && e.message) || "Failed to load devices", "err");
          return;
        }
        if (!isRouteCurrent(routeSeq)) return;
        allItems = Array.isArray(r.items) ? r.items : [];
        for (const did of Array.from(selectedIds)) {
          if (!allItems.some((x) => String(x.device_id) === did)) selectedIds.delete(did);
        }
        for (const it of allItems) {
          it.firmware_hint = null;
        }
        applyFilter();
        try {
          const hintRes = await api("/devices/firmware-hints", { timeoutMs: 25e3, retries: 0 });
          if (!isRouteCurrent(routeSeq)) return;
          mergeFirmwareHintsObject(hintRes && hintRes.hints || {});
        } catch (_) {
        }
        if (isRouteCurrent(routeSeq)) applyFilter();
      };
      mountView(view, `
      <header class="page-head">
        <h2>All devices</h2>
        <p class="muted">Thumbnails and quick status. Multi-select for production bulk updates.</p>
      </header>
      <div class="card" style="margin:0 0 12px">
        <div class="inline-form" style="margin-top:4px">
          <label class="field" style="max-width:min(100%, 360px)">
            <span>Filter</span>
            <input type="search" id="allDevFilter" placeholder="id / name / group / zone" autocomplete="off" />
          </label>
        </div>
        <div class="action-bar" style="margin-top:12px">
          <span class="chip" id="bulkSelStat">0 selected \xB7 0 visible</span>
          <button class="btn sm secondary" id="bulkSelectVisible" type="button">Select visible</button>
          <button class="btn sm secondary" id="bulkClearSel" type="button" disabled>Clear selection</button>
          <details class="toolbar-collapse" style="min-width:260px;flex:1 1 420px">
            <summary>Bulk actions</summary>
            <div class="inline-form" style="margin-top:2px">
              <label class="field">
                <span>Bulk group</span>
                <input id="bulkGroupValue" maxlength="80" placeholder="empty = clear group" />
              </label>
              <button class="btn sm" id="bulkApplyGroup" type="button" disabled>Apply group</button>
              <label class="field">
                <span>Zone override</span>
                <input id="bulkZoneValue" maxlength="31" placeholder="e.g. all / Zone-A" />
              </label>
              <div class="row" style="gap:8px;justify-content:flex-end;flex-wrap:wrap">
                <button class="btn sm" id="bulkApplyZone" type="button" disabled>Apply zone</button>
                <button class="btn sm secondary" id="bulkClearZone" type="button" disabled>Clear zone override</button>
              </div>
            </div>
          </details>
        </div>
      </div>
      <div id="allDevicesGrid" class="device-grid device-grid--skeleton" aria-busy="true">
        ${[1, 2, 3, 4, 5, 6].map(() => `<div class="device-card device-card--skeleton" role="presentation"><div class="device-card--skeleton__thumb"></div><div class="device-card--skeleton__body"><div class="device-card--skeleton__line device-card--skeleton__line--w80"></div><div class="device-card--skeleton__line device-card--skeleton__line--w40"></div><div class="device-card--skeleton__line device-card--skeleton__line--w90"></div></div></div>`).join("")}
      </div>
    `);
      const f = $("#allDevFilter", view);
      if (f) f.addEventListener("input", () => {
        applyFilter();
      });
      const grid = $("#allDevicesGrid", view);
      if (grid) {
        grid.addEventListener("change", (ev) => {
          const el = ev.target;
          if (!(el instanceof HTMLInputElement)) return;
          if (!el.classList.contains("bulk-dev-pick")) return;
          const did = String(el.dataset.deviceId || "").trim();
          if (!did) return;
          if (el.checked) selectedIds.add(did);
          else selectedIds.delete(did);
          bulkBarState();
        });
      }
      const selVis = $("#bulkSelectVisible", view);
      if (selVis) {
        selVis.addEventListener("click", () => {
          for (const d2 of filteredItems()) {
            const did = String(d2.device_id || "").trim();
            if (did) selectedIds.add(did);
          }
          applyFilter();
        });
      }
      const clrSel = $("#bulkClearSel", view);
      if (clrSel) {
        clrSel.addEventListener("click", () => {
          selectedIds.clear();
          applyFilter();
        });
      }
      const grpBtn = $("#bulkApplyGroup", view);
      if (grpBtn) {
        grpBtn.addEventListener("click", async () => {
          const rawG = String($("#bulkGroupValue", view)?.value || "").trim();
          const grpVal = rawG ? canonicalGroupKey(rawG) : "";
          const promptTxt = grpVal ? `Apply group "${grpVal}" to ${selectedIds.size} selected device(s)?` : `Clear group for ${selectedIds.size} selected device(s)?`;
          if (!confirm(promptTxt)) return;
          try {
            await runBulkProfile({ set_notification_group: true, notification_group: grpVal });
          } catch (e) {
            toast(e.message || e, "err");
          }
        });
      }
      const zoneBtn = $("#bulkApplyZone", view);
      if (zoneBtn) {
        zoneBtn.addEventListener("click", async () => {
          const z = String($("#bulkZoneValue", view)?.value || "").trim();
          if (!z) {
            toast("Enter zone value", "err");
            return;
          }
          if (!confirm(`Apply zone override "${z}" to ${selectedIds.size} selected device(s)?`)) return;
          try {
            await runBulkProfile({ set_zone_override: true, zone_override: z });
          } catch (e) {
            toast(e.message || e, "err");
          }
        });
      }
      const clrZoneBtn = $("#bulkClearZone", view);
      if (clrZoneBtn) {
        clrZoneBtn.addEventListener("click", async () => {
          if (!confirm(`Clear zone override for ${selectedIds.size} selected device(s)?`)) return;
          try {
            await runBulkProfile({ clear_zone_override: true });
          } catch (e) {
            toast(e.message || e, "err");
          }
        });
      }
      view.addEventListener("click", (ev) => {
        const t = ev.target && ev.target.closest && ev.target.closest(".js-fw-hint");
        if (!t) return;
        ev.preventDefault();
        ev.stopPropagation();
        const did0 = t.getAttribute("data-did");
        const h = did0 && hintById.get(did0);
        const row = did0 ? allItems.find((x) => String(x.device_id) === String(did0)) : null;
        if (h) {
          openGlobalFwHintDialog(h, {
            currentFw: row && row.fw != null ? String(row.fw) : "",
            deviceId: String(did0 || ""),
            canOperateThisDevice: void 0
          });
        }
      });
      requestAnimationFrame(() => {
        setTimeout(() => {
          void loadDevicesAndHints();
        }, 0);
      });
      scheduleRouteTicker(routeSeq, "devices-list-live", loadDevicesAndHints, 22e3);
      return;
    }
    const isSuperViewer = !!(state.me && state.me.role === "superadmin");
    let d = await api(`/devices/${encodeURIComponent(id)}`);
    const canOperateThisDevice = !!(d.can_operate ?? (state.me && (state.me.role === "superadmin" || state.me.role === "admin")));
    window.__devicePollLocks = window.__devicePollLocks || /* @__PURE__ */ new Map();
    const runPollDedup = (key, worker) => {
      const k = String(key || "");
      if (!k) return worker();
      const locks = window.__devicePollLocks;
      if (locks.has(k)) return locks.get(k);
      const p = (async () => {
        try {
          return await worker();
        } finally {
          if (locks.get(k) === p) locks.delete(k);
        }
      })();
      locks.set(k, p);
      return p;
    };
    setCrumb(d.display_label ? `Device \xB7 ${d.display_label}` : `Device \xB7 ${id}`);
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
      signal_weak: "Weak signal"
    };
    const deviceLiveModel = (dev) => {
      const on = isOnline(dev);
      const s = dev.last_status_json || {};
      const reason = s.disconnect_reason || (on ? "none" : "network_lost");
      const outV = s.vbat == null || s.vbat < 0 ? "\u2014" : `${Number(s.vbat).toFixed(2)} V`;
      const rssi = s.rssi == null || s.rssi === -127 ? "\u2014" : `${s.rssi} dBm`;
      const netT = String(s.net_type || dev.net_type || "");
      const wifiSsidDd = netT === "wifi" ? s.wifi_ssid != null && String(s.wifi_ssid).length > 0 ? escapeHtml(String(s.wifi_ssid)) : `<span class="muted">Not associated</span>` : `<span class="muted">N/A (${escapeHtml(netT || "\u2014")})</span>`;
      const wifiChDd = netT === "wifi" && s.wifi_channel != null && Number(s.wifi_channel) > 0 ? escapeHtml(String(s.wifi_channel)) : "\u2014";
      return { on, s, reason, outV, rssi, wifiSsidDd, wifiChDd };
    };
    const dm = deviceLiveModel(d);
    const rawCommandDrawer = state.me && state.me.role === "superadmin" ? `
    <details class="card device-drawer">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Raw command</span>
        <span class="device-drawer__hint muted">Superadmin \xB7 manual MQTT cmd</span>
      </summary>
      <div class="device-drawer__body">
        <label class="field"><span>cmd</span><input id="cmdName" placeholder="get_info / ota" ${can("can_send_command") ? "" : "disabled"} /></label>
        <label class="field" style="margin-top:8px"><span>params (JSON)</span><textarea id="cmdParams" placeholder='{"key":"value"}' ${can("can_send_command") ? "" : "disabled"}></textarea></label>
        <div class="row" style="margin-top:8px;justify-content:flex-end">
          <button class="btn" id="sendCmd" ${can("can_send_command") ? "" : "disabled"}>Send</button>
        </div>
      </div>
    </details>` : "";
    const canUseSharePanel = !!(state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users")) && (!d.is_shared || state.me.role === "superadmin"));
    const sharePanel = canUseSharePanel ? `
    <details class="card device-drawer" id="sharePanel">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Sharing</span>
        <span class="device-drawer__hint muted">Grant / revoke \xB7 expand</span>
      </summary>
      <div class="device-drawer__body">
        <div class="row" style="justify-content:flex-end;margin-bottom:8px">
          <button class="btn secondary btn-tap sm" type="button" id="shareRefresh">Refresh</button>
        </div>
        <p class="muted" style="margin:0 0 10px">Grant or revoke per-account access (admin: your users only).</p>
        <div class="inline-form" style="margin-top:4px">
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
    </details>
  ` : "";
    const renderMsgFeed = (items) => {
      const msgItems = Array.isArray(items) ? items : [];
      if (msgItems.length === 0) return `<p class="muted audit-empty">No messages.</p>`;
      return `<div class="audit-feed">${msgItems.map((m) => {
        const plRows = messagePayloadRows(m.payload || {});
        const extra = plRows.length ? `<div class="audit-extra">${plRows.map(
          (row) => `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`
        ).join("")}</div>` : "";
        return `<article class="audit-item">
        <div class="audit-item-top">
          <div class="audit-time">
            <span class="audit-ts mono">${escapeHtml(fmtTs(m.ts_received))}</span>
            <span class="muted audit-rel">${escapeHtml(fmtRel(m.ts_received))}</span>
          </div>
          <span class="chip">${escapeHtml(m.channel || "\u2014")}</span>
        </div>
        ${extra}
      </article>`;
      }).join("")}</div>`;
    };
    const mqttMsgPanel = isSuperViewer ? `
    <div class="card">
      <details id="mqttMsgDetails">
        <summary style="cursor:pointer;font-weight:600">MQTT debug messages (latest 25)</summary>
        <p class="muted" style="margin:8px 0 0">Debug-only raw device uplink snapshots. Hidden by default to keep the page clean.</p>
        <div class="divider"></div>
        <div class="audit-feed-wrap" id="devMsgsList"><p class="muted">Expand to load\u2026</p></div>
      </details>
    </div>` : "";
    mountView(view, `
    <nav class="device-page-back-nav" aria-label="Device navigation">
      <a href="#/devices" class="btn secondary sm btn-tap device-page-back">\u2190 Back</a>
    </nav>
    <div class="card device-focus-layout">
      <div class="device-focus-left">
        <div class="row" style="align-items:flex-start;flex-wrap:wrap;gap:10px">
          <div class="device-page-head" style="flex:1;min-width:0">
            <div class="device-primary-name">${escapeHtml(d.display_label || id)}</div>
            ${d.display_label ? `<div class="device-id-sub mono">${escapeHtml(id)}</div>` : ""}
          </div>
          <span class="badge ${dm.on ? "online" : "offline"}" id="devOnlineBadge">${dm.on ? "online" : "offline"}</span>
          <span class="chip" id="devReasonChip">${escapeHtml(reasonEn[dm.reason] || dm.reason)}</span>
          ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
        </div>
        <div class="device-hero-card">
          <div class="device-thumb">${escapeHtml((d.display_label || id || "?").slice(0, 1).toUpperCase())}</div>
          <div class="device-hero-meta">
            <div class="device-hero-line device-hero-line--fw">
              <span class="muted">Firmware</span>
              <div class="device-hero-fw">
                <span class="mono" id="devFwVer">${escapeHtml(d.fw || "\u2014")}</span>
                <span class="device-fw-state" id="devFwStatus" aria-live="polite">\u2014</span>
                <button type="button" class="btn sm secondary fw-hint-cta" id="devFwHintBtn" style="display:${d.firmware_hint && d.firmware_hint.update_available && firmwareHintStillValid(d.fw, d.firmware_hint) ? "inline-flex" : "none"}" title="New firmware on server / \u670D\u52A1\u5668\u6709\u65B0\u56FA\u4EF6">\u66F4\u65B0</button>
              </div>
            </div>
            <div class="device-hero-line"><span class="muted">Platform</span><span class="mono">${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}</span></div>
            <div class="device-hero-line"><span class="muted">Network</span><span class="mono" id="devNetRow">${escapeHtml(d.net_type || "\u2014")} \xB7 ${escapeHtml(dm.s.ip || "\u2014")}</span></div>
            <div class="device-hero-line"><span class="muted">Wi\u2011Fi</span><span id="devWifiSsid">${dm.wifiSsidDd}</span></div>
            <div class="device-hero-line"><span class="muted">Output V</span><span class="mono" id="devOutV">${escapeHtml(dm.outV)}</span></div>
            <div class="device-hero-line"><span class="muted">Tx / Rx</span><span class="mono" id="devTxRx">${escapeHtml(bps(dm.s.tx_bps))} / ${escapeHtml(bps(dm.s.rx_bps))}</span></div>
            <div class="device-hero-line"><span class="muted">RSSI</span><span class="mono" id="devRssi">${escapeHtml(dm.rssi)}</span></div>
            <div class="device-hero-line"><span class="muted">Wi\u2011Fi CH</span><span class="mono" id="devWifiCh">${dm.wifiChDd}</span></div>
            <div class="device-hero-line"><span class="muted">Uptime</span><span class="mono" id="devUptime">${escapeHtml(dm.s.uptime_s ? `${Math.floor(dm.s.uptime_s / 3600)}h ${Math.floor(dm.s.uptime_s % 3600 / 60)}m` : "\u2014")}</span></div>
            <div class="device-hero-line"><span class="muted">Heap</span><span class="mono" id="devHeap">${escapeHtml(dm.s.free_heap ? `${dm.s.free_heap} B (min ${dm.s.min_free_heap || "?"} B)` : "\u2014")}</span></div>
            <div class="device-hero-line"><span class="muted">Disconnect</span><span class="mono" id="devDisconnect">${escapeHtml(dm.reason)}</span></div>
            <div class="device-hero-line"><span class="muted">Updated</span><span id="devUpdated">${escapeHtml(fmtTs(d.updated_at))} (${escapeHtml(fmtRel(d.updated_at))})</span></div>
          </div>
        </div>
      </div>
      <aside class="device-focus-right">
        <div class="card" style="margin:0">
          <h3 style="margin:0 0 8px">Ownership</h3>
          <p class="muted" style="margin:0 0 8px">Current account binding for this device.</p>
          <div class="device-owner-kv">
            <div><span class="muted">Account</span><span class="mono">${escapeHtml(d.owner_admin || d.shared_by || "\u2014")}</span></div>
            <div><span class="muted">Email</span><span class="mono">${escapeHtml(d.owner_email || "\u2014")}</span></div>
            <div><span class="muted">Shared</span><span class="mono">${d.is_shared ? `yes \xB7 by ${escapeHtml(d.shared_by || "?")}` : "no"}</span></div>
          </div>
        </div>
        <div class="card" style="margin:12px 0 0">
          <h3 style="margin:0 0 8px;font-size:13px;color:var(--text-muted)">Notifications</h3>
          ${d.is_shared ? `<p class="muted" style="margin:0 0 8px">Device share is <strong>device-scoped</strong> only. You cannot see or edit the owner&rsquo;s notification group; use your own tenant group cards or single-device actions.</p>` : ""}
          <div class="row" style="gap:10px;align-items:flex-end;flex-wrap:wrap">
            <label class="field grow"><span>Display name</span>
              <input id="dispLabel" value="${escapeHtml(d.display_label || "")}" maxlength="80" />
            </label>
            <label class="field grow"><span>Notification group</span>
              <input id="notifGroup" value="${escapeHtml(d.notification_group || "")}" maxlength="80" placeholder="e.g. Warehouse A" ${d.is_shared ? 'disabled title="Owner tenant only"' : ""} />
            </label>
            <button class="btn secondary btn-tap" type="button" id="saveProfile">Save</button>
          </div>
        </div>
      </aside>
    </div>

    <div class="split device-quick-split">
      <div class="card">
        <h3>Quick actions</h3>
        ${d.is_shared ? `<p class="muted" style="margin:0 0 8px">Shared by <span class="mono">${escapeHtml(d.shared_by || "?")}</span>. Delete/Revoke actions are disabled for shared devices.</p>` : ""}
        <div class="row">
          <button class="btn" id="alertOn" ${can("can_alert") ? "" : "disabled"}>Siren ON</button>
          <button class="btn secondary" id="alertOff" ${can("can_alert") ? "" : "disabled"}>Siren OFF</button>
          <button class="btn secondary" id="selfTest" ${can("can_send_command") && canOperateThisDevice ? "" : "disabled"}>Self-test</button>
        </div>
        <div class="row" style="margin-top:10px">
          <input id="rebootDelay" placeholder="Delay seconds (e.g. 30)" style="max-width:200px" />
          <button class="btn secondary" id="doReboot" ${can("can_send_command") && canOperateThisDevice ? "" : "disabled"}>Schedule reboot</button>
        </div>
        <div class="row" style="margin-top:14px">
          <button class="btn secondary" id="unrevoke" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Unrevoke</button>
        </div>
      </div>
    </div>
    ${sharePanel}

    <details class="card device-drawer" id="wifiCtlCard">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Wi\u2011Fi (device)</span>
        <span class="device-drawer__hint muted">Provision \xB7 NVS \xB7 expand</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0 0 10px">Credentials are written to device NVS, then the board reboots. Optional <strong>follow\u2011up commands</strong> are stored in NVS and run <strong>in order</strong> after Wi\u2011Fi + MQTT reconnect \u2014 no second dashboard click (safe cmds only: get_info, ping, self_test, set_param).</p>
        ${can("can_send_command") && canOperateThisDevice ? `
        <div class="inline-form" style="margin-top:4px">
          <label class="field grow"><span>New SSID</span><input id="wifiNewSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz network name" /></label>
          <label class="field grow"><span>Password</span><input id="wifiNewPass" type="password" maxlength="64" autocomplete="new-password" placeholder="empty if open network" /></label>
          <div class="field" style="margin-top:10px">
            <span>After reconnect (stored on device, sequential)</span>
            <div class="row" style="gap:14px;flex-wrap:wrap;margin-top:6px">
              <label><input type="checkbox" id="wifiChainGetInfo" checked /> <span class="mono">get_info</span> (status)</label>
              <label><input type="checkbox" id="wifiChainPing" checked /> <span class="mono">ping</span></label>
              <label><input type="checkbox" id="wifiChainSelfTest" /> <span class="mono">self_test</span></label>
            </div>
          </div>
          <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:8px">
            <button class="btn btn-tap" type="button" id="wifiApplyBtn">Start provision task</button>
          </div>
        </div>
        <div style="margin-top:8px">
          <progress id="wifiTaskProgress" value="0" max="100" style="width:100%;height:12px"></progress>
        </div>
        <p class="muted" id="wifiScanStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span> and <strong>operate</strong> access on this device (tenant owner, admin, or shared grant with Operate).</p>`}
      </div>
    </details>

    <details class="card danger-zone danger-zone--compact device-drawer">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Danger zone</span>
        <span class="device-drawer__hint muted">Unbind &amp; reset</span>
      </summary>
      <div class="device-drawer__body danger-zone-body">
        <p class="muted danger-zone-compact-lead">Removes this device from your tenant and sends <span class="mono">unclaim_reset</span> when online. Re-add from Activate.</p>
        <div class="danger-zone-single-action">
          <button class="btn danger sm danger-zone-unbind-btn" type="button" id="deleteReset" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Unbind &amp; reset</button>
        </div>
      </div>
    </details>

    ${d.is_shared ? `
    <details class="card device-drawer" id="triggerPolicyCard">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Trigger policy</span>
        <span class="device-drawer__hint muted">Owner tenant only</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0">Sibling / group trigger policy is managed by the <strong>owning tenant</strong> only. Device share does not expose group policy.</p>
      </div>
    </details>` : `
    <details class="card device-drawer" id="triggerPolicyCard">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Trigger policy</span>
        <span class="device-drawer__hint muted">Server \xB7 group scope \xB7 expand</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0 0 10px">Scope: owner account + group <span class="mono">${escapeHtml(d.notification_group || "(default)")}</span>. Siblings = same tenant + same <span class="mono">notification_group</span> (server normalizes spacing/case). Remote #1 = silent; #2 = loud to siblings; panic = local + optional sibling siren.</p>
        ${can("can_send_command") && canOperateThisDevice ? `
        <div class="inline-form" style="margin-top:4px;gap:12px;flex-wrap:wrap;align-items:flex-end">
          <label class="field"><span>Panic local</span><input type="checkbox" id="tpPanicLocal" title="Sound on device that pressed panic" /></label>
          <label class="field"><span>Panic \u2192 siblings</span><input type="checkbox" id="tpPanicLink" title="MQTT siren to same-group devices" /></label>
          <label class="field"><span>Remote silent link</span><input type="checkbox" id="tpSilentLink" /></label>
          <label class="field"><span>Remote loud link</span><input type="checkbox" id="tpLoudLink" /></label>
          <label class="field"><span>Exclude self</span><input type="checkbox" id="tpExcludeSelf" /></label>
          <label class="field"><span>Loud (min)</span><input id="tpLoudMin" type="number" min="0.5" max="5" step="0.5" value="3" title="Remote / #2 sibling siren length" /></label>
          <label class="field"><span>Panic sibling (min)</span><input id="tpPanicMin" type="number" min="0.5" max="10" step="0.5" value="5" title="Panic MQTT sibling siren length" /></label>
          <div class="row wide" style="justify-content:flex-end;flex-basis:100%">
            <button class="btn secondary btn-tap" type="button" id="tpRefresh">Refresh</button>
            <button class="btn btn-tap" type="button" id="tpSave">Save</button>
          </div>
        </div>
        <p class="muted" id="tpStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span> and <strong>operate</strong> access on this device.</p>`}
      </div>
    </details>`}

    ${rawCommandDrawer}

    ${mqttMsgPanel}`);
    const patchDeviceLive = (dev) => {
      const m = deviceLiveModel(dev);
      const onlineBadge = $("#devOnlineBadge", view);
      if (onlineBadge) {
        onlineBadge.textContent = m.on ? "online" : "offline";
        onlineBadge.className = `badge ${m.on ? "online" : "offline"}`;
      }
      const reasonChip = $("#devReasonChip", view);
      if (reasonChip) reasonChip.textContent = String(reasonEn[m.reason] || m.reason);
      const setText = (idSel, txt) => {
        const el = $(idSel, view);
        if (el) el.textContent = String(txt);
      };
      const setHtml = (idSel, txt) => {
        const el = $(idSel, view);
        if (el) setChildMarkup(el, String(txt));
      };
      setText("#devNetRow", `${dev.net_type || "\u2014"} \xB7 ${m.s.ip || "\u2014"}`);
      setHtml("#devWifiSsid", m.wifiSsidDd);
      setHtml("#devWifiCh", m.wifiChDd);
      setText("#devRssi", m.rssi);
      setText("#devOutV", m.outV);
      setText("#devTxRx", `${bps(m.s.tx_bps)} / ${bps(m.s.rx_bps)}`);
      setText("#devDisconnect", m.reason);
      setText("#devUptime", m.s.uptime_s ? `${Math.floor(m.s.uptime_s / 3600)}h ${Math.floor(m.s.uptime_s % 3600 / 60)}m` : "\u2014");
      setText("#devHeap", m.s.free_heap ? `${m.s.free_heap} B (min ${m.s.min_free_heap || "?"} B)` : "\u2014");
      setText("#devUpdated", `${fmtTs(dev.updated_at)} (${fmtRel(dev.updated_at)})`);
      syncDevicePageFirmwareHint(view, dev, id);
    };
    patchDeviceLive(d);
    scheduleRouteTicker(routeSeq, `device-live-${id}`, async () => {
      if (!isRouteCurrent(routeSeq)) return;
      const latest = await apiGetCached(`/devices/${encodeURIComponent(id)}`, { timeoutMs: 16e3 }, 5e3);
      if (!isRouteCurrent(routeSeq) || !latest) return;
      d = latest;
      patchDeviceLive(latest);
    }, 12e3);
    if (isSuperViewer) {
      const det = $("#mqttMsgDetails", view);
      const box = $("#devMsgsList", view);
      let loaded = false;
      const loadDebugMsgs = async () => {
        if (loaded || !box) return;
        loaded = true;
        setChildMarkup(box, `<p class="muted">Loading\u2026</p>`);
        try {
          const msgs = await api(`/devices/${encodeURIComponent(id)}/messages?limit=25`, { timeoutMs: 16e3 });
          setChildMarkup(box, renderMsgFeed(msgs.items || []));
        } catch (e) {
          setChildMarkup(box, `<p class="badge offline">${escapeHtml(e.message || e)}</p>`);
        }
      };
      if (det) {
        det.addEventListener("toggle", () => {
          if (det.open) loadDebugMsgs();
        });
      }
    }
    $("#saveProfile").addEventListener("click", async () => {
      try {
        const body = { display_label: ($("#dispLabel").value || "").trim() };
        if (!d.is_shared) {
          body.notification_group = canonicalGroupKey($("#notifGroup") && $("#notifGroup").value || "");
        }
        await api(`/devices/${encodeURIComponent(id)}/profile`, {
          method: "PATCH",
          body
        });
        if (!d.is_shared) {
          reconcileGroupMetaForDevice(id, body.notification_group || "", d.owner_admin);
        }
        toast("Saved", "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    const withDev = (fn) => async () => {
      try {
        await fn();
        toast("Sent", "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    };
    $("#alertOn").addEventListener("click", withDev(() => api(`/devices/${encodeURIComponent(id)}/alert/on?duration_ms=${DEFAULT_REMOTE_SIREN_MS}`, { method: "POST" })));
    $("#alertOff").addEventListener("click", withDev(() => api(`/devices/${encodeURIComponent(id)}/alert/off`, { method: "POST" })));
    $("#selfTest").addEventListener("click", withDev(() => api(`/devices/${encodeURIComponent(id)}/self-test`, { method: "POST" })));
    $("#doReboot").addEventListener("click", withDev(() => {
      const v = parseInt($("#rebootDelay").value, 10);
      if (!Number.isFinite(v) || v < 5) throw new Error("delay must be >= 5 seconds");
      return api(`/devices/${encodeURIComponent(id)}/schedule-reboot`, { method: "POST", body: { delay_s: v } });
    }));
    $("#unrevoke").addEventListener("click", withDev(async () => {
      await api(`/devices/${encodeURIComponent(id)}/unrevoke`, { method: "POST" });
      bustDeviceListCaches();
    }));
    const deleteResetBtn = $("#deleteReset", view);
    if (deleteResetBtn) {
      deleteResetBtn.addEventListener("click", async () => {
        if (!confirm("Delete this device from current account records? You can re-add and reconfigure later.")) return;
        const typed = String(prompt(`Type device ID to confirm delete/reset:
${id}`) || "").trim();
        if (typed.toUpperCase() !== String(id).toUpperCase()) {
          toast("Confirmation mismatch", "err");
          return;
        }
        try {
          const dr = await api(`/devices/${encodeURIComponent(id)}/delete-reset`, {
            method: "POST",
            body: { confirm_text: typed }
          });
          removeDeviceIdFromAllGroupMeta(id);
          bustDeviceListCaches();
          const sentNv = dr && dr.nvs_purge_sent === true;
          const ackNv = dr && dr.nvs_purge_acked === true;
          toast(
            `Device removed from account.${ackNv ? " Device confirmed unclaim_reset (WiFi+claim cleared, rebooting)." : sentNv ? " Command was dispatched but device ack not confirmed before unlink." : " Command dispatch failed/offline."} Re-add from Activate.`,
            ackNv ? "ok" : "err"
          );
          location.hash = "#/devices";
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
    const sendCmdBtn = $("#sendCmd");
    if (sendCmdBtn) {
      sendCmdBtn.addEventListener("click", async () => {
        const name = ($("#cmdName").value || "").trim();
        if (!name) {
          toast("Enter cmd", "err");
          return;
        }
        let params = {};
        const raw = ($("#cmdParams").value || "").trim();
        if (raw) {
          try {
            params = JSON.parse(raw);
          } catch {
            toast("Invalid JSON in params", "err");
            return;
          }
        }
        try {
          await api(`/devices/${encodeURIComponent(id)}/commands`, { method: "POST", body: { cmd: name, params } });
          toast("Command sent", "ok");
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
    const wifiApplyBtn = $("#wifiApplyBtn");
    try {
      const rawPf = sessionStorage.getItem("croc.deviceWifiPrefill.v1");
      if (rawPf) {
        const pf = JSON.parse(rawPf);
        const match = pf && String(pf.device_id || "").toUpperCase() === String(id).toUpperCase();
        if (match && pf.ssid) {
          const wS = $("#wifiNewSsid", view);
          const wP = $("#wifiNewPass", view);
          const card = $("#wifiCtlCard", view);
          if (wS) wS.value = String(pf.ssid);
          if (wP) wP.value = String(pf.password || "");
          sessionStorage.removeItem("croc.deviceWifiPrefill.v1");
          if (card) card.open = true;
          toast("Prefilled Wi\u2011Fi from Activate page \u2014 start provision below when the device is online.", "ok");
        }
      }
    } catch (_) {
    }
    const wifiTaskProgress = $("#wifiTaskProgress");
    const setWifiProgress = (n) => {
      if (!wifiTaskProgress) return;
      const v = Math.max(0, Math.min(100, Number(n || 0)));
      wifiTaskProgress.value = v;
    };
    const pollWifiTask = async (taskId) => runPollDedup(`wifi-task:${id}:${String(taskId || "")}`, async () => {
      const st = $("#wifiScanStatus");
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 1e3));
        try {
          const t = await api(`/devices/${encodeURIComponent(id)}/provision/wifi-task/${encodeURIComponent(taskId)}`, { timeoutMs: 16e3 });
          setWifiProgress(t.progress || 0);
          if (st) st.textContent = String(t.message || t.status || "");
          if (t.status === "success") {
            toast("Provision success", "ok");
            return;
          }
          if (t.status === "failed") {
            toast(t.message || "Provision failed", "err");
            return;
          }
        } catch (e) {
          if (st) st.textContent = String(e.message || e);
        }
      }
      if (st) st.textContent = "Timed out waiting task result";
      toast("Provision task timeout", "err");
    });
    if (wifiApplyBtn) {
      wifiApplyBtn.addEventListener("click", async () => {
        const ssid = ($("#wifiNewSsid", view).value || "").trim();
        const password = $("#wifiNewPass", view).value || "";
        const st = $("#wifiScanStatus", view);
        if (!ssid) {
          toast("Enter SSID", "err");
          return;
        }
        if (!confirm("Save Wi\u2011Fi on device and reboot? You may lose contact until it joins the new network.")) return;
        try {
          wifiApplyBtn.disabled = true;
          setWifiProgress(10);
          if (st) st.textContent = "Creating provision task\u2026";
          const chain = [];
          const cGi = $("#wifiChainGetInfo", view);
          const cPi = $("#wifiChainPing", view);
          const cSt = $("#wifiChainSelfTest", view);
          if (cGi && cGi.checked) chain.push({ cmd: "get_info", params: {} });
          if (cPi && cPi.checked) chain.push({ cmd: "ping", params: {} });
          if (cSt && cSt.checked) chain.push({ cmd: "self_test", params: {} });
          const body = { ssid, password };
          if (chain.length) body.chain = chain;
          const r = await api(`/devices/${encodeURIComponent(id)}/provision/wifi-task`, {
            method: "POST",
            body
          });
          setWifiProgress(r.progress || 35);
          if (st) st.textContent = `Task ${r.task_id} running\u2026`;
          await pollWifiTask(r.task_id);
        } catch (e) {
          toast(e.message || e, "err");
          if (st) st.textContent = String(e.message || e);
        } finally {
          wifiApplyBtn.disabled = false;
        }
      });
    }
    const tpPanicLocal = $("#tpPanicLocal");
    const tpPanicLink = $("#tpPanicLink");
    const tpSilentLink = $("#tpSilentLink");
    const tpLoudLink = $("#tpLoudLink");
    const tpExcludeSelf = $("#tpExcludeSelf");
    const tpLoudMin = $("#tpLoudMin");
    const tpPanicMin = $("#tpPanicMin");
    const tpStatus = $("#tpStatus");
    const loadTriggerPolicy = async () => {
      if (!tpPanicLocal || !tpPanicLink || !tpSilentLink || !tpLoudLink || !tpExcludeSelf || !tpLoudMin || !tpPanicMin) return;
      try {
        if (tpStatus) tpStatus.textContent = "Loading policy\u2026";
        const r = await api(`/devices/${encodeURIComponent(id)}/trigger-policy`, { timeoutMs: 16e3 });
        const p = r.policy || {};
        tpPanicLocal.checked = !!p.panic_local_siren;
        if (tpPanicLink) tpPanicLink.checked = p.panic_link_enabled !== false;
        tpSilentLink.checked = !!p.remote_silent_link_enabled;
        tpLoudLink.checked = !!p.remote_loud_link_enabled;
        tpExcludeSelf.checked = !!p.fanout_exclude_self;
        const loudMs = Number(p.remote_loud_duration_ms || DEFAULT_REMOTE_SIREN_MS);
        const panicMs = Number(p.panic_fanout_duration_ms || DEFAULT_PANIC_FANOUT_MS);
        tpLoudMin.value = String(Math.round(Math.max(0.5, Math.min(5, loudMs / 6e4)) * 10) / 10);
        tpPanicMin.value = String(Math.round(Math.max(0.5, Math.min(10, panicMs / 6e4)) * 10) / 10);
        if (tpStatus) tpStatus.textContent = `Loaded for group ${r.scope_group || "(default)"}`;
      } catch (e) {
        if (tpStatus) tpStatus.textContent = String(e.message || e);
      }
    };
    const tpRefresh = $("#tpRefresh");
    if (tpRefresh) tpRefresh.addEventListener("click", () => loadTriggerPolicy());
    const tpSave = $("#tpSave");
    if (tpSave) {
      tpSave.addEventListener("click", async () => {
        try {
          const lm = parseFloat(tpLoudMin && tpLoudMin.value || "3", 10);
          const pm = parseFloat(tpPanicMin && tpPanicMin.value || "5", 10);
          if (!Number.isFinite(lm) || lm < 0.5 || lm > 5) throw new Error("Loud duration must be 0.5\u20135 minutes");
          if (!Number.isFinite(pm) || pm < 0.5 || pm > 10) throw new Error("Panic sibling duration must be 0.5\u201310 minutes");
          const remote_loud_duration_ms = Math.round(lm * 6e4);
          const panic_fanout_duration_ms = Math.round(pm * 6e4);
          if (tpStatus) tpStatus.textContent = "Saving policy\u2026";
          await api(`/devices/${encodeURIComponent(id)}/trigger-policy`, {
            method: "PUT",
            body: {
              panic_local_siren: !!(tpPanicLocal && tpPanicLocal.checked),
              panic_link_enabled: !!(tpPanicLink && tpPanicLink.checked),
              remote_silent_link_enabled: !!(tpSilentLink && tpSilentLink.checked),
              remote_loud_link_enabled: !!(tpLoudLink && tpLoudLink.checked),
              fanout_exclude_self: !!(tpExcludeSelf && tpExcludeSelf.checked),
              remote_loud_duration_ms,
              panic_fanout_duration_ms
            }
          });
          if (tpStatus) tpStatus.textContent = "Policy saved";
          toast("Trigger policy saved", "ok");
        } catch (e) {
          if (tpStatus) tpStatus.textContent = String(e.message || e);
          toast(e.message || e, "err");
        }
      });
      loadTriggerPolicy();
    }
    const shareListEl = $("#shareList");
    const renderShares = async () => {
      if (!shareListEl) return;
      setChildMarkup(shareListEl, `<p class="muted">Loading shares\u2026</p>`);
      try {
        const r = await api(`/admin/devices/${encodeURIComponent(id)}/shares`, { timeoutMs: 16e3 });
        const items = r.items || [];
        setChildMarkup(
          shareListEl,
          `
        <div class="table-wrap"><table class="t">
          <thead><tr><th>User</th><th>Role</th><th>View</th><th>Operate</th><th>Granted by</th><th>Granted at</th><th>Status</th><th></th></tr></thead>
          <tbody>${items.length === 0 ? `<tr><td colspan="8" class="muted">No shares</td></tr>` : items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.grantee_username || "")}</td>
                  <td>${escapeHtml(it.grantee_role || "\u2014")}</td>
                  <td>${it.can_view ? "yes" : "no"}</td>
                  <td>${it.can_operate ? "yes" : "no"}</td>
                  <td class="mono">${escapeHtml(it.granted_by || "")}</td>
                  <td>${escapeHtml(fmtTs(it.granted_at))}</td>
                  <td>${it.revoked_at ? `<span class="badge offline">revoked</span>` : `<span class="badge online">active</span>`}</td>
                  <td>${it.revoked_at ? "" : `<button class="btn ghost shareRevokeBtn" data-user="${escapeHtml(it.grantee_username || "")}">Revoke</button>`}</td>
                </tr>
              `).join("")}</tbody>
        </table></div>
      `
        );
        $$(".shareRevokeBtn", shareListEl).forEach((btn) => {
          btn.addEventListener("click", async () => {
            const u = btn.getAttribute("data-user") || "";
            if (!u) return;
            if (!confirm(`Revoke share for ${u}?`)) return;
            try {
              await api(`/admin/devices/${encodeURIComponent(id)}/share/${encodeURIComponent(u)}`, { method: "DELETE" });
              toast("Share revoked", "ok");
              await renderShares();
            } catch (e) {
              toast(e.message || e, "err");
            }
          });
        });
      } catch (e) {
        setChildMarkup(shareListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    };
    const shareGrantBtn = $("#shareGrant");
    if (shareGrantBtn) {
      shareGrantBtn.addEventListener("click", async () => {
        const grantee = ($("#shareUser").value || "").trim();
        const canView = !!$("#shareCanView").checked;
        const canOperate = !!$("#shareCanOperate").checked;
        if (!grantee) {
          toast("Enter grantee username", "err");
          return;
        }
        if (!canView && !canOperate) {
          toast("Select view and/or operate", "err");
          return;
        }
        try {
          await api(`/admin/devices/${encodeURIComponent(id)}/share`, {
            method: "POST",
            body: { grantee_username: grantee, can_view: canView, can_operate: canOperate }
          });
          toast("Share granted", "ok");
          await renderShares();
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
    const shareRefreshBtn = $("#shareRefresh");
    if (shareRefreshBtn) {
      shareRefreshBtn.addEventListener("click", () => renderShares());
      renderShares();
    }
  });
  registerRoute("events", async (view, _args) => {
    const navTok = state.routeSeq;
    setCrumb("Events");
    const me = state.me || { username: "", role: "" };
    const isSuper = me.role === "superadmin";
    const scopeLabel = isSuper ? "System-wide" : me.role === "admin" ? "Your tenant" : "Your account";
    mountView(view, `
    <div class="ui-shell card audit-page" style="margin:0">
      <div class="row between" style="flex-wrap:wrap;gap:10px">
        <div>
          <h2 class="ui-section-title" style="margin:0">Event center</h2>
          <p class="muted" style="margin:4px 0 0">Visibility: ${scopeLabel}.</p>
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
        <label class="field"><span>Device ID</span><input id="evDevice" placeholder="SN-\u2026 or id" /></label>
        <label class="field wide"><span>Search</span><input id="evQ" placeholder="summary / actor / event_type" /></label>
        <div class="row wide action-bar" style="justify-content:flex-end;gap:8px;flex-wrap:wrap">
          <button class="btn sm" id="evApply">Apply & reload</button>
          <details class="toolbar-collapse" style="min-width:160px">
            <summary>More tools</summary>
            <div class="table-actions">
              <button class="btn sm secondary" id="evStats">By device (7d)</button>
              <button class="btn sm secondary" id="evCsv">Export CSV</button>
              <button class="btn sm secondary" id="evReload">Last 200</button>
            </div>
          </details>
        </div>
      </div>
    </div>
    <div id="evStatsBox" class="card" style="margin-top:12px;display:none">
      <h3 style="margin:0 0 8px">Events per device (7 days)</h3>
      <div id="evStatsInner" class="muted">\u2014</div>
    </div>
    <div class="ui-shell card audit-page" style="margin-top:12px">
      <div id="evList" class="audit-feed-wrap muted">Connecting\u2026</div>
    </div>`);
    let paused = false;
    let buffer = [];
    const BUFFER_MAX = 180;
    const RENDER_LIMIT = 150;
    let evRenderTimer = 0;
    let evReconnectBackoffMs = 800;
    function badgeClass(lvl) {
      return {
        debug: "neutral",
        info: "accent",
        warn: "partial",
        error: "failed",
        critical: "revoked"
      }[lvl] || "neutral";
    }
    function catClass(cat) {
      return {
        alarm: "failed",
        ota: "accent",
        presence: "partial",
        provision: "accent",
        device: "neutral",
        auth: "partial",
        audit: "neutral",
        system: "neutral"
      }[cat] || "neutral";
    }
    function rowHtml(e) {
      const primary = e.summary && String(e.summary).trim() || (e.event_type || "\u2014");
      const tsShort = fmtTs(e.ts_malaysia || e.ts);
      const typeDiffers = e.event_type && String(e.event_type) !== String(primary);
      const extras = eventDetailDedupedRows(
        e.detail && typeof e.detail === "object" && !Array.isArray(e.detail) ? e.detail : {},
        e
      );
      const devLink = e.device_id ? `<a class="mono audit-target" href="#/devices/${encodeURIComponent(e.device_id)}">${escapeHtml(e.device_id)}</a>` : "";
      const targetStr = e.target && e.target !== e.device_id ? String(e.target) : "";
      const typeTag = typeDiffers ? ` \xB7 <span class="mono" style="font-size:12px;opacity:0.88">${escapeHtml(e.event_type)}</span>` : "";
      const extraBlock = extras.length ? `<div class="audit-extra">${extras.map(
        (row) => `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`
      ).join("")}</div>` : "";
      return `<details class="audit-item audit-item--foldable" data-level="${escapeHtml(e.level || "")}">
      <summary class="audit-item__fold-sum">
      <div class="audit-item-top">
        <div class="audit-time">
          <span class="audit-ts mono">${escapeHtml(tsShort)}</span>
          <span class="muted audit-rel">${escapeHtml(fmtRel(e.ts))}</span>
        </div>
        <span class="badge ${badgeClass(e.level)}">${escapeHtml(e.level || "")}</span>
        <span class="badge ${catClass(e.category)}">${escapeHtml(e.category || "")}</span>
      </div>
      <div class="audit-item-line audit-item__fold-primary" style="font-weight:600;margin-top:8px">${escapeHtml(primary)}${typeTag}</div>
      </summary>
      <div class="audit-item__fold-body">
      <div class="audit-item-line" style="font-size:12.5px;flex-wrap:wrap">
        <span class="audit-actor">${e.actor ? escapeHtml(e.actor) : "\u2014"}</span>
        ${targetStr ? ` <span class="audit-arrow">\u2192</span> <span class="mono audit-target">${escapeHtml(targetStr)}</span>` : ""}
        ${devLink ? ` \xB7 ${devLink}` : ""}
        ${e.owner_admin ? ` <span class="chip" title="owner_admin">@${escapeHtml(e.owner_admin)}</span>` : ""}
      </div>
      ${extraBlock}
      </div>
    </details>`;
    }
    function flushEvRender() {
      evRenderTimer = 0;
      const listEl = document.getElementById("evList");
      if (!listEl) return;
      if (buffer.length === 0) {
        setHtmlIfChanged(listEl, `<p class="muted audit-empty">No events.</p>`);
        return;
      }
      const visible = buffer.slice(0, RENDER_LIMIT);
      setHtmlIfChanged(listEl, `<div class="audit-feed">${visible.map(rowHtml).join("")}</div>`);
    }
    function scheduleEvRender() {
      if (evRenderTimer) return;
      evRenderTimer = setTimeout(flushEvRender, 120);
    }
    function pushEvent(ev) {
      if (paused) return;
      let row = ev;
      try {
        if (ev && ev.detail != null && typeof ev.detail === "object") {
          const sj = JSON.stringify(ev.detail);
          if (sj.length > 12e3) {
            row = Object.assign({}, ev, {
              detail: { _truncated: true, _approx_bytes: sj.length }
            });
          }
        }
      } catch (_) {
      }
      buffer.unshift(row);
      if (buffer.length > BUFFER_MAX) buffer.length = BUFFER_MAX;
      scheduleEvRender();
    }
    function currentFilters() {
      const p = new URLSearchParams();
      const lvl = $("#evLevel").value.trim();
      if (lvl) p.set("min_level", lvl);
      const cat = $("#evCategory").value.trim();
      if (cat) p.set("category", cat);
      const dev = $("#evDevice").value.trim();
      if (dev) p.set("device_id", dev);
      const q = $("#evQ").value.trim();
      if (q) p.set("q", q);
      return p;
    }
    async function loadHistory() {
      try {
        if (!isRouteCurrent(navTok)) return;
        const p = currentFilters();
        p.set("limit", "200");
        const r = await api("/events?" + p.toString(), { timeoutMs: 16e3 });
        if (!isRouteCurrent(navTok)) return;
        buffer = (r.items || []).slice();
        if (buffer.length > BUFFER_MAX) buffer = buffer.slice(0, BUFFER_MAX);
        if (evRenderTimer) {
          clearTimeout(evRenderTimer);
          evRenderTimer = 0;
        }
        flushEvRender();
      } catch (e) {
        if (!isRouteCurrent(navTok)) return;
        const listEl = document.getElementById("evList");
        if (listEl) mountView(listEl, hx`<p class="badge offline">${e.message || e}</p>`);
        toast(e.message || e, "err");
      }
    }
    function closeStream() {
      if (window.__evReconnectTimer) {
        try {
          clearTimeout(window.__evReconnectTimer);
        } catch (_) {
        }
        window.__evReconnectTimer = 0;
      }
      if (window.__evSSE) {
        try {
          window.__evSSE.close();
        } catch (_) {
        }
        window.__evSSE = null;
      }
      if (window.__evFetchAbort) {
        try {
          window.__evFetchAbort.abort();
        } catch (_) {
        }
        window.__evFetchAbort = null;
      }
      const live = $("#evLive");
      if (live) {
        live.textContent = "Offline";
        live.className = "badge offline";
      }
    }
    function openStream() {
      if (!isRouteCurrent(navTok)) return;
      closeStream();
      const p = currentFilters();
      const slack = Math.max(0, BUFFER_MAX - buffer.length);
      p.set("backlog", String(Math.min(100, slack)));
      const qs = p.toString();
      const tok = getToken();
      const ac = new AbortController();
      window.__evFetchAbort = ac;
      const shim = {
        readyState: EventSource.CONNECTING,
        close() {
          try {
            ac.abort();
          } catch (_) {
          }
          window.__evFetchAbort = null;
          this.readyState = EventSource.CLOSED;
        }
      };
      window.__evSSE = shim;
      const scheduleReconnect = () => {
        if (!isRouteCurrent(navTok) || paused || window.__evReconnectTimer) return;
        const wait = evReconnectBackoffMs + Math.floor(Math.random() * 480);
        window.__evReconnectTimer = setTimeout(() => {
          window.__evReconnectTimer = 0;
          if (!isRouteCurrent(navTok) || paused) return;
          openStream();
        }, wait);
        evReconnectBackoffMs = Math.min(8e3, Math.floor(evReconnectBackoffMs * 1.5));
      };
      const run = async () => {
        const url = apiBase() + "/events/stream" + (qs ? "?" + qs : "");
        const hdrs = {
          Accept: "text/event-stream",
          "Cache-Control": "no-store"
        };
        if (tok) hdrs.Authorization = "Bearer " + tok;
        try {
          const r = await fetch(url, {
            method: "GET",
            credentials: "include",
            headers: hdrs,
            signal: ac.signal
          });
          if (!isRouteCurrent(navTok)) return;
          if (!r.ok) {
            const errText = await r.text().catch(() => "");
            throw new Error(errText || String(r.status));
          }
          if (!r.body || typeof r.body.getReader !== "function") {
            throw new Error("Event stream unsupported in this browser");
          }
          evReconnectBackoffMs = 800;
          shim.readyState = EventSource.OPEN;
          const liveOn = $("#evLive");
          if (liveOn) {
            liveOn.textContent = "Live";
            liveOn.className = "badge online";
            liveOn.title = "Live stream connected";
          }
          await pumpSseBody(r.body.getReader(), ac.signal, (kind, payload) => {
            if (kind === "ping") return;
            if (!isRouteCurrent(navTok)) return;
            try {
              const ev = JSON.parse(payload);
              if (ev.event_type === "stream.hello") return;
              pushEvent(ev);
            } catch (_) {
            }
          });
          if (ac.signal.aborted || !isRouteCurrent(navTok)) return;
          shim.readyState = EventSource.CLOSED;
          if (!paused && isRouteCurrent(navTok)) {
            evReconnectBackoffMs = 800;
            const live = $("#evLive");
            if (live) {
              live.textContent = "Reconnecting\u2026";
              live.className = "badge offline";
            }
            scheduleReconnect();
          }
        } catch (e) {
          if (e && e.name === "AbortError") return;
          if (!isRouteCurrent(navTok)) return;
          shim.readyState = EventSource.CLOSED;
          const live = $("#evLive");
          if (live && isRouteCurrent(navTok)) {
            live.textContent = "Reconnecting\u2026";
            live.className = "badge offline";
          }
          if (!paused && isRouteCurrent(navTok)) scheduleReconnect();
        }
      };
      void run();
    }
    $("#evPause").addEventListener("click", () => {
      paused = !paused;
      $("#evPause").textContent = paused ? "Resume" : "Pause";
    });
    $("#evClear").addEventListener("click", () => {
      buffer = [];
      if (evRenderTimer) {
        clearTimeout(evRenderTimer);
        evRenderTimer = 0;
      }
      flushEvRender();
    });
    $("#evApply").addEventListener("click", () => {
      loadHistory().then(openStream);
    });
    $("#evReload").addEventListener("click", loadHistory);
    $("#evStats").addEventListener("click", async () => {
      try {
        if (!isRouteCurrent(navTok)) return;
        const r = await api("/events/stats/by-device?hours=168&limit=200", { timeoutMs: 16e3 });
        const items = r.items || [];
        const evStatsBoxEl = $("#evStatsBox", view);
        const evStatsInnerEl = $("#evStatsInner", view);
        if (!evStatsBoxEl || !evStatsInnerEl || !isRouteCurrent(navTok)) return;
        evStatsBoxEl.style.display = "block";
        if (items.length === 0) {
          setChildMarkup(evStatsInnerEl, "<p class='muted'>No rows with device_id.</p>");
          return;
        }
        setChildMarkup(
          evStatsInnerEl,
          `<div class="table-wrap"><table class="t"><thead><tr><th>Device</th><th>Count</th></tr></thead><tbody>${items.map((x) => `<tr><td class="mono">${escapeHtml(x.device_id)}</td><td>${x.count}</td></tr>`).join("")}</tbody></table></div>`
        );
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $("#evCsv").addEventListener("click", async () => {
      try {
        const p = currentFilters();
        p.set("limit", "8000");
        const url = apiBase() + "/events/export.csv?" + p.toString();
        const _ex = {};
        const _t = getToken();
        if (_t) _ex.Authorization = "Bearer " + _t;
        const r = await fetch(url, { credentials: "include", headers: _ex });
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
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    await loadHistory();
    openStream();
    window.__eventsStreamResume = () => {
      if (paused) return;
      if (!isRouteCurrent(navTok)) return;
      openStream();
    };
  });
  registerRoute("forgot-password", async (view) => {
    setCrumb("Forgot password");
    document.body.dataset.auth = "none";
    let enabled = true;
    try {
      const r = await fetch(apiBase() + "/auth/forgot/email/enabled");
      const j = await r.json();
      enabled = !!j.enabled;
    } catch {
      enabled = false;
    }
    mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("recovery")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner auth-surface__inner--wide">
      <div class="auth-card auth-card--panel auth-card--wide auth-card--prose" data-auth-card>
        <header class="auth-card__head">
          <h1 class="auth-card__title">Account recovery</h1>
          <p class="auth-card__lead">Reset via email verification code</p>
        </header>
        <div class="auth-card__body">
        <p class="muted auth-card__prose">
          Enter your username and the same email used at registration.
          The server sends a SHA-style verification code to that email.
          Enter the code to set a new password (saved permanently on server).
        </p>
        ${enabled ? "" : `<p class="badge revoked" style="margin:10px 0">Email sender is not configured on server.</p>`}
        <div id="fpStep1">
          <label class="field"><span>Username</span><input id="fp_user" autocomplete="username" /></label>
          <label class="field field--spaced"><span>Registered email</span><input id="fp_email" autocomplete="email" /></label>
          <div class="auth-card__submit">
            <button class="btn btn-tap btn-block" type="button" id="fp_go" ${enabled ? "" : "disabled"}>Send SHA code</button>
            <a class="auth-link auth-link--center" href="#/login">Back to sign in</a>
          </div>
          <p class="auth-card__msg muted" id="fp_msg1" aria-live="polite"></p>
        </div>
        <div id="fpStep2" style="display:none">
          <label class="field"><span>SHA code (from email)</span>
            <input id="fp_sha_code" class="mono" maxlength="32" autocomplete="one-time-code" />
          </label>
          <label class="field field--spaced"><span>New password (\u22658)</span><input id="fp_p1" type="password" autocomplete="new-password" /></label>
          <label class="field field--spaced"><span>Confirm password</span><input id="fp_p2" type="password" autocomplete="new-password" /></label>
          <div class="auth-card__submit">
            <button class="btn btn-tap btn-block" type="button" id="fp_done">Update password</button>
            <button class="btn secondary btn-tap btn-block" type="button" id="fp_resend">Resend SHA code</button>
            <button class="btn secondary btn-tap btn-block" type="button" id="fp_back">Back</button>
          </div>
          <p class="auth-card__msg muted" id="fp_msg2" aria-live="polite"></p>
        </div>
        </div>
      </div>
      ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
    const m1 = $("#fp_msg1"), m2 = $("#fp_msg2");
    let fpCooldown = 0;
    let fpCooldownTimer = 0;
    const fpGoBtn = $("#fp_go");
    const fpResendBtn = $("#fp_resend");
    const applyFpCooldownUi = () => {
      const left = Math.max(0, Number(fpCooldown || 0));
      if (fpGoBtn) {
        fpGoBtn.disabled = !enabled || left > 0;
        fpGoBtn.textContent = left > 0 ? `Resend in ${left}s` : "Send SHA code";
      }
      if (fpResendBtn) {
        fpResendBtn.disabled = left > 0;
        fpResendBtn.textContent = left > 0 ? `Resend in ${left}s` : "Resend SHA code";
      }
    };
    const startFpCooldown = (seconds) => {
      fpCooldown = Math.max(0, Number(seconds || 0));
      applyFpCooldownUi();
      if (fpCooldownTimer) clearInterval(fpCooldownTimer);
      if (window.__fpCooldownTimer) {
        try {
          clearInterval(window.__fpCooldownTimer);
        } catch (_) {
        }
        window.__fpCooldownTimer = 0;
      }
      if (fpCooldown <= 0) return;
      fpCooldownTimer = setInterval(() => {
        fpCooldown = Math.max(0, fpCooldown - 1);
        applyFpCooldownUi();
        if (fpCooldown <= 0) {
          clearInterval(fpCooldownTimer);
          fpCooldownTimer = 0;
          window.__fpCooldownTimer = 0;
        }
      }, 1e3);
      window.__fpCooldownTimer = fpCooldownTimer;
    };
    const parseCooldownFromMessage = (msg) => {
      const m = String(msg || "").match(/wait\s+(\d+)s/i);
      return m ? Math.max(1, Number(m[1])) : 0;
    };
    const doForgotSend = async () => {
      m1.textContent = "";
      const username = $("#fp_user").value.trim();
      const email = ($("#fp_email").value || "").trim().toLowerCase();
      if (!username || !email) {
        m1.textContent = "Enter username and email";
        return false;
      }
      if (fpCooldown > 0) {
        m1.textContent = `Please wait ${fpCooldown}s before resending.`;
        return false;
      }
      const check = await fetch(apiBase() + "/auth/forgot/email/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email })
      });
      const cj = await check.json().catch(() => ({}));
      if (!check.ok) {
        const det = cj.detail;
        const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : det || check.statusText;
        throw new Error(msg);
      }
      if (!cj.matched) {
        m1.textContent = "Username and registered email do not match.";
        return false;
      }
      const preWait = Number(cj.resend_after_seconds || 0);
      if (preWait > 0) {
        startFpCooldown(preWait);
        m1.textContent = `Please wait ${preWait}s before sending again.`;
        return false;
      }
      const r = await fetch(apiBase() + "/auth/forgot/email/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email })
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        const det = d.detail;
        const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : det || r.statusText;
        const wait = parseCooldownFromMessage(msg);
        if (wait > 0) startFpCooldown(wait);
        throw new Error(msg);
      }
      const cd = Number(d.resend_after_seconds || 60);
      startFpCooldown(cd);
      m1.textContent = `Code sent. TTL ${(Number(d.ttl_seconds || 0) / 60).toFixed(0)} min.`;
      return true;
    };
    applyFpCooldownUi();
    $("#fp_go").addEventListener("click", async () => {
      try {
        const ok = await doForgotSend();
        if (!ok) return;
        $("#fpStep1").style.display = "none";
        $("#fpStep2").style.display = "block";
      } catch (e) {
        m1.textContent = String(e.message || e);
      }
    });
    if (fpResendBtn) {
      fpResendBtn.addEventListener("click", async () => {
        try {
          const ok = await doForgotSend();
          if (ok) m2.textContent = `Code resent. Wait ${fpCooldown}s before next resend.`;
        } catch (e) {
          m2.textContent = String(e.message || e);
        }
      });
    }
    $("#fp_back").addEventListener("click", () => {
      $("#fpStep2").style.display = "none";
      $("#fpStep1").style.display = "block";
      m2.textContent = "";
    });
    $("#fp_done").addEventListener("click", async () => {
      m2.textContent = "";
      const username = $("#fp_user").value.trim();
      const email = ($("#fp_email").value || "").trim().toLowerCase();
      const sha_code = ($("#fp_sha_code").value || "").trim().toUpperCase();
      const password = $("#fp_p1").value;
      const password_confirm = $("#fp_p2").value;
      if (!email || !sha_code || !password) {
        m2.textContent = "Enter email, SHA code, and password";
        return;
      }
      if (password !== password_confirm) {
        m2.textContent = "Passwords do not match";
        return;
      }
      try {
        const r = await fetch(apiBase() + "/auth/forgot/email/complete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, email, sha_code, password, password_confirm })
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
          const det = d.detail;
          const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : det || r.statusText;
          throw new Error(msg);
        }
        setChildMarkup(m2, `<span class="badge online">Password updated</span> Redirecting to sign in\u2026`);
        toast("Password updated", "ok");
        scheduleRouteRedirect(1500, "#/login");
      } catch (e) {
        m2.textContent = String(e.message || e);
      }
    });
  });
  registerRoute("group", async (view, args, routeSeq) => {
    const g = canonicalGroupKey(decodeURIComponent(args[0] || ""));
    if (!g) {
      location.hash = "#/overview";
      return;
    }
    const tenantOwner = String(window.__routeQuery && window.__routeQuery.get("owner") || "").trim();
    const metaKey = groupCardMetaKey(g, tenantOwner);
    const groupScope = state.me && state.me.username ? state.me.username : "anon";
    const GROUP_META_LS_KEY = `croc.group.meta.v2.${groupScope}`;
    const GROUP_SETTINGS_LS_KEY = `croc.group.settings.v1.${groupScope}`;
    const GROUP_API_CAPS_LS_KEY = `croc.group.api.caps.v2.${groupScope}`;
    const loadGroupMeta = () => {
      try {
        const raw = localStorage.getItem(GROUP_META_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return obj && typeof obj === "object" ? obj : {};
      } catch {
        return {};
      }
    };
    const loadGroupSettings = () => {
      try {
        const raw = localStorage.getItem(GROUP_SETTINGS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return obj && typeof obj === "object" ? obj : {};
      } catch {
        return {};
      }
    };
    const loadGroupApiCaps = () => {
      try {
        const raw = localStorage.getItem(GROUP_API_CAPS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return {
          apply: obj && obj.apply === false ? false : true,
          delete: obj && obj.delete === false ? false : true
        };
      } catch {
        return { apply: true, delete: true };
      }
    };
    const saveGroupApiCaps = (caps) => localStorage.setItem(GROUP_API_CAPS_LS_KEY, JSON.stringify({
      apply: !!(caps && caps.apply),
      delete: !!(caps && caps.delete)
    }));
    window.__groupDelayTimers = window.__groupDelayTimers || /* @__PURE__ */ new Map();
    const meta = loadGroupMeta();
    const gsMap = loadGroupSettings();
    const groupApiCaps = loadGroupApiCaps();
    setCrumb(`Group \xB7 ${(meta[metaKey] || meta[g] || {}).display_name || g}`);
    mountView(view, `
    <section class="card">
      <div class="row" style="align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <h2 style="margin:0">${escapeHtml((meta[metaKey] || meta[g] || {}).display_name || g)}</h2>
        <a href="#/overview" class="btn ghost right">\u2190 Back</a>
      </div>
      <p class="muted" style="margin-top:10px">Loading group\u2026</p>
    </section>`);
    if (!isRouteCurrent(routeSeq)) return;
    const [listRes] = await Promise.allSettled([apiGetCached("/devices", { timeoutMs: 16e3 }, 3e3)]);
    if (!isRouteCurrent(routeSeq)) return;
    let list = listRes.status === "fulfilled" && listRes.value ? listRes.value : { items: [] };
    let byId = new Map((list.items || []).map((d) => [String(d.device_id), d]));
    syncGroupMetaWithDevices(meta, list.items || []);
    try {
      localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta));
    } catch (_) {
    }
    const gm = meta[metaKey] || meta[g] || { display_name: g, owner_name: "", phone: "", email: "", device_ids: [] };
    const rowsByGroup = () => (list.items || []).filter((d) => {
      if (canonicalGroupKey(d.notification_group) !== g) return false;
      if (state.me && state.me.role === "superadmin" && tenantOwner) {
        return String(d.owner_admin || "").trim() === tenantOwner;
      }
      return true;
    });
    let rows = rowsByGroup();
    let ids = rows.map((d) => String(d.device_id || "")).filter(Boolean);
    const isSharedGroup = rows.some((d) => !!d.is_shared);
    const online = rows.filter((d) => isOnline(d)).length;
    const offline = Math.max(0, rows.length - online);
    setCrumb(`Group \xB7 ${gm.display_name || g}`);
    mountView(view, `
    <section class="card">
      <div class="row" style="align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <h2 style="margin:0;flex:1;min-width:0">${escapeHtml(gm.display_name || g)}</h2>
        <div class="row" style="gap:8px;align-items:center;flex-shrink:0;margin-left:auto">
          ${tenantOwner ? `<span class="card-owner-tag" title="Owning admin / \u6240\u5C5E\u79DF\u6237">${escapeHtml(tenantOwner)}</span>` : ""}
          <a href="#/overview" class="btn ghost right">\u2190 Back</a>
        </div>
      </div>
      <div class="divider"></div>
      <div class="row" style="gap:6px;flex-wrap:wrap">
        <span class="badge neutral">total <span id="grpTotal">${rows.length}</span></span>
        <span class="badge online">online <span id="grpOnline">${online}</span></span>
        <span class="badge offline">offline <span id="grpOffline">${offline}</span></span>
        <span class="chip">${escapeHtml(g)}</span>
      </div>
      <p class="muted" style="margin-top:8px">Owner: ${escapeHtml(gm.owner_name || "\u2014")} \xB7 ${escapeHtml(gm.phone || "\u2014")} \xB7 ${escapeHtml(gm.email || "\u2014")}</p>
      <div class="row" style="margin-top:8px;gap:8px;justify-content:flex-end">
        <button class="btn sm danger" id="grpAlarmOn" ${can("can_alert") ? "" : "disabled"}>Alarm ON</button>
        <button class="btn sm secondary" id="grpAlarmOff" ${can("can_alert") ? "" : "disabled"}>Alarm OFF</button>
      </div>
    </section>
    <section class="card">
      <h3 style="margin:0">Devices</h3>
      <div class="divider"></div>
      <div class="device-grid" id="groupPageDevices"></div>
    </section>
    <details class="card danger-zone device-drawer">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Danger zone</span>
        <span class="device-drawer__hint muted">Delete group \xB7 expand</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0 0 10px">Delete group will clear notification_group from all devices in this group.</p>
        <div class="row" style="justify-content:flex-end">
          <button class="btn danger btn-tap" id="grpDelete" ${isSharedGroup ? 'disabled title="Shared group cannot be deleted"' : ""}>Delete group</button>
        </div>
      </div>
    </details>
  `);
    const devGrid = $("#groupPageDevices", view);
    const renderGroupDevices = () => {
      if (!devGrid) return;
      setChildMarkup(
        devGrid,
        rows.length ? rows.map((d) => {
          const on = isOnline(d);
          const primary = escapeHtml(d.display_label || d.device_id || "unknown");
          const subId = d.display_label ? `<div class="device-id-sub mono">${escapeHtml(d.device_id || "")}</div>` : "";
          return `<a class="device-card" href="#/devices/${encodeURIComponent(d.device_id)}" style="text-decoration:none;color:inherit">
        <h3><div class="device-primary-name">${primary}</div>${subId}</h3>
        <div><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
          ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
          ${d.fw ? `<span class="chip">v${escapeHtml(d.fw)}</span>` : ""}
          ${d.is_shared ? `<span class="badge accent" title="shared device">sharing by ${escapeHtml(d.shared_by || "?")}</span>` : ""}
        </div>
        <div class="meta">Platform: ${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}<br/>Manufacturer: ESA Sibu</div>
      </a>`;
        }).join("") : `<p class="muted">No devices in this group.</p>`
      );
      const onNow = rows.filter((d) => isOnline(d)).length;
      const offNow = Math.max(0, rows.length - onNow);
      const tEl = $("#grpTotal", view);
      const oEl = $("#grpOnline", view);
      const fEl = $("#grpOffline", view);
      if (tEl) tEl.textContent = String(rows.length);
      if (oEl) oEl.textContent = String(onNow);
      if (fEl) fEl.textContent = String(offNow);
    };
    renderGroupDevices();
    const clearGroupByDevicePatchCompat = async () => {
      let changed = 0;
      for (const id of ids) {
        await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: "" } });
        changed += 1;
      }
      return { ok: true, changed };
    };
    const withOwnerQuery = (path, ownerO) => {
      const q = groupApiQueryOwner(ownerO);
      if (!q) return path;
      const join = path.includes("?") ? "&" : "?";
      return `${path}${join}${q}`;
    };
    const deleteGroupCardCompat = async (groupKey, ownerO) => runGroupDeleteAction({
      groupKey,
      ownerAdmin: ownerO,
      apiCaps: groupApiCaps,
      saveApiCaps: saveGroupApiCaps,
      tryDeletePostRoute: async (gk, oa) => {
        const p = withOwnerQuery(`/group-cards/${encodeURIComponent(gk)}/delete`, oa);
        try {
          return await api(p, { method: "POST" });
        } catch (e) {
          if (!isGroupRouteMissingError(e)) throw e;
        }
        return await api(withOwnerQuery(`/api/group-cards/${encodeURIComponent(gk)}/delete`, oa), { method: "POST" });
      },
      tryDeleteRoute: async (gk, oa) => {
        const p = withOwnerQuery(`/group-cards/${encodeURIComponent(gk)}`, oa);
        try {
          return await api(p, { method: "DELETE" });
        } catch (e) {
          if (!isGroupRouteMissingError(e)) throw e;
        }
        return await api(withOwnerQuery(`/api/group-cards/${encodeURIComponent(gk)}`, oa), { method: "DELETE" });
      },
      clearFallback: clearGroupByDevicePatchCompat
    });
    const applyGroupSettingsFallbackCompat = async (_groupKey, _ownerO, payload) => {
      const durationMs = Number(payload.trigger_duration_ms || DEFAULT_REMOTE_SIREN_MS);
      const tkey = metaKey;
      const prev = window.__groupDelayTimers.get(tkey);
      if (prev) {
        clearTimeout(prev);
        window.__groupDelayTimers.delete(tkey);
      }
      await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
      return { ok: true, fallback: true, device_count: ids.length };
    };
    const tryApplyRouteCompat = async (groupKey, ownerO) => {
      const p = withOwnerQuery(`/group-cards/${encodeURIComponent(groupKey)}/apply`, ownerO);
      try {
        return await api(p, { method: "POST" });
      } catch (e) {
        if (!isGroupRouteMissingError(e)) throw e;
      }
      return await api(withOwnerQuery(`/api/group-cards/${encodeURIComponent(groupKey)}/apply`, ownerO), { method: "POST" });
    };
    const sendAlert = async (action) => {
      if (!can("can_alert")) {
        toast("No can_alert capability", "err");
        return;
      }
      if (ids.length === 0) {
        toast("No devices in this group", "warn");
        return;
      }
      if (!confirm(`${action === "on" ? "Open" : "Close"} alarm for ${ids.length} devices in ${g}?`)) return;
      if (action === "on") {
        const payload = groupTriggerPayloadFromSettings(gsMap[metaKey] || gsMap[g] || {});
        await runGroupApplyOnAction({
          groupKey: g,
          ownerAdmin: tenantOwner,
          payload,
          apiCaps: groupApiCaps,
          saveApiCaps: saveGroupApiCaps,
          tryApplyRoute: tryApplyRouteCompat,
          applyFallback: applyGroupSettingsFallbackCompat
        });
      } else {
        const prev = window.__groupDelayTimers.get(metaKey);
        if (prev) {
          clearTimeout(prev);
          window.__groupDelayTimers.delete(metaKey);
        }
        await api("/alerts", { method: "POST", body: { action: "off", duration_ms: DEFAULT_REMOTE_SIREN_MS, device_ids: ids } });
      }
      toast(`${action === "on" ? "Alarm ON" : "Alarm OFF"} \xB7 ${ids.length}`, "ok");
    };
    const alarmOnBtn = $("#grpAlarmOn", view);
    const alarmOffBtn = $("#grpAlarmOff", view);
    const delGroupBtn = $("#grpDelete", view);
    if (alarmOnBtn) alarmOnBtn.addEventListener("click", () => sendAlert("on"));
    if (alarmOffBtn) alarmOffBtn.addEventListener("click", () => sendAlert("off"));
    if (delGroupBtn) {
      delGroupBtn.addEventListener("click", async () => {
        if (isSharedGroup) {
          toast("Shared group cannot be deleted", "err");
          return;
        }
        if (!confirm(`Delete group card "${g}"?`)) return;
        try {
          await deleteGroupCardCompat(g, tenantOwner);
          if (meta[metaKey]) delete meta[metaKey];
          else if (meta[g]) delete meta[g];
          localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta));
          toast("Group deleted", "ok");
          location.hash = "#/overview";
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
    const refreshGroupLive = async () => {
      if (!isRouteCurrent(routeSeq)) return;
      const latest = await apiGetCached("/devices", { timeoutMs: 16e3 }, 2e3);
      if (!isRouteCurrent(routeSeq)) return;
      list = latest || { items: [] };
      byId = new Map((list.items || []).map((d) => [String(d.device_id), d]));
      syncGroupMetaWithDevices(meta, list.items || []);
      try {
        localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta));
      } catch (_) {
      }
      rows = rowsByGroup();
      ids = rows.map((d) => String(d.device_id || "")).filter(Boolean);
      renderGroupDevices();
    };
    scheduleRouteTicker(routeSeq, `group-live-${g}`, refreshGroupLive, 1e4);
  });
  registerRoute("login", async (view) => {
    setCrumb("Sign in");
    document.body.dataset.auth = "none";
    const cleanAuthMessage = (raw) => {
      const s = String(raw || "").trim();
      if (!s) return "Request failed. Please try again.";
      const l = s.toLowerCase();
      if (l.includes("401")) return "Username or password is incorrect.";
      if (l.includes("invalid credentials")) return "Username or password is incorrect.";
      if (l.includes("too many login attempts")) return s;
      if (l.includes("session expired")) return "Session expired. Please sign in again.";
      if (l.includes("networkerror") || l.includes("failed to fetch")) return "Network error. Please check server/API.";
      return s.replace(/^error:\s*/i, "");
    };
    mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("login")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner">
          <div class="auth-card auth-card--panel auth-card--auth-main" data-auth-card>
            <header class="auth-card__head">
              <h1 class="auth-card__title">Sign in</h1>
              <p class="auth-card__lead">Use the credentials your administrator provided.</p>
            </header>
            <form class="auth-card__body" id="loginForm" autocomplete="on">
              <label class="field">
                <span>Username</span>
                <input name="username" autocomplete="username" required placeholder="e.g. dan" />
              </label>
              <label class="field field--spaced">
                <span>Password</span>
                <input name="password" type="password" autocomplete="current-password" required placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" />
              </label>
              <div class="auth-card__submit">
                <button class="btn btn-tap btn-block auth-btn-primary" type="submit" id="loginSubmit">Sign in</button>
              </div>
              <p class="auth-card__msg auth-card__msg--fixed muted" id="loginMsg" aria-live="polite"></p>
              <nav class="auth-card__links auth-card__links--grid" aria-label="Other sign-in options">
                <a class="auth-link" href="#/register">Register admin</a>
                <a class="auth-link" href="#/account-activate">Activate account</a>
                <a class="auth-link" href="#/forgot-password">Forgot password</a>
              </nav>
            </form>
          </div>
          ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
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
        btn.textContent = "Signing in\u2026";
      }
      try {
        await login(data.get("username"), data.get("password"));
        await loadMe();
        await loadHealth();
        location.hash = "#/overview";
      } catch (e) {
        msg.textContent = cleanAuthMessage(e.message || e);
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
  registerRoute("ota", async (view, _args, routeSeq) => {
    await __renderOtaFirmwareRoute(view, routeSeq);
  });
  async function __renderOtaFirmwareRoute(view, routeSeq) {
    setCrumb("OTA (ops)");
    const me = state.me || { username: "", role: "user" };
    const isSuper = me.role === "superadmin";
    if (!isSuper) {
      mountView(view, `
      <div class="card">
        <h2 class="ui-section-title" style="margin:0">OTA & firmware</h2>
        <p class="muted" style="margin:8px 0 0">\u79DF\u6237\u4FA7 <strong>\u4E0D</strong>\u518D\u4F7F\u7528 Admin OTA \u63A7\u5236\u53F0\u3002\u8BF7\u5728 <a href="#/devices">\u5168\u90E8\u8BBE\u5907</a> \u4E0E\u8BBE\u5907\u8BE6\u60C5\u67E5\u770B\u7248\u672C\u65C1\u7684 <strong>\u2191 + \u7EA2\u70B9</strong>\uFF08\u6709\u53EF\u7528\u65B0\u56FA\u4EF6\u65F6\uFF09\u3002OTA \u4E0A\u4F20\u4E0E campaign \u4EC5 <strong>superadmin</strong> \u5728\u4FA7\u680F\u300COTA (ops)\u300D\u64CD\u4F5C\u3002</p>
        <p class="muted" style="margin:8px 0 0">There is <strong>no</strong> admin OTA console in this product. Use <a href="#/devices">All devices</a> and device detail for the <strong>\u2191 + red dot</strong> when an upgrade is available. Staging and campaigns are <strong>superadmin</strong> only (sidebar <strong>OTA (ops)</strong>).</p>
      </div>`);
      return;
    }
    const helpCard = `
    <div class="card ota-help-card">
      <h2 class="ui-section-title" style="margin:0">OTA & firmware \xB7 \u4F7F\u7528\u8BF4\u660E</h2>
      <div class="ota-help__cols">
        <div>
          <h3 class="ota-help__h">\u4E2D\u6587</h3>
          <ul class="muted ota-help__ul">
            <li><strong>\u5168\u5458\uFF08\u542B admin\uFF09</strong>\uFF1A\u53EA\u770B <a href="#/devices">\u5168\u90E8\u8BBE\u5907</a> / \u8BBE\u5907\u8BE6\u60C5\u4E0A\u7684 <strong>\u2191 + \u7EA2\u70B9</strong> \u4E0E\u8BF4\u660E\u5F39\u7A97\uFF1B\u4E0D\u5728\u6B64\u9875\u5BF9 campaign \u505A Accept\u3002</li>
            <li><strong>\u68C0\u6D4B</strong>\uFF1A\u670D\u52A1\u5668\u6BD4\u8F83 <code>OTA_FIRMWARE_DIR</code> \u4E2D\u7684 <code>.bin</code> \u4E0E\u8BBE\u5907 <code>fw</code>\uFF1B\u9700 <code>OTA_PUBLIC_BASE_URL</code> \u624D\u80FD\u5728\u5F39\u7A97\u4E2D\u7ED9\u51FA\u4E0B\u8F7D URL\u3002</li>
            <li><strong>\u6587\u4EF6</strong>\uFF1A\u63A8\u8350 <code>croc-\u7248\u672C\u53F7-8\u4F4Dhex.bin</code>\uFF1B\u540C\u540D <code>.txt</code> / <code>.md</code> \u4E3A release notes\u3002</li>
            <li><strong>Superadmin</strong>\uFF1A\u5728\u672C\u9875\u4E0B\u65B9\u4E0A\u4F20 / \u4ECE\u5DF2\u5B58\u6587\u4EF6\u5EFA campaign\uFF08\u82E5\u4ECD\u4F7F\u7528\u540E\u7AEF campaign \u6D41\uFF0C\u7531 API \u6216\u5176\u5B83\u6D41\u7A0B\u8BA9\u5404\u79DF\u6237\u8BBE\u5907\u62C9\u53D6\uFF1B\u63A7\u5236\u53F0\u4E0D\u518D\u7ED9 admin \u63D0\u4F9B OTA \u5165\u53E3\uFF09\u3002</li>
          </ul>
        </div>
        <div>
          <h3 class="ota-help__h">English</h3>
          <ul class="muted ota-help__ul">
            <li><strong>Everyone (including admin)</strong>: use <a href="#/devices">All devices</a> / device detail <strong>\u2191 + red dot</strong> + notes dialog only \u2014 <strong>no</strong> tenant OTA Accept UI here.</li>
            <li><strong>Detection</strong>: server compares <code>.bin</code> in <code>OTA_FIRMWARE_DIR</code> vs device <code>fw</code>; set <code>OTA_PUBLIC_BASE_URL</code> for URLs in the dialog.</li>
            <li><strong>Files</strong>: prefer <code>croc-SEMVER-random8.bin</code>; sidecar <code>.txt</code>/<code>.md</code> for notes.</li>
            <li><strong>Superadmin</strong>: upload / create-from-stored below. Campaign APIs may still exist server-side; this dashboard does not expose an admin OTA workflow.</li>
          </ul>
        </div>
      </div>
      <p class="muted" style="margin:12px 0 0">Fleet: <a href="#/devices">All devices</a></p>
    </div>`;
    const superCard = `
    <div class="card">
      <h2 class="ui-section-title">Superadmin \xB7 Upload & campaign</h2>
      <p class="muted" style="margin:0 0 8px">Upload stages a <code>.bin</code> under <code>OTA_FIRMWARE_DIR</code> (upload password <code>OTA_UPLOAD_PASSWORD</code>). The API keeps at most <strong id="otaMaxBinsLbl">10</strong> <code>.bin</code> files and deletes the <strong>oldest by file mtime</strong> (and sidecars) when over limit \u2014 same rule as <code>POST /ota/firmware/upload</code>. The list below is <strong>fetched from this server</strong> (<code>GET /ota/firmwares</code>); click <strong>Refresh list</strong> after upload or if you copied files in by hand.</p>
      <div class="inline-form">
        <label class="field wide"><span>Upload password *</span><input type="password" id="otaStUploadPwd" autocomplete="off" placeholder="Server OTA_UPLOAD_PASSWORD" /></label>
        <label class="field"><span>Firmware file (.bin)</span><input type="file" id="otaStFile" accept=".bin,application/octet-stream" /></label>
        <label class="field"><span>Version label *</span><input id="otaStFw" placeholder="6.6.8" maxlength="40" /></label>
        <div class="row wide" style="justify-content:flex-end">
          <button type="button" class="btn btn-tap" id="otaStBtn">Upload & verify</button>
        </div>
      </div>
      <p class="muted" id="otaRetentionInfo" style="margin-top:8px;min-height:1.2em"></p>
      <p class="muted" id="otaStResult" style="margin-top:4px;min-height:1.2em"></p>
      <div class="divider"></div>
      <h3 style="margin:0 0 6px">Publish from server-staged firmware / \u4F7F\u7528\u670D\u52A1\u5668\u4E0A\u7684\u56FA\u4EF6</h3>
      <p class="muted" style="margin:0 0 8px;font-size:12.5px">The dropdown is populated by <strong>pulling the current directory listing from the API</strong> (not from your PC). Pick a <code>.bin</code> already on the server, then create a campaign. <strong>Version</strong> is resolved on the server (<code>.version</code> sidecar or filename) \u2014 not hand-typed; it should match that build&rsquo;s <code>FW_VERSION</code>.</p>
      <div class="row wide" style="align-items:flex-end;flex-wrap:wrap;gap:10px;margin-bottom:6px">
        <label class="field wide" style="flex:1;min-width:220px;margin:0"><span>Firmware on server *</span><select id="otaFromSel"><option value="">Loading\u2026</option></select></label>
        <button type="button" class="btn secondary btn-tap sm" id="otaFwListRefresh">Refresh list</button>
      </div>
      <label class="field wide"><span>Version (from server, read-only)</span><input type="text" id="otaFromResolvedVer" class="mono" readonly tabindex="-1" value="\u2014" style="background:var(--bg-muted);cursor:default" aria-live="polite" /></label>
      <label class="field wide"><span>Notes</span><input id="otaFromNotes" maxlength="500" /></label>
      <label class="checkbox"><input type="checkbox" id="otaFromAllAd" checked /><span>Target all admins</span></label>
      <label class="field wide"><span>Or comma-separated admin usernames</span><input id="otaFromAdmTxt" placeholder="admin-a, admin-b (when not targeting all)" /></label>
      <div class="row wide" style="justify-content:flex-end;margin-top:10px">
        <button type="button" class="btn btn-tap" id="otaFromBtn">Create campaign</button>
      </div>
    </div>`;
    mountView(view, helpCard + superCard);
    const otaSyncFromStoredVersion = () => {
      const sel = $("#otaFromSel", view);
      const ro = $("#otaFromResolvedVer", view);
      if (!ro) return;
      if (!sel || !sel.value) {
        ro.value = "\u2014";
        return;
      }
      const i = Number(sel.selectedIndex);
      const opt = sel.options[i];
      const raw = opt && opt.getAttribute("data-fw-version");
      const v = raw && String(raw).trim() || "";
      ro.value = v || "\u2014";
    };
    const refreshFirmwareSelect = async () => {
      if (!isSuper) return;
      const sel = $("#otaFromSel", view);
      if (!sel) return;
      try {
        const r = await api("/ota/firmwares", { timeoutMs: 2e4 });
        if (!isRouteCurrent(routeSeq)) return;
        const items = r.items || [];
        const ret = r.retention;
        const mx = $("#otaMaxBinsLbl", view);
        if (mx && ret && ret.max_bins != null) mx.textContent = String(ret.max_bins);
        const inf = $("#otaRetentionInfo", view);
        if (inf) {
          inf.textContent = ret ? `Server directory: ${ret.stored_count || 0} / max ${ret.max_bins} .bin files (oldest mtime removed when over limit). Upload password: ${ret.upload_password_configured ? "configured" : "not set on server"}.` : "";
        }
        const fmtM = (ts) => {
          const t = Number(ts);
          if (!Number.isFinite(t) || t <= 0) return "";
          try {
            const d = new Date(t * 1e3);
            return d.toLocaleString(void 0, { dateStyle: "short", timeStyle: "short" });
          } catch {
            return "";
          }
        };
        sel.innerHTML = items.length ? items.map((it) => {
          const vRaw = it.fw_version && String(it.fw_version).trim() || "";
          const dv = vRaw ? escapeHtml(vRaw) : "";
          const fv = vRaw ? ` \xB7 v${escapeHtml(vRaw)}` : "";
          const mt = fmtM(it.mtime);
          const mtS = mt ? ` \xB7 ${escapeHtml(mt)}` : "";
          return `<option value="${escapeHtml(it.name)}" data-fw-version="${dv}">${escapeHtml(it.name)}${fv} (${Math.round(Number(it.size || 0) / 1024)} KB${mtS})</option>`;
        }).join("") : '<option value="">(no .bin in folder)</option>';
        otaSyncFromStoredVersion();
        sel.onchange = otaSyncFromStoredVersion;
      } catch (e) {
        const inf = $("#otaRetentionInfo", view);
        if (inf) inf.textContent = "";
        sel.innerHTML = `<option value="">${escapeHtml(e.message || "list failed")}</option>`;
        otaSyncFromStoredVersion();
        sel.onchange = otaSyncFromStoredVersion;
      }
    };
    await refreshFirmwareSelect();
    const otaFwListRefresh = $("#otaFwListRefresh", view);
    if (otaFwListRefresh) {
      otaFwListRefresh.addEventListener("click", async () => {
        otaFwListRefresh.disabled = true;
        try {
          await refreshFirmwareSelect();
          toast("Firmware list refreshed from server", "ok");
        } catch (_) {
        } finally {
          otaFwListRefresh.disabled = false;
        }
      });
    }
    const stBtn = $("#otaStBtn", view);
    if (stBtn) {
      stBtn.addEventListener("click", async () => {
        const inp = $("#otaStFile", view);
        const f = inp && inp.files && inp.files[0];
        const fw = String($("#otaStFw", view)?.value || "").trim();
        const upw = String($("#otaStUploadPwd", view)?.value || "");
        if (!f || !fw) {
          toast("Choose file and version label", "err");
          return;
        }
        if (!upw) {
          toast("Enter the upload password (set OTA_UPLOAD_PASSWORD on the server).", "err");
          return;
        }
        if (!confirm("Upload firmware to server (HEAD check against public /fw/ URL)?")) return;
        try {
          const fd = new FormData();
          fd.append("file", f);
          fd.append("fw_version", fw);
          fd.append("upload_password", upw);
          const r = await api("/ota/firmware/upload", { method: "POST", body: fd, timeoutMs: 18e4 });
          if (!isRouteCurrent(routeSeq)) return;
          const resEl = $("#otaStResult", view);
          if (resEl) resEl.textContent = `Stored ${r.stored_as || ""} \xB7 head_ok=${r.head_ok} \xB7 ${r.verify || ""}`;
          toast("Upload finished", r.head_ok ? "ok" : "err");
          if (inp) inp.value = "";
          refreshFirmwareSelect();
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
    const fromBtn = $("#otaFromBtn", view);
    if (fromBtn) {
      fromBtn.addEventListener("click", async () => {
        const fn = String($("#otaFromSel", view)?.value || "").trim();
        const notes = String($("#otaFromNotes", view)?.value || "").trim();
        const allCh = $("#otaFromAllAd", view);
        const rawAdm = String($("#otaFromAdmTxt", view)?.value || "").trim();
        const target_admins = allCh && allCh.checked ? ["*"] : rawAdm ? rawAdm.split(/[\s,;]+/).filter(Boolean) : ["*"];
        if (!fn) {
          toast("Select a firmware package from the list", "err");
          return;
        }
        if (!confirm("Create OTA campaign from this stored file? The campaign version will be taken from the server (staged .version / filename), not the UI.")) return;
        try {
          const out = await api("/ota/campaigns/from-stored", {
            method: "POST",
            body: { filename: fn, notes: notes || void 0, target_admins }
          });
          toast(
            out && out.fw_version ? `Campaign created \xB7 v${out.fw_version}` : "Campaign created",
            "ok"
          );
          try {
            bustDeviceListCaches();
          } catch (_) {
          }
        } catch (e) {
          toast(e.message || e, "err");
        }
      });
    }
  }
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
  registerRoute("overview", async (view, _args, routeSeq) => {
    setCrumb("Overview");
    const groupScope = state.me && state.me.username ? state.me.username : "anon";
    const GROUP_API_CAPS_LS_KEY = `croc.group.api.caps.v2.${groupScope}`;
    const loadGroupApiCaps = () => {
      try {
        const raw = localStorage.getItem(GROUP_API_CAPS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return {
          settings: obj && obj.settings === false ? false : true,
          apply: obj && obj.apply === false ? false : true,
          delete: obj && obj.delete === false ? false : true,
          prefix: obj && (obj.prefix === "/api" || obj.prefix === "") ? obj.prefix : ""
        };
      } catch {
        return { settings: true, apply: true, delete: true, prefix: "" };
      }
    };
    const saveGroupApiCaps = (caps) => {
      localStorage.setItem(GROUP_API_CAPS_LS_KEY, JSON.stringify({
        settings: !!(caps && caps.settings),
        apply: !!(caps && caps.apply),
        delete: !!(caps && caps.delete),
        prefix: caps && caps.prefix === "/api" ? "/api" : ""
      }));
    };
    const groupApiCaps = loadGroupApiCaps();
    const tryGroupApiCall = async (suffix, opts) => {
      const lastErrs = [];
      const prefixes = groupApiCaps.prefix === "/api" ? ["/api", ""] : ["", "/api"];
      for (const px of prefixes) {
        try {
          const r = await api(`${px}/group-cards${suffix}`, opts);
          if (groupApiCaps.prefix !== px) {
            groupApiCaps.prefix = px;
            saveGroupApiCaps(groupApiCaps);
          }
          return r;
        } catch (e) {
          const msg = String(e && e.message || e || "");
          lastErrs.push(e);
          if (msg.includes("404") || msg.includes("405") || msg.includes("501")) continue;
          throw e;
        }
      }
      throw lastErrs[lastErrs.length - 1] || new Error("group route unavailable");
    };
    const loadGroupSettingsCompat = async () => {
      if (!groupApiCaps.settings) return { items: [] };
      try {
        return await tryGroupApiCall("/settings", { timeoutMs: 12e3, retries: 1 });
      } catch (e) {
        const msg = String(e && e.message || e || "");
        if (msg.includes("404") || msg.includes("405") || msg.includes("501")) {
          groupApiCaps.settings = false;
          saveGroupApiCaps(groupApiCaps);
          return { items: [] };
        }
        throw e;
      }
    };
    const fetchOverviewAndDevices = async () => {
      let bestOv = null;
      let bestList = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        const [ovR, liR] = await Promise.allSettled([
          api("/dashboard/overview", { timeoutMs: 22e3, retries: 3 }),
          api("/devices", { timeoutMs: 22e3, retries: 3 })
        ]);
        if (ovR.status === "fulfilled" && ovR.value) bestOv = ovR.value;
        if (liR.status === "fulfilled" && liR.value) bestList = liR.value;
        if (bestOv && bestList) return { ov: bestOv, list: bestList };
        if (attempt === 0) await _sleep(500);
      }
      return { ov: bestOv, list: bestList };
    };
    const [ovListRes, grpSetRes] = await Promise.allSettled([
      fetchOverviewAndDevices(),
      loadGroupSettingsCompat()
    ]);
    let ov = ovListRes.status === "fulfilled" && ovListRes.value && ovListRes.value.ov ? ovListRes.value.ov : null;
    let list = ovListRes.status === "fulfilled" && ovListRes.value && ovListRes.value.list ? ovListRes.value.list : null;
    if (!ov || !list) {
      const cached = state.overviewCache;
      if (cached && cached.ov && cached.list) {
        ov = ov || cached.ov;
        list = list || cached.list;
        toast("Showing last known data \u2014 server is slow or offline; will retry on refresh.", "warn");
      }
    }
    if (!ov) ov = { mqtt_connected: false };
    if (!list) list = { items: [] };
    state.overviewCache = { ov, list, ts: Date.now() };
    const groupSettingsItems = grpSetRes.status === "fulfilled" && grpSetRes.value && Array.isArray(grpSetRes.value.items) ? grpSetRes.value.items : [];
    let devices = list.items || [];
    let byId = new Map(devices.map((d) => [String(d.device_id), d]));
    const GROUP_META_LS_KEY = `croc.group.meta.v2.${groupScope}`;
    const GROUP_SETTINGS_LS_KEY = `croc.group.settings.v1.${groupScope}`;
    const loadGroupMeta = () => {
      try {
        const raw = localStorage.getItem(GROUP_META_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return obj && typeof obj === "object" ? obj : {};
      } catch {
        return {};
      }
    };
    const saveGroupMeta = (obj) => localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(obj || {}));
    const loadLocalGroupSettings = () => {
      try {
        const raw = localStorage.getItem(GROUP_SETTINGS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return obj && typeof obj === "object" ? obj : {};
      } catch {
        return {};
      }
    };
    const saveLocalGroupSettings = (obj) => localStorage.setItem(GROUP_SETTINGS_LS_KEY, JSON.stringify(obj || {}));
    const groupDelayTimers = /* @__PURE__ */ new Map();
    const localGroupSettings = loadLocalGroupSettings();
    const groupSettingsMap = /* @__PURE__ */ new Map();
    for (const [k, v] of Object.entries(localGroupSettings)) groupSettingsMap.set(String(k), v || {});
    for (const x of groupSettingsItems) {
      const mk = groupCardMetaKey(
        x.group_key,
        state.me && state.me.role === "superadmin" ? x.owner_admin : ""
      );
      if (mk) groupSettingsMap.set(mk, x);
    }
    const meta = loadGroupMeta();
    syncGroupMetaWithDevices(meta, devices);
    saveGroupMeta(meta);
    let selectedGroup = "";
    const hh = state.health || {};
    const httpOk = !!(hh.ok ?? true);
    const mqConnected = !!(hh.mqtt_connected ?? ov.mqtt_connected);
    const mqQDepth = Number(hh.mqtt_ingest_queue_depth || 0);
    const mqDropped = Number(hh.mqtt_ingest_dropped || 0);
    const totalDevices = Number(ov.total_devices != null ? ov.total_devices : devices.length);
    const onlineDevices = Number(ov.presence && ov.presence.online != null ? ov.presence.online : devices.filter(isOnline).length);
    const offlineDevices = Math.max(0, totalDevices - onlineDevices);
    const txBps = Number(ov.throughput && ov.throughput.tx_bps_total || 0);
    const rxBps = Number(ov.throughput && ov.throughput.rx_bps_total || 0);
    const bps = (v) => {
      v = Number(v || 0);
      if (v < 1024) return `${v.toFixed(0)} B/s`;
      if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
      return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
    };
    const mqStatus = !mqConnected ? "Disconnected" : mqDropped > 0 || mqQDepth >= 300 ? "Warning" : "Healthy";
    const mqClass = !mqConnected ? "revoked" : mqStatus === "Warning" ? "offline" : "online";
    let lastOverviewHeaderSig = "";
    const patchOverviewHeader = (vals) => {
      const sig = JSON.stringify(vals || {});
      if (sig === lastOverviewHeaderSig) return;
      lastOverviewHeaderSig = sig;
      const setTxt = (id, v) => {
        const el = $(`#${id}`, view);
        if (el && el.textContent !== String(v)) el.textContent = String(v);
      };
      setTxt("ovServerV", vals.server);
      setTxt("ovDevicesV", vals.devices);
      setTxt("ovOnlineV", vals.online);
      setTxt("ovOfflineV", vals.offline);
      setTxt("ovTxV", vals.tx);
      setTxt("ovRxV", vals.rx);
      setTxt("ovMqttQueue", vals.queue);
      setTxt("ovMqttDropped", vals.dropped);
      const risk = $("#ovMqttRisk", view);
      if (risk) {
        if (risk.textContent !== String(vals.risk)) risk.textContent = String(vals.risk);
        const want = `badge ${vals.riskClass}`;
        if (risk.className !== want) risk.className = want;
      }
    };
    mountView(view, `
    <header class="page-head">
      <h2>Overview</h2>
      <p class="muted">Fleet snapshot, group cards, and MQTT health for your scope.</p>
    </header>
    <section class="stats">
      <div class="stat"><div class="k">Server</div><div class="v" id="ovServerV">\u2014</div><div class="sub">HTTP + MQTT realtime</div></div>
      <div class="stat"><div class="k">Devices</div><div class="v" id="ovDevicesV">\u2014</div><div class="sub">total in scope</div></div>
      <div class="stat"><div class="k">Online</div><div class="v" id="ovOnlineV">\u2014</div><div class="sub">active now</div></div>
      <div class="stat"><div class="k">Offline</div><div class="v" id="ovOfflineV">\u2014</div><div class="sub">inactive now</div></div>
      <div class="stat"><div class="k">TX</div><div class="v" id="ovTxV">\u2014</div><div class="sub">aggregate uplink</div></div>
      <div class="stat"><div class="k">RX</div><div class="v" id="ovRxV">\u2014</div><div class="sub">aggregate downlink</div></div>
    </section>
    <section class="card card--groups">
      <div class="row">
        <h3 style="margin:0">MQTT risk</h3>
        <span class="badge ${mqClass}" id="ovMqttRisk">${mqStatus}</span>
      </div>
      <div class="divider"></div>
      <div class="muted">queue=<span class="mono" id="ovMqttQueue">0</span> \xB7 dropped=<span class="mono" id="ovMqttDropped">0</span></div>
    </section>
    <section class="card">
      <div class="row">
        <h2 style="margin:0">Group cards</h2>
        <button class="btn sm secondary right" id="grpNew">New group</button>
      </div>
      ${state.me && state.me.role === "superadmin" ? `
      <div class="row" style="flex-wrap:wrap;gap:10px;align-items:flex-end;margin:10px 0 4px">
        <label class="field" style="margin:0;min-width:220px;flex:1">
          <span>Filter by owner / \u6309\u79DF\u6237\u7B5B\u9009\u7EC4\u5361</span>
          <input type="search" id="ovOwnerFilter" list="ovOwnerDatalist" placeholder="username substring\u2026" autocomplete="off" />
          <datalist id="ovOwnerDatalist"></datalist>
        </label>
        <button type="button" class="btn sm secondary btn-tap" id="ovOwnerClear">Clear</button>
      </div>
      <p class="muted" style="margin:0 0 8px;font-size:12px">One card per tenant group. <span class="mono">__unowned__</span> means no owner.</p>
      ` : ""}
      <div id="groupCards" class="device-grid"></div>
      ${state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users")) ? `
      <details class="share-fold" id="grpShareFold">
        <summary class="share-fold__summary">
          <span>Global sharing</span>
          <span class="muted">Device ACL only</span>
        </summary>
        <div class="share-global-panel">
          <div class="share-global-head">
            <div class="share-global-toolbar">
              <button class="btn sm secondary btn-tap" type="button" id="grpShareRefresh">Refresh</button>
              <button class="btn sm btn-tap" type="button" id="grpShareOpen">New grant</button>
            </div>
          </div>
          <p class="muted" style="margin:0 0 6px;font-size:12px">Shared users get per-device access only; group cards and trigger policy stay tenant-local.</p>
          <div id="shareGrantsTableWrap" class="share-grants-table mini" style="margin-top:10px">
            <p class="muted" style="margin:0;padding:8px 0">Loading shares\u2026</p>
          </div>
        </div>
      </details>` : ""}
    </section>
    <div id="shareModal" class="grp-modal" style="display:none">
      <div class="grp-modal-card" style="max-width:760px;width:min(760px,96vw)">
        <h3 style="margin:0 0 8px" id="shareModalTitle">Share devices / group</h3>
        <p class="muted" id="shareTargetHint" style="margin:0 0 10px">Select devices, users, and permissions.</p>
        <p class="muted" id="shareEditNote" style="margin:0 0 8px;display:none"></p>
        <div class="row" style="gap:10px;align-items:flex-start;flex-wrap:wrap">
          <div style="flex:1;min-width:280px">
            <div class="row" style="justify-content:space-between;align-items:center">
              <strong>Devices</strong>
              <label class="muted"><input type="checkbox" id="shareSelAllDevices" /> Select all</label>
            </div>
            <div id="shareDeviceList" class="grp-pick-list grp-pick-list--devices" style="max-height:280px;overflow:auto"></div>
          </div>
          <div style="flex:1;min-width:280px">
            <div class="row" style="justify-content:space-between;align-items:center">
              <strong>Users</strong>
              <label class="muted"><input type="checkbox" id="shareSelAllUsers" /> Select all</label>
            </div>
            <div id="shareUserList" class="grp-pick-list" style="max-height:260px;overflow:auto"></div>
          </div>
        </div>
        <div class="row" style="margin-top:10px;gap:14px">
          <label><input type="checkbox" id="sharePermView" checked /> can_view</label>
          <label><input type="checkbox" id="sharePermOperate" /> can_operate</label>
        </div>
        <p class="muted" id="shareBatchStat" style="min-height:1.2em;margin:8px 0 0"></p>
        <div class="row" style="justify-content:flex-end;gap:8px;margin-top:10px">
          <button class="btn sm secondary" id="shareModalCancel" type="button">Cancel</button>
          <button class="btn sm" id="shareModalApply" type="button">Apply sharing</button>
        </div>
      </div>
    </div>
    <div id="grpSetModal" class="grp-modal" style="display:none">
      <div class="grp-modal-card">
        <h3 style="margin:0 0 8px">Group trigger settings</h3>
        <p class="muted" id="gsKeyLabel" style="margin:0 0 10px"></p>
        <p class="muted" style="margin:0 0 10px;font-size:12px;line-height:1.45" lang="zh">\u5EF6\u8FDF\u4E3A 0 \u8868\u793A\u7ACB\u5373\u9E23\u54CD\uFF1B\u9E23\u54CD\u65F6\u957F\u4EE5\u5206\u949F\u8BA1\uFF08\u4E0E\u5355\u673A\u8FDC\u7A0B\u8B66\u62A5\u590D\u4F4D\u7B56\u7565\u4E00\u81F4\uFF09\u3002<br/><span lang="en">Delay 0 = immediate siren. Duration is in minutes (same idea as remote siren length).</span></p>
        <label class="field"><span>Siren duration (minutes)</span><input id="gsDurMin" type="number" min="0.5" max="5" step="0.5" /></label>
        <label class="field field--spaced"><span>Delay before siren (seconds)</span><input id="gsDelay" type="number" min="0" max="3600" step="1" /></label>
        <label class="field field--spaced field--toggle">
          <span class="row field--toggle__row" style="margin:0;align-items:flex-start;gap:10px">
            <input id="gsReboot" type="checkbox" />
            <span class="field--toggle__text">Reboot + self-check this group after trigger</span>
          </span>
        </label>
        <div class="row" style="justify-content:flex-end;gap:8px;margin-top:10px">
          <button class="btn sm secondary" id="gsCancel" type="button">Cancel</button>
          <button class="btn sm secondary" id="gsApply" type="button">Apply now</button>
          <button class="btn sm" id="gsSave" type="button">Save</button>
        </div>
      </div>
    </div>
    <div id="grpModal" class="grp-modal" style="display:none">
      <div class="grp-modal-card grp-modal-card--edit">
        <header class="grp-modal__head">
          <h3 class="grp-modal__title">\u7F16\u8F91\u7EC4\u5361 / Edit group card</h3>
          <p class="grp-modal__lede muted">\u586B\u5199\u7EC4\u6807\u8BC6\u4E0E\u5C55\u793A\u4FE1\u606F\uFF0C\u52FE\u9009\u8981\u51FA\u73B0\u5728\u6B64\u5361\u4E0A\u7684\u8BBE\u5907\u3002\u9700\u8981\u8BF4\u660E\u65F6\u8BF7\u5411\u7BA1\u7406\u5458\u7D22\u53D6\u6587\u6863\u3002<br/><span lang="en">Set the group identifier and display fields, then pick devices for this card. Ask your administrator for documentation if needed.</span></p>
        </header>
        <div class="grp-modal__fields">
          <label class="field"><span>Group key</span><input id="gmKey" placeholder="e.g. Warehouse-A" autocomplete="off"/></label>
          <p class="muted grp-modal__key-hint" style="margin:-2px 0 10px;font-size:11px;line-height:1.45">\u4FDD\u5B58\u65F6\u4F1A\u81EA\u52A8\u6574\u7406\u9996\u5C3E\u7A7A\u683C\u4E0E\u8FDE\u7EED\u7A7A\u683C\uFF08Unicode NFC\uFF09\u3002<strong>\u5927\u5C0F\u5199\u4ECD\u533A\u5206</strong>\uFF1B\u4E0E\u300C\u8BBE\u5907\u8BE6\u60C5 \u2192 Notification group\u300D\u4E0D\u4E00\u81F4\u65F6\u4F1A\u51FA\u73B0\u591A\u5F20\u7EC4\u5361\u3002<br/><span lang="en">Spaces are normalized on save; <strong>case still matters</strong>. Must match each device&rsquo;s Notification group or you will see multiple cards.</span></p>
          <label class="field"><span>Display name</span><input id="gmName" autocomplete="off"/></label>
          <label class="field"><span>Owner name</span><input id="gmOwner" autocomplete="name"/></label>
          <label class="field"><span>Phone</span><input id="gmPhone" inputmode="tel" autocomplete="tel"/></label>
          <label class="field"><span>Email</span><input id="gmEmail" type="email" autocomplete="email"/></label>
          <div class="field field--devices">
            <span>Devices in this group</span>
            <div id="gmDevices" class="grp-pick-list grp-pick-list--devices" role="group" aria-label="Devices in group"></div>
          </div>
        </div>
        <div class="row grp-modal__actions" style="justify-content:flex-end;gap:8px;margin-top:12px">
          <button class="btn sm secondary" id="gmCancel" type="button">Cancel</button>
          <button class="btn sm" id="gmSave" type="button">Save</button>
        </div>
      </div>
    </div>`);
    patchOverviewHeader({
      server: `${httpOk ? "HTTP OK" : "HTTP DOWN"} \xB7 ${mqConnected ? "MQTT UP" : "MQTT DOWN"}`,
      devices: totalDevices,
      online: onlineDevices,
      offline: offlineDevices,
      tx: bps(txBps),
      rx: bps(rxBps),
      queue: mqQDepth,
      dropped: mqDropped,
      risk: mqStatus,
      riskClass: mqClass
    });
    const groupCardsEl = $("#groupCards", view);
    const grpModalEl = $("#grpModal", view);
    const grpSetModalEl = $("#grpSetModal", view);
    const shareModalEl = $("#shareModal", view);
    if (!groupCardsEl || !grpModalEl || !grpSetModalEl) return;
    const repopOvOwnerDatalist = () => {
      const dl = $("#ovOwnerDatalist", view);
      if (!dl || !(state.me && state.me.role === "superadmin")) return;
      const owners = [...new Set(devices.map((d) => String(d.owner_admin || "").trim()).filter(Boolean))].sort();
      setChildMarkup(dl, owners.map((o) => `<option value="${escapeHtml(o)}"></option>`).join(""));
    };
    const groupDeviceRow = (d, { checked, disabled } = {}) => {
      const did = String(d && d.device_id != null ? d.device_id : "").trim();
      if (!did) return "";
      const name0 = d && d.display_label != null && String(d.display_label).trim();
      const name = name0 || did;
      const ck = checked ? " checked" : "";
      const di = disabled ? " disabled" : "";
      return `<label class="grp-pick-item grp-pick-item--device"><input type="checkbox" class="grp-pick-chk" value="${escapeHtml(did)}"${ck}${di} /><span class="grp-pick-text"><span class="grp-pick-name">${escapeHtml(name)}</span><span class="grp-pick-id mono" title="Device ID / \u5E8F\u5217\u53F7">${escapeHtml(did)}</span></span></label>`;
    };
    let editingGroup = "";
    const normalizeGroupKey = (v) => String(v == null ? "" : v).trim();
    let ownerFilterQ = "";
    const devicesForGroups = () => {
      if (!(state.me && state.me.role === "superadmin")) return devices;
      const q = ownerFilterQ.trim().toLowerCase();
      if (!q) return devices;
      return devices.filter((d) => String(d.owner_admin || "").toLowerCase().includes(q));
    };
    const groupDeviceIdsFromList = (g, tenantOwner) => {
      const key = canonicalGroupKey(g);
      if (!key) return [];
      const t = String(tenantOwner || "").trim();
      const isSuper = state.me && state.me.role === "superadmin";
      const out = [];
      for (const d of devices) {
        if (!d || canonicalGroupKey(d.notification_group) !== key) continue;
        if (isSuper) {
          const o = String(d.owner_admin || "").trim();
          if (t === "") {
            if (o) continue;
          } else if (o !== t) {
            continue;
          }
        } else if (t && String(d.owner_admin || "").trim() !== t) {
          continue;
        }
        const did = String(d.device_id || "").trim();
        if (did) out.push(did);
      }
      return out;
    };
    const collectGroupSlots = () => buildGroupSlotsFromDeviceList(devicesForGroups());
    const groupDeviceIdsFromSlot = (slot) => {
      const ids = groupDeviceIdsFromList(slot.groupKey, slot.tenantOwner);
      return ids.filter((x) => byId.has(String(x)));
    };
    const groupSharedBySlot = (slot) => {
      const rows = groupDeviceIdsFromSlot(slot).map((id) => byId.get(String(id))).filter(Boolean);
      const sharedFrom = new Set(rows.map((d) => String(d.shared_by || "")).filter(Boolean));
      return Array.from(sharedFrom);
    };
    const groupSharedByNotificationKey = (gk) => {
      const key = canonicalGroupKey(gk);
      if (!key) return [];
      const rows = devices.filter((d) => canonicalGroupKey(d.notification_group) === key);
      const sharedFrom = new Set(rows.map((d) => String(d.shared_by || "")).filter(Boolean));
      return Array.from(sharedFrom);
    };
    const granteesFullyCoveringDevices = (deviceIds, shareItems) => {
      const ids = (Array.isArray(deviceIds) ? deviceIds : []).map((x) => String(x || "").trim()).filter(Boolean);
      const n = ids.length;
      if (!n || !Array.isArray(shareItems)) return /* @__PURE__ */ new Set();
      const dset = new Set(ids);
      const counts = /* @__PURE__ */ new Map();
      for (const it of shareItems) {
        if (it && it.revoked_at) continue;
        const did = String(it && it.device_id || "").trim();
        if (!dset.has(did)) continue;
        const g = String(it && it.grantee_username || "").trim();
        if (!g) continue;
        counts.set(g, (counts.get(g) || 0) + 1);
      }
      const out = /* @__PURE__ */ new Set();
      for (const [g, c] of counts) {
        if (c >= n) out.add(g);
      }
      return out;
    };
    const shareScopeBadgesHtml = (rows) => {
      const list2 = Array.isArray(rows) ? rows.filter(Boolean) : [];
      const n = list2.length;
      if (!n) return "";
      const sharedRows = list2.filter((d) => d && d.is_shared);
      const sn = sharedRows.length;
      if (sn === 0) return "";
      if (sn === n) {
        const owners = [...new Set(sharedRows.map((d) => String(d.shared_by || "").trim()).filter(Boolean))];
        const o = owners.length === 1 ? owners[0] : owners.join(", ");
        return `<span class="badge accent" title="Device-level ACL: every device on this card is shared to you (same notification group)">ACL: full group \xB7 ${escapeHtml(o || "?")}</span>`;
      }
      return `<span class="badge partial" title="Device-level ACL: only some devices on this card are shared">ACL: partial devices (${sn}/${n})</span>`;
    };
    const renderDeviceCard = (d) => {
      const on = isOnline(d);
      const primary = escapeHtml(d.display_label || d.device_id || "unknown");
      const subId = d.display_label ? `<div class="device-id-sub mono">${escapeHtml(d.device_id || "")}</div>` : "";
      const showOwnerTag = !!(d.owner_admin && state.me && (state.me.role === "superadmin" || d.is_shared));
      const ownerCorner = showOwnerTag ? `<div class="device-card__corner-tr device-card__corner-tr--solo"><span class="card-owner-tag" title="Owning admin / \u79DF\u6237">${escapeHtml(String(d.owner_admin))}</span></div>` : "";
      return `<a class="device-card${showOwnerTag ? " device-card--has-owner-tag" : ""}" href="#/devices/${encodeURIComponent(d.device_id)}" style="text-decoration:none;color:inherit">
      ${ownerCorner}
      <h3><div class="device-primary-name">${primary}</div>${subId}</h3>
      <div><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
        ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
        ${d.fw ? `<span class="chip">v${escapeHtml(d.fw)}</span>` : ""}
        ${d.is_shared ? `<span class="badge accent" title="shared device">sharing by ${escapeHtml(d.shared_by || "?")}</span>` : ""}
      </div>
      <div class="meta">
        Platform: ${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}<br/>
        Manufacturer: ESA Sibu<br/>
        Updated: ${escapeHtml(fmtRel(d.updated_at))}
      </div>
    </a>`;
    };
    const buildGroupCardHtml = (slot) => {
      const g = slot.groupKey;
      const ids = groupDeviceIdsFromSlot(slot);
      const rows = ids.map((id) => byId.get(String(id))).filter(Boolean);
      const total = rows.length;
      const on = rows.filter((d) => isOnline(d)).length;
      const off = Math.max(0, total - on);
      const m = meta[slot.metaKey] || {};
      const gs = groupSettingsMap.get(slot.metaKey) || {
        trigger_mode: "continuous",
        trigger_duration_ms: DEFAULT_REMOTE_SIREN_MS,
        delay_seconds: 0,
        reboot_self_check: false
      };
      const isSharedGroup = groupSharedBySlot(slot).length > 0;
      const scopeShareHtml = shareScopeBadgesHtml(rows);
      const dsec = Number(gs.delay_seconds || 0);
      const modeLabel = dsec > 0 ? `immediate (delay cfg: ${dsec}s)` : "immediate";
      const shareBtn = state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users")) ? `<button class="group-del-ico js-share-group" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" title="Share devices in this card (device ACL only \u2014 not group secrets)">\u21EA</button>` : "";
      const unassignedSuper = state.me && state.me.role === "superadmin" && !slot.tenantOwner;
      const hasCorner = !!(slot.tenantOwner || shareBtn || unassignedSuper);
      const ownerPill = slot.tenantOwner ? `<span class="card-owner-tag" title="Owning admin / \u6240\u5C5E\u79DF\u6237">${escapeHtml(slot.tenantOwner)}</span>` : unassignedSuper ? `<span class="card-owner-tag" title="No owner_admin on devices in this card">Unassigned</span>` : "";
      const cornerHtml = hasCorner ? `<div class="device-card__corner-tr" role="group" aria-label="Tenant">${ownerPill}${shareBtn}</div>` : "";
      return `<article class="device-card js-group-card ${hasCorner ? "js-group-card--has-corner " : ""}${selectedGroup === slot.metaKey ? "is-selected" : ""}" data-meta-key="${escapeHtml(slot.metaKey)}" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" style="cursor:pointer;position:relative">
      ${cornerHtml}
      <h3><div class="device-primary-name">${escapeHtml(m.display_name || g)}</div><div class="device-id-sub mono">${escapeHtml(g)}</div></h3>
      <div class="meta" style="margin-bottom:8px">
        Trigger: <span class="mono">${escapeHtml(modeLabel)}</span> \xB7
        Duration: <span class="mono">${escapeHtml(String(Math.round((Number(gs.trigger_duration_ms) || DEFAULT_REMOTE_SIREN_MS) / 6e4 * 10) / 10))} min</span> \xB7
        Reboot+self-check: <span class="mono">${gs.reboot_self_check ? "yes" : "no"}</span>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;align-items:center">
        <span class="badge neutral">total ${total}</span>
        <span class="badge online">online ${on}</span>
        <span class="badge offline">offline ${off}</span>
        ${scopeShareHtml}
      </div>
      <div class="meta">Owner: ${escapeHtml(m.owner_name || "\u2014")} \xB7 ${escapeHtml(m.phone || "\u2014")} \xB7 ${escapeHtml(m.email || "\u2014")}</div>
      <div class="group-card-actions">
        <div class="group-card-actions__alarms">
          <button class="btn sm danger js-alert-on" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button">Alarm ON</button>
          <button class="btn sm secondary js-alert-off" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button">Alarm OFF</button>
        </div>
        <div class="group-card-actions__manage">
          <button class="btn sm secondary js-group-settings" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" ${isSharedGroup ? 'disabled title="Shared group follows owner settings"' : ""}>Settings</button>
          <button class="btn sm secondary js-edit-group" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" ${isSharedGroup ? 'disabled title="Shared group: device membership is read-only"' : ""}>Edit</button>
          <button class="btn sm danger js-del-group" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" ${isSharedGroup ? 'disabled title="Shared group cannot be deleted"' : 'title="Delete group"'}>Delete</button>
        </div>
      </div>
    </article>`;
    };
    const renderGroups = () => {
      const slots = collectGroupSlots();
      if (slots.length === 0) {
        setChildMarkup(groupCardsEl, `<p class="muted">No groups yet.</p>`);
        return;
      }
      const existing = new Map(
        $$(".js-group-card", groupCardsEl).map((el) => [String(el.getAttribute("data-meta-key") || el.getAttribute("data-group") || ""), el])
      );
      const frag = document.createDocumentFragment();
      for (const slot of slots) {
        const html = buildGroupCardHtml(slot);
        let node = existing.get(slot.metaKey) || null;
        if (!node || node.outerHTML !== html) {
          const sub = parseHtmlToFragment(html.trim());
          node = sub.firstElementChild;
        }
        if (node) frag.appendChild(node);
      }
      groupCardsEl.replaceChildren(frag);
    };
    const editingSettingsSlot = { metaKey: "", groupKey: "", tenantOwner: "" };
    const readSlotFromBtn = (btn) => {
      const card = btn && btn.closest ? btn.closest(".js-group-card") : null;
      const metaKey = String(btn && btn.dataset && btn.dataset.metaKey || card && card.getAttribute("data-meta-key") || "");
      const groupKey = String(btn && btn.dataset && btn.dataset.group || card && card.getAttribute("data-group") || "");
      const tenantOwner = String(btn && btn.dataset && btn.dataset.owner || card && card.getAttribute("data-owner") || "");
      return { metaKey, groupKey, tenantOwner };
    };
    const openSettingsModal = (slot) => {
      editingSettingsSlot.metaKey = slot.metaKey || "";
      editingSettingsSlot.groupKey = slot.groupKey || "";
      editingSettingsSlot.tenantOwner = slot.tenantOwner || "";
      if (!editingSettingsSlot.metaKey) return;
      const gs = groupSettingsMap.get(editingSettingsSlot.metaKey) || {
        trigger_mode: "continuous",
        trigger_duration_ms: DEFAULT_REMOTE_SIREN_MS,
        delay_seconds: 0,
        reboot_self_check: false
      };
      const label = editingSettingsSlot.tenantOwner ? `Group: ${editingSettingsSlot.groupKey} \xB7 admin: ${editingSettingsSlot.tenantOwner}` : `Group: ${editingSettingsSlot.groupKey}`;
      $("#gsKeyLabel", view).textContent = label;
      const durMin = Math.max(0.5, Math.min(5, (Number(gs.trigger_duration_ms) || DEFAULT_REMOTE_SIREN_MS) / 6e4));
      const gdm = $("#gsDurMin", view);
      if (gdm) gdm.value = String(Math.round(durMin * 10) / 10);
      $("#gsDelay", view).value = String(Number(gs.delay_seconds || 0));
      $("#gsReboot", view).checked = !!gs.reboot_self_check;
      grpSetModalEl.style.display = "flex";
    };
    const closeSettingsModal = () => {
      grpSetModalEl.style.display = "none";
    };
    const collectSettingsPayload = () => {
      const durMinEl = $("#gsDurMin", view);
      const durMin = parseFloat(durMinEl && durMinEl.value || "3", 10);
      const delay = parseInt($("#gsDelay", view).value, 10);
      const reboot = !!$("#gsReboot", view).checked;
      if (!Number.isFinite(durMin) || durMin < 0.5 || durMin > 5) {
        throw new Error("Siren duration must be 0.5\u20135 minutes");
      }
      if (!Number.isFinite(delay) || delay < 0 || delay > 3600) {
        throw new Error("Delay seconds must be 0-3600");
      }
      const duration = Math.round(durMin * 6e4);
      return {
        trigger_mode: delay > 0 ? "delay" : "continuous",
        trigger_duration_ms: duration,
        delay_seconds: delay,
        reboot_self_check: reboot
      };
    };
    const persistSettingsLocal = (metaKey, payload) => {
      const all = loadLocalGroupSettings();
      all[metaKey] = Object.assign({}, payload || {});
      saveLocalGroupSettings(all);
    };
    const saveGroupSettingsCompat = async (groupKey, tenantOwner, payload) => {
      const mk = groupCardMetaKey(groupKey, tenantOwner);
      const path = groupApiSuffixWithOwner(`/${encodeURIComponent(groupKey)}/settings`, tenantOwner);
      const body = Object.assign({}, payload || {});
      if (state.me && state.me.role === "superadmin" && String(tenantOwner || "").trim()) {
        body.owner_admin = String(tenantOwner).trim();
      }
      if (!groupApiCaps.settings) {
        persistSettingsLocal(mk, body);
        return body;
      }
      try {
        return await tryGroupApiCall(path, {
          method: "PUT",
          body
        });
      } catch (e) {
        const msg = String(e && e.message || e || "");
        if (msg.includes("404") || msg.includes("405") || msg.includes("501")) {
          groupApiCaps.settings = false;
          saveGroupApiCaps(groupApiCaps);
          persistSettingsLocal(mk, body);
          return body;
        }
        throw e;
      }
    };
    const applyGroupSettingsFallback = async (groupKey, tenantOwner, payload) => {
      const slot = { metaKey: groupCardMetaKey(groupKey, tenantOwner), groupKey, tenantOwner: tenantOwner || "" };
      const ids = groupDeviceIdsFromSlot(slot);
      if (!ids.length) throw new Error("No devices in this group");
      if (!can("can_alert")) throw new Error("No can_alert capability");
      const durationMs = Number(payload.trigger_duration_ms || DEFAULT_REMOTE_SIREN_MS);
      const timerKey = slot.metaKey;
      const prevTimer = groupDelayTimers.get(timerKey);
      if (prevTimer) {
        clearTimeout(prevTimer);
        groupDelayTimers.delete(timerKey);
      }
      await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
      let rebootJobs = 0;
      let selfTests = 0;
      if (payload.reboot_self_check) {
        if (!can("can_send_command")) throw new Error("Reboot+self-check needs can_send_command");
        for (const did of ids) {
          await api(`/devices/${encodeURIComponent(did)}/self-test`, { method: "POST" });
          selfTests += 1;
          await api(`/devices/${encodeURIComponent(did)}/commands`, {
            method: "POST",
            body: { cmd: "reboot", params: {} }
          });
          rebootJobs += 1;
        }
      }
      return { ok: true, fallback: true, device_count: ids.length, self_tests: selfTests, reboot_jobs: rebootJobs };
    };
    $("#gsCancel", view).addEventListener("click", closeSettingsModal);
    $("#gsSave", view).addEventListener("click", async () => {
      try {
        if (!editingSettingsSlot.metaKey) throw new Error("No group selected");
        const payload = collectSettingsPayload();
        const r = await saveGroupSettingsCompat(
          editingSettingsSlot.groupKey,
          editingSettingsSlot.tenantOwner,
          payload
        );
        groupSettingsMap.set(editingSettingsSlot.metaKey, r || payload);
        renderGroups();
        closeSettingsModal();
        toast("Group settings saved", "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $("#gsApply", view).addEventListener("click", async () => {
      try {
        if (!editingSettingsSlot.metaKey) throw new Error("No group selected");
        const payload = collectSettingsPayload();
        await saveGroupSettingsCompat(
          editingSettingsSlot.groupKey,
          editingSettingsSlot.tenantOwner,
          payload
        );
        groupSettingsMap.set(editingSettingsSlot.metaKey, payload);
        const r = await runGroupApplyOnAction({
          groupKey: editingSettingsSlot.groupKey,
          ownerAdmin: editingSettingsSlot.tenantOwner,
          payload,
          apiCaps: groupApiCaps,
          saveApiCaps: saveGroupApiCaps,
          tryApplyRoute: (gk, oa) => tryGroupApiCall(
            groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}/apply`, oa),
            { method: "POST" }
          ),
          applyFallback: applyGroupSettingsFallback
        });
        renderGroups();
        closeSettingsModal();
        toast(`Applied to ${Number(r.device_count || 0)} devices${r && r.fallback ? " (fallback mode)" : ""}`, "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    const clearGroupByDevicePatch = async (groupKey, tenantOwner) => {
      const slot = { metaKey: groupCardMetaKey(groupKey, tenantOwner), groupKey, tenantOwner: tenantOwner || "" };
      const ids = groupDeviceIdsFromSlot(slot);
      if (!ids.length) return { ok: true, changed: 0 };
      let changed = 0;
      for (const id of ids) {
        await api(`/devices/${encodeURIComponent(id)}/profile`, {
          method: "PATCH",
          body: { notification_group: "" }
        });
        changed += 1;
      }
      return { ok: true, changed };
    };
    const deleteGroupCard = async (groupKey, tenantOwner) => runGroupDeleteAction({
      groupKey,
      ownerAdmin: tenantOwner,
      apiCaps: groupApiCaps,
      saveApiCaps: saveGroupApiCaps,
      tryDeletePostRoute: (gk, oa) => tryGroupApiCall(
        groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}/delete`, oa),
        { method: "POST" }
      ),
      tryDeleteRoute: (gk, oa) => tryGroupApiCall(
        groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}`, oa),
        { method: "DELETE" }
      ),
      clearFallback: clearGroupByDevicePatch
    });
    const openGroupModal = (metaKey) => {
      editingGroup = metaKey || "";
      const parsed = parseGroupMetaKey(editingGroup);
      const gk = parsed.groupKey || "";
      const m = meta[editingGroup] || { display_name: gk || "", owner_name: "", phone: "", email: "", device_ids: [] };
      const slot = { metaKey: editingGroup, groupKey: gk, tenantOwner: parsed.tenantOwner };
      $("#gmKey", view).value = canonicalGroupKey(gk) || "";
      $("#gmName", view).value = m.display_name || "";
      $("#gmOwner", view).value = m.owner_name || "";
      $("#gmPhone", view).value = m.phone || "";
      $("#gmEmail", view).value = m.email || "";
      const sel = new Set((m.device_ids || []).map(String));
      const pick = $("#gmDevices", view);
      const isSharedGroup = groupSharedBySlot(slot).length > 0;
      if (pick) {
        setChildMarkup(
          pick,
          devices.map((d) => groupDeviceRow(d, { checked: sel.has(String(d.device_id)), disabled: isSharedGroup })).filter(Boolean).join("")
        );
        if (isSharedGroup) {
          prependChildMarkup(
            pick,
            `<p class="grp-pick-hint muted" style="margin:0 0 8px">Shared group: \u6210\u5458\u53EA\u8BFB\u3002 \xB7 Device membership is read-only.</p>`
          );
        }
      }
      grpModalEl.style.display = "flex";
    };
    const closeGroupModal = () => {
      grpModalEl.style.display = "none";
    };
    let sharePrefillGroup = "";
    let sharePrefillOwner = "";
    let shareModalUsersCache = [];
    let shareModalEditSpec = null;
    let overviewShareItems = [];
    let shareDevChangeBound = false;
    const refreshOverviewShareItemsSilently = async () => {
      if (!(state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users")))) return;
      try {
        const r = await api("/admin/shares?limit=2000", { timeoutMs: 12e3 });
        overviewShareItems = Array.isArray(r.items) ? r.items.filter((x) => x && !x.revoked_at) : [];
      } catch (_) {
      }
    };
    const loadOverviewShareGrants = async () => {
      const wrap = $("#shareGrantsTableWrap", view);
      if (!wrap) return;
      if (!(state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users")))) return;
      setChildMarkup(wrap, `<p class="muted" style="margin:0;padding:8px 0">Loading\u2026</p>`);
      try {
        const r = await api("/admin/shares?limit=2000", { timeoutMs: 22e3 });
        overviewShareItems = Array.isArray(r.items) ? r.items.filter((x) => x && !x.revoked_at) : [];
        const rows = [...overviewShareItems].sort((a, b) => {
          const c = String(a.device_id || "").localeCompare(String(b.device_id || ""));
          return c !== 0 ? c : String(a.grantee_username || "").localeCompare(String(b.grantee_username || ""));
        });
        if (!rows.length) {
          setChildMarkup(wrap, `<p class="muted" style="margin:0;padding:8px 0">No active shares in your scope.</p>`);
          return;
        }
        const body = rows.map((it) => {
          const did = escapeHtml(String(it.device_id || ""));
          const gu = escapeHtml(String(it.grantee_username || ""));
          const v = it.can_view ? "\u2713" : "\u2014";
          const o = it.can_operate ? "\u2713" : "\u2014";
          return `<tr data-device-id="${did}" data-grantee="${gu}">
          <td class="mono">${did}</td>
          <td class="mono">${gu}</td>
          <td>${v}</td>
          <td>${o}</td>
          <td style="white-space:nowrap">
            <button type="button" class="btn sm secondary js-share-grant-edit">Edit</button>
            <button type="button" class="btn sm danger js-share-grant-revoke">Revoke</button>
          </td>
        </tr>`;
        }).join("");
        setChildMarkup(wrap, `<div class="table-wrap"><table class="t"><thead><tr><th>Device</th><th>Grantee</th><th>View</th><th>Operate</th><th>Actions</th></tr></thead><tbody>${body}</tbody></table></div>`);
      } catch (e) {
        setChildMarkup(wrap, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    };
    const renderShareUserPickList = () => {
      const userListEl = $("#shareUserList", view);
      if (!userListEl) return;
      const preserve = /* @__PURE__ */ new Map();
      $$("input[type='checkbox']", userListEl).forEach((inp) => {
        const v = String(inp.value || "").trim();
        if (!inp.disabled && v) preserve.set(v, !!inp.checked);
      });
      if (!shareModalUsersCache.length) {
        setChildMarkup(userListEl, `<p class="muted">No eligible users.</p>`);
        return;
      }
      const selIds = $$("#shareDeviceList input[type='checkbox']", view).filter((x) => x.checked && !x.disabled).map((x) => String(x.value || "").trim()).filter(Boolean);
      const locked = granteesFullyCoveringDevices(selIds, overviewShareItems);
      const eg = shareModalEditSpec;
      const editUser = eg ? String(eg.grantee_username || "").trim() : "";
      setChildMarkup(
        userListEl,
        shareModalUsersCache.map((x) => {
          const u = String(x.username || "").trim();
          const uname = escapeHtml(u);
          const role = escapeHtml(x.role || "user");
          const isEditUser = !!(eg && editUser && u === editUser);
          const isLocked = !isEditUser && selIds.length > 0 && locked.has(u);
          const checked = isEditUser ? true : !!preserve.get(u);
          const dis = isLocked || isEditUser ? "disabled" : "";
          const lockNote = isLocked ? ` <span class="muted" title="Already has ACL on every selected device">(already shared)</span>` : "";
          const cls = isLocked ? "grp-pick-item is-grant-locked" : "grp-pick-item";
          return `<label class="${cls}"><input type="checkbox" value="${uname}" ${checked ? "checked" : ""} ${dis}/> <span>${uname} <span class="mono">(${role})</span>${lockNote}</span></label>`;
        }).join("") || `<p class="muted">No active admin/user accounts.</p>`
      );
    };
    const openShareModal = async (prefillGroup, prefillOwner, editSpec) => {
      if (!shareModalEl) return;
      shareModalEditSpec = editSpec && typeof editSpec === "object" ? editSpec : null;
      const editDid = shareModalEditSpec ? String(shareModalEditSpec.device_id || "").trim() : "";
      sharePrefillGroup = String(prefillGroup || "").trim();
      sharePrefillOwner = String(prefillOwner || "").trim();
      const devListEl = $("#shareDeviceList", view);
      const userListEl = $("#shareUserList", view);
      const hintEl = $("#shareTargetHint", view);
      const statEl = $("#shareBatchStat", view);
      const titleEl = $("#shareModalTitle", view);
      const noteEl = $("#shareEditNote", view);
      if (!devListEl || !userListEl || !hintEl || !statEl) return;
      statEl.textContent = "";
      if (titleEl) titleEl.textContent = shareModalEditSpec ? "Edit device share" : "Share devices / group";
      if (noteEl) {
        if (shareModalEditSpec) {
          noteEl.style.display = "block";
          noteEl.textContent = `Device ${editDid} \xB7 grantee ${String(shareModalEditSpec.grantee_username || "")} \u2014 adjust permissions and apply.`;
        } else {
          noteEl.style.display = "none";
          noteEl.textContent = "";
        }
      }
      if (shareModalEditSpec) {
        hintEl.textContent = "Permissions apply to this device\u2013user pair (UPSERT). Group/fleet semantics stay with the owning tenant.";
        const pv = $("#sharePermView", view);
        const po = $("#sharePermOperate", view);
        if (pv) pv.checked = !!shareModalEditSpec.can_view;
        if (po) po.checked = !!shareModalEditSpec.can_operate;
      } else {
        hintEl.textContent = sharePrefillGroup ? `Prefilling devices in \u201C${sharePrefillGroup}\u201D \u2014 still device-level ACL only (not a \u201Cgroup share\u201D).` : "Select devices and users. Grants are per-device; recipients never inherit your group keys or group-card settings. Users already fully covered on the current device selection are locked \u2014 use Edit in the table.";
        const pv = $("#sharePermView", view);
        const po = $("#sharePermOperate", view);
        if (pv) pv.checked = true;
        if (po) po.checked = false;
      }
      const picked = new Set(
        sharePrefillGroup && !shareModalEditSpec ? groupDeviceIdsFromList(sharePrefillGroup, sharePrefillOwner).map(String) : []
      );
      if (shareModalEditSpec) {
        const row = devices.find((d) => String(d.device_id) === editDid);
        setChildMarkup(
          devListEl,
          row ? groupDeviceRow(row, { checked: true, disabled: true }) : `<label class="grp-pick-item grp-pick-item--device"><input type="checkbox" class="grp-pick-chk" value="${escapeHtml(editDid)}" checked disabled /><span class="grp-pick-text"><span class="grp-pick-name">${escapeHtml(editDid)}</span><span class="grp-pick-id mono">${escapeHtml(editDid)}</span></span></label>`
        );
      } else {
        setChildMarkup(
          devListEl,
          devices.filter((d) => !d.is_shared).map((d) => groupDeviceRow(d, { checked: picked.has(String(d.device_id)), disabled: false })).filter(Boolean).join("") || `<p class="muted">No own devices available.</p>`
        );
      }
      if (!shareDevChangeBound) {
        shareDevChangeBound = true;
        devListEl.addEventListener("change", () => {
          if (shareModalEl && shareModalEl.style.display === "flex" && !shareModalEditSpec) renderShareUserPickList();
        });
      }
      await refreshOverviewShareItemsSilently();
      setChildMarkup(userListEl, `<p class="muted">Loading users\u2026</p>`);
      try {
        const u = await api("/auth/users", { timeoutMs: 16e3 });
        shareModalUsersCache = (u.items || []).filter((x) => {
          const role = String(x.role || "");
          const st = String(x.status || "active");
          if (!(st === "active" || st === "")) return false;
          if (state.me && state.me.role === "admin") return role === "user";
          return role === "admin" || role === "user";
        });
        renderShareUserPickList();
      } catch (e) {
        shareModalUsersCache = [];
        setChildMarkup(userListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
      const allDev = $("#shareSelAllDevices", view);
      const allUsr = $("#shareSelAllUsers", view);
      if (allDev) {
        allDev.checked = false;
        allDev.disabled = !!shareModalEditSpec;
        allDev.onchange = () => {
          $$("#shareDeviceList input[type='checkbox']:not([disabled])", view).forEach((x) => {
            x.checked = !!allDev.checked;
          });
          if (!shareModalEditSpec) renderShareUserPickList();
        };
      }
      if (allUsr) {
        allUsr.checked = false;
        allUsr.onchange = () => {
          $$("#shareUserList input[type='checkbox']:not([disabled])", view).forEach((x) => {
            x.checked = !!allUsr.checked;
          });
        };
      }
      shareModalEl.style.display = "flex";
    };
    const closeShareModal = () => {
      if (shareModalEl) shareModalEl.style.display = "none";
      shareModalEditSpec = null;
      const allDev = $("#shareSelAllDevices", view);
      if (allDev) allDev.disabled = false;
      const titleEl = $("#shareModalTitle", view);
      if (titleEl) titleEl.textContent = "Share devices / group";
      const noteEl = $("#shareEditNote", view);
      if (noteEl) {
        noteEl.style.display = "none";
        noteEl.textContent = "";
      }
    };
    $("#grpNew", view).addEventListener("click", () => openGroupModal(""));
    $("#gmCancel", view).addEventListener("click", closeGroupModal);
    const grpShareOpenBtn = $("#grpShareOpen", view);
    if (grpShareOpenBtn) grpShareOpenBtn.addEventListener("click", () => openShareModal("", "", null));
    const grpShareRefreshBtn = $("#grpShareRefresh", view);
    if (grpShareRefreshBtn) grpShareRefreshBtn.addEventListener("click", () => loadOverviewShareGrants());
    const shareGrantsWrap = $("#shareGrantsTableWrap", view);
    if (shareGrantsWrap) {
      shareGrantsWrap.addEventListener("click", async (ev) => {
        const btn = ev.target.closest("button");
        if (!btn) return;
        const tr = btn.closest("tr");
        if (!tr) return;
        const device_id = tr.getAttribute("data-device-id") || "";
        const grantee_username = tr.getAttribute("data-grantee") || "";
        if (!device_id || !grantee_username) return;
        const row = overviewShareItems.find((x) => String(x.device_id) === device_id && String(x.grantee_username) === grantee_username);
        if (btn.classList.contains("js-share-grant-edit")) {
          openShareModal("", "", row ? {
            device_id: row.device_id,
            grantee_username: row.grantee_username,
            can_view: !!Number(row.can_view),
            can_operate: !!Number(row.can_operate)
          } : {
            device_id,
            grantee_username,
            can_view: true,
            can_operate: false
          });
          return;
        }
        if (btn.classList.contains("js-share-grant-revoke")) {
          if (!confirm(`Revoke share for ${grantee_username} on ${device_id}?`)) return;
          try {
            await api(`/admin/devices/${encodeURIComponent(device_id)}/share/${encodeURIComponent(grantee_username)}`, { method: "DELETE" });
            toast("Share revoked", "ok");
            await loadOverviewShareGrants();
            await refreshOverviewShareItemsSilently();
            try {
              bustDeviceListCaches();
            } catch (_) {
            }
          } catch (e) {
            toast(e.message || e, "err");
          }
        }
      });
    }
    const shareCancelBtn = $("#shareModalCancel", view);
    if (shareCancelBtn) shareCancelBtn.addEventListener("click", closeShareModal);
    const shareApplyBtn = $("#shareModalApply", view);
    if (shareApplyBtn) {
      shareApplyBtn.addEventListener("click", async () => {
        const statEl = $("#shareBatchStat", view);
        const deviceIds = $$("#shareDeviceList input[type='checkbox']", view).filter((x) => x.checked).map((x) => String(x.value || "").trim()).filter(Boolean);
        const usernames = $$("#shareUserList input[type='checkbox']", view).filter((x) => x.checked).map((x) => String(x.value || "").trim()).filter(Boolean);
        const canView = !!$("#sharePermView", view)?.checked;
        const canOperate = !!$("#sharePermOperate", view)?.checked;
        if (!deviceIds.length) {
          toast("Select at least one device", "err");
          return;
        }
        if (!usernames.length) {
          toast("Select at least one user", "err");
          return;
        }
        if (!canView && !canOperate) {
          toast("Select at least one permission", "err");
          return;
        }
        const total = deviceIds.length * usernames.length;
        if (statEl) statEl.textContent = `Applying ${total} share grants\u2026`;
        const res = await grantShareMatrix(
          deviceIds,
          usernames,
          { can_view: canView, can_operate: canOperate },
          (p) => {
            if (statEl) statEl.textContent = `Applied ${p.idx}/${p.total} \xB7 ok ${p.ok} \xB7 failed ${p.fail}`;
          }
        );
        const ok = Number(res.ok || 0);
        const fail = Number(res.fail || 0);
        if (fail === 0) {
          toast(`Sharing applied (${ok}/${total})`, "ok");
          closeShareModal();
          loadOverviewShareGrants();
          try {
            bustDeviceListCaches();
          } catch (_) {
          }
        } else {
          toast(`Sharing done with failures (${ok} ok, ${fail} failed)`, "warn");
          loadOverviewShareGrants();
        }
      });
    }
    $("#gmSave", view).addEventListener("click", async () => {
      const key = canonicalGroupKey($("#gmKey", view).value || "");
      if (!key) {
        toast("Group key required", "err");
        return;
      }
      const oldMetaKey = String(editingGroup || "").trim();
      const oldParsed = parseGroupMetaKey(oldMetaKey);
      const oldEntry = oldMetaKey && Object.prototype.hasOwnProperty.call(meta, oldMetaKey) ? meta[oldMetaKey] : null;
      const display_name = String($("#gmName", view).value || "").trim();
      const owner_name = String($("#gmOwner", view).value || "").trim();
      const phone = String($("#gmPhone", view).value || "").trim();
      const email = String($("#gmEmail", view).value || "").trim();
      const picks = Array.from($$("#gmDevices input[type='checkbox']", view)).filter((x) => x.checked).map((x) => String(x.value || "").trim());
      let tenantForMeta = oldParsed.tenantOwner || "";
      if (state.me && state.me.role === "superadmin") {
        for (const id of picks) {
          const dev = byId.get(String(id));
          const o = dev && String(dev.owner_admin || "").trim();
          if (o) {
            tenantForMeta = o;
            break;
          }
        }
      }
      const newMetaKey = groupCardMetaKey(key, tenantForMeta);
      if (groupSharedByNotificationKey(key).length > 0) {
        const keepIds = oldEntry && Array.isArray(oldEntry.device_ids) ? oldEntry.device_ids.map((x) => String(x)) : [];
        if (oldMetaKey && oldMetaKey !== newMetaKey && meta[oldMetaKey]) delete meta[oldMetaKey];
        meta[newMetaKey] = { display_name, owner_name, phone, email, device_ids: keepIds };
        saveGroupMeta(meta);
        try {
          bustDeviceListCaches();
        } catch (_) {
        }
        closeGroupModal();
        renderGroups();
        toast("Group card updated (shared group \u2014 device list is owner-managed)", "ok");
        return;
      }
      const previousDeviceIds = oldMetaKey ? groupDeviceIdsFromList(oldParsed.groupKey, oldParsed.tenantOwner) : [];
      if (picks.length > 0) {
        try {
          for (const id of picks) {
            await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: key } });
          }
          const nextSet = new Set(picks);
          for (const id of previousDeviceIds) {
            if (!nextSet.has(id)) {
              await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: "" } });
            }
          }
        } catch (e) {
          toast(e.message || e, "err");
          return;
        }
      } else {
        for (const id of previousDeviceIds) {
          try {
            await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: "" } });
          } catch (e) {
            toast(e.message || e, "err");
            return;
          }
        }
      }
      if (oldMetaKey && oldMetaKey !== newMetaKey && meta[oldMetaKey]) delete meta[oldMetaKey];
      meta[newMetaKey] = { display_name, owner_name, phone, email, device_ids: picks };
      saveGroupMeta(meta);
      try {
        bustDeviceListCaches();
      } catch (_) {
      }
      closeGroupModal();
      renderGroups();
      toast("Group saved \u2014 device notification groups synced for sibling alarm fan-out", "ok");
    });
    groupCardsEl.addEventListener("click", async (ev) => {
      const btn = ev.target.closest("button");
      if (btn) {
        const slot = readSlotFromBtn(btn);
        const g2 = slot.groupKey;
        if (!g2) return;
        if (btn.classList.contains("js-edit-group")) {
          openGroupModal(slot.metaKey);
          return;
        }
        if (btn.classList.contains("js-group-settings")) {
          openSettingsModal(slot);
          return;
        }
        if (btn.classList.contains("js-share-group")) {
          if (!(state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users")))) {
            toast("No sharing permission", "err");
            return;
          }
          openShareModal(g2, slot.tenantOwner, null);
          return;
        }
        if (btn.classList.contains("js-del-group")) {
          if (groupSharedBySlot(slot).length > 0) {
            toast("Shared group cannot be deleted", "err");
            return;
          }
          if (!confirm(`Delete group card "${g2}"?`)) return;
          try {
            await deleteGroupCard(g2, slot.tenantOwner);
            if (slot.metaKey && meta[slot.metaKey]) delete meta[slot.metaKey];
            saveGroupMeta(meta);
            renderGroups();
            toast("Group deleted", "ok");
          } catch (e) {
            toast(e.message || e, "err");
          }
          return;
        }
        if (!can("can_alert")) {
          toast("No can_alert capability", "err");
          return;
        }
        const ids = groupDeviceIdsFromSlot(slot);
        if (ids.length === 0) {
          toast("No devices in this group", "warn");
          return;
        }
        const action = btn.classList.contains("js-alert-on") ? "on" : "off";
        if (!confirm(`${action === "on" ? "Open" : "Close"} alarm for ${ids.length} devices in ${g2}?`)) return;
        try {
          if (action === "on") {
            const payload = groupTriggerPayloadFromSettings(groupSettingsMap.get(slot.metaKey) || {});
            await runGroupApplyOnAction({
              groupKey: g2,
              ownerAdmin: slot.tenantOwner,
              payload,
              apiCaps: groupApiCaps,
              saveApiCaps: saveGroupApiCaps,
              tryApplyRoute: (gk, oa) => tryGroupApiCall(
                groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}/apply`, oa),
                { method: "POST" }
              ),
              applyFallback: applyGroupSettingsFallback
            });
          } else {
            const prevTimer = groupDelayTimers.get(slot.metaKey);
            if (prevTimer) {
              clearTimeout(prevTimer);
              groupDelayTimers.delete(slot.metaKey);
            }
            await api("/alerts", { method: "POST", body: { action, duration_ms: DEFAULT_REMOTE_SIREN_MS, device_ids: ids } });
          }
          toast(`${action === "on" ? "Alarm ON" : "Alarm OFF"} \xB7 ${ids.length}`, "ok");
        } catch (e) {
          toast(e.message || e, "err");
        }
        return;
      }
      const card = ev.target.closest(".js-group-card");
      if (!card) return;
      const g = card.dataset.group || "";
      if (!g) return;
      const ow = String(card.getAttribute("data-owner") || "").trim();
      location.hash = `#/group/${encodeURIComponent(g)}${ow ? `?owner=${encodeURIComponent(ow)}` : ""}`;
    });
    const OVERVIEW_LIVE_MS = 7500;
    const refreshOverviewLive = async () => {
      if (!isRouteCurrent(routeSeq)) return;
      try {
        bustApiGetCachedPrefix("/dashboard/overview");
        bustApiGetCachedPrefix("/devices");
        const [ovN, listN] = await Promise.all([
          api("/dashboard/overview", { timeoutMs: 2e4, retries: 2 }),
          api("/devices", { timeoutMs: 2e4, retries: 2 })
        ]);
        if (!isRouteCurrent(routeSeq)) return;
        ov = ovN || ov;
        list = listN || list;
        state.overviewCache = { ov, list, ts: Date.now() };
        devices = Array.isArray(list.items) ? list.items.slice() : [];
        byId = new Map(devices.map((d) => [String(d.device_id), d]));
        const hh2 = state.health || {};
        const httpOk2 = !!(hh2.ok ?? true);
        const mqConnected2 = !!(hh2.mqtt_connected ?? ov.mqtt_connected);
        const mqQDepth2 = Number(hh2.mqtt_ingest_queue_depth || 0);
        const mqDropped2 = Number(hh2.mqtt_ingest_dropped || 0);
        const totalDevices2 = Number(ov.total_devices != null ? ov.total_devices : devices.length);
        const onlineDevices2 = Number(ov.presence && ov.presence.online != null ? ov.presence.online : devices.filter(isOnline).length);
        const offlineDevices2 = Math.max(0, totalDevices2 - onlineDevices2);
        const txBps2 = Number(ov.throughput && ov.throughput.tx_bps_total || 0);
        const rxBps2 = Number(ov.throughput && ov.throughput.rx_bps_total || 0);
        const bps2 = (v) => {
          v = Number(v || 0);
          if (v < 1024) return `${v.toFixed(0)} B/s`;
          if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
          return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
        };
        const mqStatus2 = !mqConnected2 ? "Disconnected" : mqDropped2 > 0 || mqQDepth2 >= 300 ? "Warning" : "Healthy";
        const mqClass2 = !mqConnected2 ? "revoked" : mqStatus2 === "Warning" ? "offline" : "online";
        patchOverviewHeader({
          server: `${httpOk2 ? "HTTP OK" : "HTTP DOWN"} \xB7 ${mqConnected2 ? "MQTT UP" : "MQTT DOWN"}`,
          devices: totalDevices2,
          online: onlineDevices2,
          offline: offlineDevices2,
          tx: bps2(txBps2),
          rx: bps2(rxBps2),
          queue: mqQDepth2,
          dropped: mqDropped2,
          risk: mqStatus2,
          riskClass: mqClass2
        });
        syncGroupMetaWithDevices(meta, devices);
        saveGroupMeta(meta);
        repopOvOwnerDatalist();
        renderGroups();
      } catch (_) {
      }
    };
    scheduleRouteTicker(routeSeq, "overview-live", refreshOverviewLive, OVERVIEW_LIVE_MS);
    const ovOwnerInp = $("#ovOwnerFilter", view);
    const ovOwnerClr = $("#ovOwnerClear", view);
    if (ovOwnerInp && state.me && state.me.role === "superadmin") {
      repopOvOwnerDatalist();
      const onOwnerFilt = () => {
        ownerFilterQ = String(ovOwnerInp.value || "");
        renderGroups();
      };
      ovOwnerInp.addEventListener("input", onOwnerFilt);
      ovOwnerInp.addEventListener("change", onOwnerFilt);
      if (ovOwnerClr) {
        ovOwnerClr.addEventListener("click", () => {
          ovOwnerInp.value = "";
          ownerFilterQ = "";
          renderGroups();
        });
      }
    }
    renderGroups();
    if (state.me && (state.me.role === "superadmin" || state.me.role === "admin" && can("can_manage_users"))) {
      loadOverviewShareGrants();
    }
  });
  registerRoute("register", async (view) => {
    setCrumb("Register admin");
    document.body.dataset.auth = "none";
    const cleanSignupMessage = (raw) => {
      const s = String(raw || "").trim();
      if (!s) return "Request failed. Please try again.";
      const l = s.toLowerCase();
      if (l.includes("already exists")) return "Username or email already exists.";
      if (l.includes("invalid") && l.includes("email")) return "Email format is invalid.";
      if (l.includes("networkerror") || l.includes("failed to fetch")) return "Network error. Please check server/API.";
      return s.replace(/^error:\s*/i, "");
    };
    mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("register")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner">
      <div class="auth-card auth-card--panel auth-card--wide" data-auth-card>
        <header class="auth-card__head">
          <h1 class="auth-card__title">Create admin</h1>
          <p class="auth-card__lead">Email verification, then sign in.</p>
        </header>
        <div class="auth-card__body">
          <p class="auth-card__note muted">After verification, you can sign in immediately.</p>
          <ol class="auth-steps" aria-label="Steps">
            <li id="r_step_ind1" class="is-active"><span class="auth-steps__n">1</span><span class="auth-steps__t">Your details</span></li>
            <li id="r_step_ind2"><span class="auth-steps__n">2</span><span class="auth-steps__t">Email code</span></li>
          </ol>
          <div id="rStep1">
            <label class="field"><span>Username</span><input id="r_user" autocomplete="username" placeholder="2\u201364 chars, letters \xB7 digits \xB7 ._-"/></label>
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
            <label class="field field--spaced"><span>Verification code</span><input id="r_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code" placeholder="6\u201312 digits"/></label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="button" id="r_verify">Complete signup</button>
              <button class="btn secondary btn-tap btn-block" type="button" id="r_resend">Resend code</button>
              <button class="btn ghost btn-tap btn-block" type="button" id="r_back_step">Edit details</button>
            </div>
            <p class="auth-card__msg muted" id="r_msg2" aria-live="polite"></p>
          </div>
        </div>
      </div>
      ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
    const m1 = $("#r_msg1"), m2 = $("#r_msg2");
    $("#r_start").addEventListener("click", async () => {
      m1.textContent = "";
      const body = {
        username: $("#r_user").value.trim(),
        password: $("#r_pass").value,
        email: $("#r_email").value.trim()
      };
      if (!body.username || !body.password || !body.email) {
        m1.textContent = "Username, password, and email required";
        return;
      }
      try {
        const r = await fetch(apiBase() + "/auth/signup/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        sessionStorage.setItem("croc.signup_user", body.username);
        $("#r_shown_email").textContent = body.email;
        $("#r_step_ind1").classList.remove("is-active");
        $("#r_step_ind2").classList.add("is-active");
        $("#rStep1").style.display = "none";
        $("#rStep2").style.display = "";
      } catch (e) {
        m1.textContent = cleanSignupMessage(e.message || e);
      }
    });
    $("#r_verify").addEventListener("click", async () => {
      m2.textContent = "";
      const body = {
        username: sessionStorage.getItem("croc.signup_user") || "",
        email_code: $("#r_email_code").value.trim()
      };
      try {
        const r = await fetch(apiBase() + "/auth/signup/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        setChildMarkup(m2, `<span class="badge online">OK</span> Redirecting to sign in\u2026`);
        scheduleRouteRedirect(1500, "#/login");
      } catch (e) {
        m2.textContent = cleanSignupMessage(e.message || e);
      }
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
      if (!username) {
        m2.textContent = "Complete step 1 first";
        return;
      }
      try {
        const r = await fetch(apiBase() + "/auth/code/resend", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, channel: "email", purpose: "signup" })
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || `${r.status}`);
        m2.textContent = "Code resent";
      } catch (e) {
        m2.textContent = cleanSignupMessage(e.message || e);
      }
    });
  });
  async function renderSignalsPage(view, _args, routeSeq) {
    setCrumb("Signals");
    mountView(view, `
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
      <div id="sigList"><p class="muted">Loading\u2026</p></div>
    </div>`);
    const reload = async () => {
      const hours = parseInt($("#sig_hours").value, 10) || 168;
      const qs = new URLSearchParams({ limit: "200", since_hours: String(hours) });
      try {
        if (!isRouteCurrent(routeSeq)) return;
        const [d, sumR] = await Promise.all([
          api("/activity/signals?" + qs.toString(), { timeoutMs: 24e3 }),
          api("/alarms/summary", { timeoutMs: 16e3 }).catch(() => ({ last_24h: 0, last_7d: 0, top_sources_7d: [] }))
        ]);
        if (!isRouteCurrent(routeSeq)) return;
        const sigSummaryEl = $("#sigSummary", view);
        const sigListEl = $("#sigList", view);
        if (!sigSummaryEl || !sigListEl) return;
        setHtmlIfChanged(sigSummaryEl, [
          ["Alarms 24h", sumR.last_24h || 0, "device-side alarm rows"],
          ["Alarms 7d", sumR.last_7d || 0, "same scope"],
          ["Top source 7d", (sumR.top_sources_7d || []).slice(0, 1).map((x) => `${x.source_id} \xD7 ${x.c}`).join("") || "\u2014", "by count"]
        ].map(([k, v, s]) => `<div class="stat"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div><div class="sub">${escapeHtml(s)}</div></div>`).join(""));
        const items = d.items || [];
        const whoLbl = (w) => ({
          remote_button: "GPIO / local button",
          network: "MQTT / network",
          api: "API / automation"
        })[w] || w;
        setHtmlIfChanged(sigListEl, items.length === 0 ? `<p class="muted audit-empty">No rows in this window.</p>` : `<div class="audit-feed">${items.map((a) => {
          const dev = a.device_id === "*" ? "(bulk)" : a.device_id;
          const link = a.device_id && a.device_id !== "*" ? `<a class="mono audit-target" href="#/devices/${encodeURIComponent(a.device_id)}">${escapeHtml(dev)}</a>` : escapeHtml(dev);
          const em = a.email_sent ? "queued" : a.email_detail || "\u2014";
          const fo = a.kind && a.kind.startsWith("bulk") ? String(a.fanout_count || 0) : String(a.fanout_count ?? "\u2014");
          const whoS = a.kind === "device_alarm" ? whoLbl(a.who) : a.who || "\u2014";
          const tShort = fmtTs(a.ts);
          return `<article class="audit-item">
            <div class="audit-item-top">
              <div class="audit-time">
                <span class="audit-ts mono">${escapeHtml(tShort)}</span>
                <span class="muted audit-rel">${escapeHtml(fmtRel(a.ts))}</span>
              </div>
              <span class="chip">${escapeHtml(a.what || a.kind || "")}</span>
              <span class="chip">${escapeHtml(a.zone || "all")}</span>
            </div>
            <div class="audit-item-line" style="flex-wrap:wrap;align-items:center;gap:6px">
              <span class="mono">${link}</span>
              <span class="chip">${escapeHtml(a.display_label || "\u2014")}</span>
              <span class="chip">${escapeHtml(a.notification_group || "\u2014")}</span>
            </div>
            <div class="audit-item-line muted" style="font-size:12.5px">Who: ${escapeHtml(String(whoS))} \xB7 Fan-out: ${escapeHtml(fo)} \xB7 Email: ${escapeHtml(em)}</div>
          </article>`;
        }).join("")}</div>`);
      } catch (e) {
        if (!isRouteCurrent(routeSeq)) return;
        toast(e.message || e, "err");
      }
    };
    $("#sig_reload").addEventListener("click", reload);
    reload();
    scheduleRouteTicker(routeSeq, "signals-live-reload", reload, 1e4);
  }
  registerRoute("signals", renderSignalsPage);
  registerRoute("site", async (view, _args, routeSeq) => {
    setCrumb("Site \xB7 owners & groups / \u7AD9\u70B9");
    if (!(state.me && state.me.role === "superadmin")) {
      mountView(view, `<div class="card"><p class="muted">Superadmin only.</p></div>`);
      return;
    }
    let ownerQ = String(window.__routeQuery && window.__routeQuery.get("owner") || "").trim();
    let allDevs = [];
    try {
      const r = await api("/devices", { timeoutMs: 2e4 });
      if (!isRouteCurrent(routeSeq)) return;
      allDevs = Array.isArray(r.items) ? r.items.slice() : [];
    } catch (e) {
      if (!isRouteCurrent(routeSeq)) return;
      mountView(view, `<div class="card"><p class="badge offline">${escapeHtml(e.message || e)}</p></div>`);
      return;
    }
    const applyFilter = (list, q) => {
      const s = String(q || "").trim().toLowerCase();
      if (!s) return list;
      return list.filter((d) => String(d.owner_admin || "").toLowerCase().includes(s));
    };
    const filtered = () => applyFilter(allDevs, ownerQ);
    const ownersU = [...new Set(allDevs.map((d) => String(d.owner_admin || "").trim()).filter(Boolean))].sort();
    const fd = filtered();
    const slots = buildGroupSlotsFromDeviceList(fd);
    const rows = fd.map((d) => {
      const on = isOnline(d);
      const did = encodeURIComponent(d.device_id);
      return `<tr><td class="mono"><a href="#/devices/${did}">${escapeHtml(d.device_id)}</a></td><td class="mono">${escapeHtml(d.owner_admin || "\u2014")}</td><td>${escapeHtml(d.notification_group || "\u2014")}</td><td>${escapeHtml(d.zone || "")}</td><td><span class="badge ${on ? "online" : "offline"}">${on ? "on" : "off"}</span></td></tr>`;
    }).join("");
    const grpRows = slots.map((s) => {
      const owq = s.tenantOwner ? `?owner=${encodeURIComponent(s.tenantOwner)}` : "";
      return `<tr><td class="mono"><a href="#/group/${encodeURIComponent(s.groupKey)}${owq}">${escapeHtml(s.groupKey)}</a></td><td class="mono">${escapeHtml(s.tenantOwner || "\u2014")}</td><td class="mono muted">${escapeHtml(s.metaKey)}</td></tr>`;
    }).join("");
    mountView(view, `
    <section class="card">
      <h2 class="ui-section-title" style="margin:0">Site / \u7AD9\u70B9</h2>
      <p class="muted" style="margin:8px 0 0">Search <strong>owner admin</strong> username (substring). Lists devices and <strong>notification groups</strong> under that filter \u2014 same slot keys as Overview group cards.</p>
      <div class="inline-form" style="margin-top:12px;flex-wrap:wrap;gap:10px;align-items:flex-end">
        <label class="field grow"><span>Owner contains</span>
          <input type="search" id="siteOwnerQ" value="${escapeHtml(ownerQ)}" placeholder="e.g. dan" list="siteOwnerDl" autocomplete="off" />
          <datalist id="siteOwnerDl">${ownersU.map((o) => `<option value="${escapeHtml(o)}"></option>`).join("")}</datalist>
        </label>
        <button type="button" class="btn sm secondary btn-tap" id="siteOwnerClear">Clear</button>
        <button type="button" class="btn btn-tap" id="siteOwnerApply">Apply</button>
      </div>
    </section>
    <section class="card">
      <h3 style="margin:0 0 8px">Owners in fleet (${ownersU.length})</h3>
      <p class="muted" style="margin:0;font-size:12px">Unique <span class="mono">owner_admin</span> from API. Click a chip to filter.</p>
      <div class="row" style="gap:6px;flex-wrap:wrap;margin-top:10px">
        ${ownersU.map((o) => `<button type="button" class="chip js-site-owner-chip" data-o="${escapeHtml(o)}" style="cursor:pointer">${escapeHtml(o)}</button>`).join("")}
      </div>
    </section>
    <section class="card">
      <h3 style="margin:0 0 8px">Devices (${fd.length})</h3>
      <div class="table-wrap"><table class="t">
        <thead><tr><th>Device</th><th>Owner</th><th>Notification group</th><th>Zone</th><th>Presence</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="muted">No devices match.</td></tr>`}</tbody>
      </table></div>
    </section>
    <section class="card">
      <h3 style="margin:0 0 8px">Groups (${slots.length})</h3>
      <div class="table-wrap"><table class="t">
        <thead><tr><th>Group key</th><th>Tenant (slot)</th><th>Card meta-key</th></tr></thead>
        <tbody>${grpRows || `<tr><td colspan="3" class="muted">No groups in filter.</td></tr>`}</tbody>
      </table></div>
    </section>
  `);
    $("#siteOwnerApply", view).addEventListener("click", () => {
      ownerQ = String($("#siteOwnerQ", view)?.value || "").trim();
      location.hash = ownerQ ? `#/site?owner=${encodeURIComponent(ownerQ)}` : "#/site";
    });
    $("#siteOwnerClear", view).addEventListener("click", () => {
      location.hash = "#/site";
    });
    $("#siteOwnerQ", view).addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        $("#siteOwnerApply", view).click();
      }
    });
    $$(".js-site-owner-chip", view).forEach((btn) => {
      btn.addEventListener("click", () => {
        const o = btn.getAttribute("data-o") || "";
        location.hash = o ? `#/site?owner=${encodeURIComponent(o)}` : "#/site";
      });
    });
  });
  registerRoute("telegram", async (view) => {
    setCrumb("Telegram");
    if (!hasRole("user")) {
      mountView(view, `<div class="card"><p class="muted">Sign in required.</p></div>`);
      return;
    }
    mountView(view, `
    <div class="ui-shell telegram-shell">
    <div class="card">
      <div class="ui-section-head">
        <div>
          <h2 class="ui-section-title">Telegram connect</h2>
          <p class="ui-section-sub">No password in Telegram. Generate link, open chat, send <span class="mono">/start</span>, done.</p>
        </div>
        <div class="ui-section-actions">
          <button class="btn" id="tgGenLink">Generate connect link</button>
          <button class="btn secondary" id="tgReloadMine">Refresh bindings</button>
        </div>
      </div>
      <div id="tgLinkBox" style="margin-top:10px"></div>
    </div>
    <div class="card">
      <div class="ui-section-head">
        <div>
          <h3 class="ui-section-title">My chat bindings</h3>
          <p class="ui-section-sub">Enable, disable, or unbind your own Telegram chats.</p>
        </div>
      </div>
      <div id="tgMineList"></div>
    </div>
    <div class="card">
      <div class="ui-section-head">
        <div>
          <h3 class="ui-section-title">Manual bind (fallback)</h3>
          <p class="ui-section-sub">If deep link cannot open Telegram, use <span class="mono">/start</span> to get chat_id, then bind manually.</p>
        </div>
      </div>
      <div class="inline-form">
        <label class="field"><span>chat_id</span><input id="tgManualChatId" placeholder="e.g. 2082431201 or -100xxxx" /></label>
        <label class="field"><span>Enabled</span><input id="tgManualEnabled" type="checkbox" checked /></label>
        <div class="row wide" style="justify-content:flex-end"><button class="btn" id="tgManualBind">Bind manually</button></div>
      </div>
    </div>
    </div>
  `);
    const mineEl = $("#tgMineList", view);
    const linkEl = $("#tgLinkBox", view);
    const loadMine = async () => {
      if (!mineEl) return;
      setChildMarkup(mineEl, `<p class="muted">Loading\u2026</p>`);
      try {
        const d = await api("/admin/telegram/bindings", { timeoutMs: 16e3 });
        const items = d.items || [];
        setChildMarkup(
          mineEl,
          items.length === 0 ? `<p class="muted">No bindings yet.</p>` : `<div class="table-wrap"><table class="t">
            <thead><tr><th>chat_id</th><th>enabled</th><th>updated</th><th></th><th></th></tr></thead>
            <tbody>${items.map((it) => `
              <tr>
                <td class="mono">${escapeHtml(it.chat_id || "")}</td>
                <td>${it.enabled ? `<span class="badge online">on</span>` : `<span class="badge offline">off</span>`}</td>
                <td>${escapeHtml(fmtTs(it.updated_at || it.created_at))}</td>
                <td><button class="btn sm secondary js-tg-toggle" data-chat="${escapeHtml(String(it.chat_id || ""))}" data-en="${it.enabled ? "1" : "0"}">${it.enabled ? "Disable" : "Enable"}</button></td>
                <td><button class="btn sm danger js-tg-unbind" data-chat="${escapeHtml(String(it.chat_id || ""))}">Unbind</button></td>
              </tr>`).join("")}</tbody>
          </table></div>`
        );
      } catch (e) {
        setChildMarkup(mineEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    };
    $("#tgGenLink", view).addEventListener("click", async () => {
      if (!linkEl) return;
      try {
        const r = await api("/telegram/link-token", { method: "POST", body: { enabled_on_bind: true } });
        const deep = r.deep_link || "";
        const openChat = r.open_chat_url || "";
        const payload = r.start_payload || "";
        setChildMarkup(
          linkEl,
          deep ? `<div class="ui-status-strip">
             <div class="ui-status-item"><div class="k">Step 1</div><div class="v"><a class="btn" href="${escapeHtml(openChat || deep)}" target="_blank" rel="noopener">Open bot chat</a></div></div>
             <div class="ui-status-item"><div class="k">Step 2</div><div class="v"><a class="btn secondary" href="${escapeHtml(deep)}" target="_blank" rel="noopener">Run one-click bind</a></div></div>
           </div>
           <p class="muted mono" style="margin-top:8px">${escapeHtml(deep)}</p>` : `<p class="muted">Set <span class="mono">TELEGRAM_BOT_USERNAME</span> on server, then retry.<br/>Fallback: send <span class="mono">/start ${escapeHtml(payload)}</span> in your bot chat.</p>`
        );
      } catch (e) {
        setChildMarkup(linkEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    });
    $("#tgManualBind", view).addEventListener("click", async () => {
      const chatId = ($("#tgManualChatId", view).value || "").trim();
      const enabled = !!$("#tgManualEnabled", view).checked;
      if (!chatId) {
        toast("Enter chat_id", "err");
        return;
      }
      try {
        await api("/admin/telegram/bind-self", { method: "POST", body: { chat_id: chatId, enabled } });
        toast("Bound", "ok");
        loadMine();
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $("#tgReloadMine", view).addEventListener("click", loadMine);
    mineEl.addEventListener("click", async (ev) => {
      const tgl = ev.target.closest(".js-tg-toggle");
      if (tgl) {
        const chat = tgl.dataset.chat || "";
        const enabled = !(tgl.dataset.en === "1");
        try {
          await api(`/admin/telegram/bindings/${encodeURIComponent(chat)}/enabled?enabled=${enabled ? "true" : "false"}`, { method: "PATCH" });
          toast(enabled ? "Enabled" : "Disabled", "ok");
          loadMine();
        } catch (e) {
          toast(e.message || e, "err");
        }
        return;
      }
      const del = ev.target.closest(".js-tg-unbind");
      if (del) {
        const chat = del.dataset.chat || "";
        if (!chat) return;
        if (!confirm(`Unbind chat ${chat}?`)) return;
        try {
          await api(`/admin/telegram/bindings/${encodeURIComponent(chat)}`, { method: "DELETE" });
          toast("Unbound", "ok");
          loadMine();
        } catch (e) {
          toast(e.message || e, "err");
        }
      }
    });
    loadMine();
  });
})();
