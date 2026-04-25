/* Croc Sentinel Console - SPA
 * Markup safety: escapeHtml(str) or hx`...${str}...` for any API/user text; mountView(el, html) for route shells (DOMParser + replaceChildren, no innerHTML).
 * Live stream: Events use fetch()+stream+Authorization (not EventSource URL+?token=) for reverse-proxy reliability. */
(function () {
  "use strict";

  // ------------------------------------------------------------------ const
  const LS = {
    token: "croc.token",
    user: "croc.user",
    role: "croc.role",
    zones: "croc.zones",
    theme: "croc.theme",
    sidebarCollapsed: "croc.sidebar.collapsed",
  };
  /** One-time: drop legacy JWT in localStorage; session uses HttpOnly cookie when API omits access_token. */
  try {
    const _m = "croc.auth.migrate_cookie_v1";
    if (!localStorage.getItem(_m)) {
      localStorage.removeItem(LS.token);
      localStorage.setItem(_m, "1");
    }
  } catch (_) {}
  const OFFLINE_MS = 90 * 1000;
  /** Default remote siren / group loud duration (3 min). Panic sibling fan-out default (5 min) matches server. */
  const DEFAULT_REMOTE_SIREN_MS = 180000;
  const DEFAULT_PANIC_FANOUT_MS = 300000;

  /** Sidebar: grouped by function (paths unchanged). Order: dashboard → live data → fleet actions → integrations & RBAC. */
  const NAV_GROUPS = [
    {
      title: "Dashboard",
      items: [
        { id: "overview", label: "Overview", ico: "◎", path: "#/overview", min: "user" },
        { id: "devices", label: "All devices", ico: "▢", path: "#/devices", min: "user" },
        { id: "site", label: "Site", ico: "⌁", path: "#/site", min: "superadmin" },
      ],
    },
    {
      title: "Monitoring",
      items: [
        { id: "signals", label: "Signals", ico: "◉", path: "#/signals", min: "user" },
        { id: "events", label: "Events", ico: "≈", path: "#/events", min: "user" },
        { id: "ota", label: "OTA (ops)", ico: "↑", path: "#/ota", min: "superadmin" },
      ],
    },
    {
      title: "Alerts & fleet",
      items: [
        { id: "alerts", label: "Siren", ico: "!", path: "#/alerts", min: "user" },
        { id: "activate", label: "Activate device", ico: "+", path: "#/activate", min: "admin" },
      ],
    },
    {
      title: "Account & admin",
      items: [
        { id: "account", label: "Account", ico: "◍", path: "#/account", min: "user" },
        { id: "telegram", label: "Telegram", ico: "✆", path: "#/telegram", min: "user" },
        { id: "audit", label: "Audit", ico: "≡", path: "#/audit", min: "admin" },
        { id: "admin", label: "Admin & users", ico: "☼", path: "#/admin", min: "admin" },
      ],
    },
  ];

  const ROLE_WEIGHT = { user: 1, admin: 2, superadmin: 3 };

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

  /** Public auth: left story panel + right form (v3 layout) */
  function authAsideHtml(kind) {
    const m = {
      login: {
        t: "Operations console",
        d: "Role-scoped monitoring, OTA, and device control in one place.",
        items: ["Audit-ready events", "Per-tenant device boundaries", "Real-time health"],
      },
      register: {
        t: "Admin workspace",
        d: "Email verification, then sign in to manage your fleet.",
        items: ["Isolated tenant data", "Verification + cooldown", "No shared MQTT bleed"],
      },
      recovery: {
        t: "Account recovery",
        d: "We send a one-time code to the email on file for this account.",
        items: ["Match username to email", "Code from your inbox", "Set a new password here"],
      },
      activate: {
        t: "Activate access",
        d: "An administrator created your user — confirm with the email we sent you.",
        items: ["One-time code", "Same inbox as the invite", "Then use Sign in"],
      },
    };
    const c = m[kind] || m.login;
    return `
      <aside class="auth-surface__side" aria-label="ESA">
        <div class="auth-surface__side-main">
        <div class="auth-surface__side-content">
          <div class="auth-surface__company" lang="en">
            <p class="auth-surface__company-eyebrow">Secured platform provider</p>
            <p class="auth-surface__wordmark" translate="no">ESA</p>
            <p class="auth-surface__company-line" lang="en">Private, secured operations and tenant-safe edge access — one platform.</p>
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

  // ------------------------------------------------------------------ state
  const state = {
    me: null,
    mqttConnected: false,
    health: null,
    overviewCache: null,
    routeSeq: 0,
  };

  const GROUP_CARD_TENANT_SEP = "\u001e";
  function normalizeGroupKeyStr(v) {
    return String(v == null ? "" : v).trim();
  }
  /** One logical group per string: trim + NFC + collapse internal whitespace (avoids duplicate group cards). */
  function canonicalGroupKey(v) {
    let s = normalizeGroupKeyStr(v);
    if (!s) return "";
    try {
      s = s.normalize("NFC");
    } catch (_) {}
    return s.replace(/\s+/g, " ");
  }
  /** Stable localStorage / UI key for a group card; superadmin always prefixes owning admin (avoids duplicate cards vs plain group key). */
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
  /** Group card slots from a device list (Overview / Site). */
  function buildGroupSlotsFromDeviceList(devList) {
    const acc = new Map();
    const isSuper = state.me && state.me.role === "superadmin";
    for (const d of (Array.isArray(devList) ? devList : [])) {
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

  /** Group cards (Overview) are stored in localStorage; keep in sync when device group changes in profile. */
  function groupMetaStorageKey() {
    return (state.me && state.me.username) ? `croc.group.meta.v2.${state.me.username}` : "croc.group.meta.v2.anon";
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
    } catch (_) {}
  }
  function removeDeviceIdFromAllGroupMeta(deviceId) {
    reconcileGroupMetaForDevice(deviceId, "");
  }

  /**
   * Single source of truth for group membership: device_state.notification_group from /devices.
   * - Overwrites each group's device_ids from the API.
   * - Keeps display_name / owner / contact for groups that still exist.
   * - Drops any local-only/stale group keys to avoid residual data after edits.
   */
  function syncGroupMetaWithDevices(meta, devices) {
    if (!meta || typeof meta !== "object") return meta;
    const list = Array.isArray(devices) ? devices : [];
    const isSuper = state.me && state.me.role === "superadmin";
    const notifMap = new Map();
    for (const d of list) {
      const g = canonicalGroupKey(d && d.notification_group);
      if (!g) continue;
      const ck = groupCardMetaKey(g, isSuper ? d.owner_admin : "");
      if (!notifMap.has(ck)) notifMap.set(ck, []);
      notifMap.get(ck).push(String(d.device_id));
    }
    for (const [ck, ids] of notifMap.entries()) {
      const prev = meta[ck] && typeof meta[ck] === "object" ? meta[ck] : {};
      let dn = (prev.display_name && String(prev.display_name).trim()) || "";
      if (!dn) {
        const gOnly = isSuper && ck.includes(GROUP_CARD_TENANT_SEP)
          ? ck.slice(ck.indexOf(GROUP_CARD_TENANT_SEP) + 1)
          : ck;
        dn = gOnly;
      }
      meta[ck] = {
        display_name: dn,
        owner_name: prev.owner_name != null ? String(prev.owner_name) : "",
        phone: prev.phone != null ? String(prev.phone) : "",
        email: prev.email != null ? String(prev.email) : "",
        device_ids: ids,
      };
    }
    for (const g of Object.keys(meta)) {
      if (!notifMap.has(g)) delete meta[g];
    }
    return meta;
  }

  /** Re-fetch /devices and reconcile group-card localStorage (after profile/delete cache bust). */
  let _groupMetaSyncTimer = null;
  let _groupMetaSyncChain = Promise.resolve();
  function syncGroupMetaFromServer() {
    if (!state.me) {
      return _groupMetaSyncChain;
    }
    _groupMetaSyncChain = _groupMetaSyncChain
      .then(async () => {
        if (!state.me) return;
        const r = await api("/devices", { timeoutMs: 18000, retries: 1 });
        let meta = {};
        try {
          const raw = localStorage.getItem(groupMetaStorageKey());
          meta = raw ? JSON.parse(raw) : {};
        } catch (_) { meta = {}; }
        if (!meta || typeof meta !== "object") meta = {};
        syncGroupMetaWithDevices(meta, (r && r.items) || []);
        localStorage.setItem(groupMetaStorageKey(), JSON.stringify(meta));
      })
      .catch(() => {});
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

  /** When MQTT is down, poll faster so the green dot tracks reality (not a 30s stale snapshot). */
  const HEALTH_POLL_SLOW_MS = 12000;
  const HEALTH_POLL_FAST_MS = 3500;

  function armHealthPoll() {
    clearHealthPollTimer();
    if (!state.me) return;
    const fast = state.mqttConnected === false;
    const ms = fast ? HEALTH_POLL_FAST_MS : HEALTH_POLL_SLOW_MS;
    healthPollTimer = setInterval(tickHealthIfVisible, ms);
  }

  /** Events page: align Live badge with EventSource state (no reconnect). */
  function syncEventsLiveBadge() {
    const live = document.getElementById("evLive");
    if (!live || !window.__evSSE) return;
    const es = window.__evSSE;
    if (es.readyState === EventSource.OPEN) {
      live.textContent = "Live";
      live.className = "badge online";
      live.title = "Live stream connected";
    } else if (es.readyState === EventSource.CONNECTING) {
      live.textContent = "Reconnecting…";
      live.className = "badge offline";
      live.title = "SSE reconnecting";
    }
  }

  // ------------------------------------------------------------------ utils
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /**
   * REST base URL. Production (Traefik + StripPrefix): index.html meta `croc-api-base` is `/api`.
   * Direct access on published API ports (no /api prefix): :8088 / :18088 / :18999.
   */
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

  /** Default ceiling so a stuck reverse-proxy / API cannot leave the SPA on “Loading…” forever. */
  const DEFAULT_API_TIMEOUT_MS = 45000;
  /** Route-level async guard: full page handlers may await several API calls (slow links / cold DB). */
  const ROUTE_RENDER_TIMEOUT_MS = 90000;

  /**
   * fetch() with AbortController timeout. opts.timeoutMs: number ms, false = no limit.
   */
  async function fetchWithDeadline(url, init, timeoutMs) {
    const baseInit = Object.assign({ credentials: "include" }, init || {});
    const limit = timeoutMs === false ? 0 : (timeoutMs != null ? timeoutMs : DEFAULT_API_TIMEOUT_MS);
    if (limit <= 0) return fetch(url, baseInit);
    const ac = new AbortController();
    const tid = setTimeout(() => ac.abort(), limit);
    try {
      return await fetch(url, Object.assign({}, baseInit, { signal: ac.signal }));
    } catch (e) {
      if (e && e.name === "AbortError") {
        throw new Error(
          `Request timed out after ${limit} ms — API slow or unreachable. Check browser Network tab, ` +
            "Nginx `proxy_connect_timeout` / `proxy_read_timeout`, and upstream service.",
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
    const s = String((err && err.message) || err || "").toLowerCase();
    return (
      s.includes("timed out") ||
      s.includes("networkerror") ||
      s.includes("failed to fetch") ||
      s.includes("load failed") ||
      s.includes("temporarily unavailable")
    );
  }
  function _isRetryableHttpStatus(code) {
    return code === 408 || code === 425 || code === 429 || code === 502 || code === 503 || code === 504;
  }

  function getToken() { return localStorage.getItem(LS.token) || ""; }
  function setToken(t) {
    t ? localStorage.setItem(LS.token, t) : localStorage.removeItem(LS.token);
    if (!t) {
      _groupMetaSyncChain = Promise.resolve();
    }
  }

  // ------------------------------------------------------------------ csrf
  // Backend default: cookie `sentinel_csrf` (NOT HttpOnly) + header `X-CSRF-Token`
  // (double-submit). Names overridable via <meta>; falls back to defaults that
  // match api/app.py CSRF_COOKIE_NAME / CSRF_HEADER_NAME.
  const CSRF_COOKIE_NAME = (function () {
    const m = document.querySelector('meta[name="croc-csrf-cookie"]');
    return (m && m.getAttribute("content") || "sentinel_csrf").trim() || "sentinel_csrf";
  })();
  const CSRF_HEADER_NAME = (function () {
    const m = document.querySelector('meta[name="croc-csrf-header"]');
    return (m && m.getAttribute("content") || "X-CSRF-Token").trim() || "X-CSRF-Token";
  })();
  let _csrfTokenMemory = "";
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
    } catch (_) {}
    return "";
  }
  function getCsrfToken() {
    if (_csrfTokenMemory) return _csrfTokenMemory;
    const c = _readCsrfCookie();
    if (c) _csrfTokenMemory = c;
    return _csrfTokenMemory;
  }
  function setCsrfToken(t) { _csrfTokenMemory = String(t || ""); }
  /** Best-effort refresh: GET /auth/csrf rotates cookie and returns the value. */
  async function refreshCsrfToken() {
    try {
      const r = await fetchWithDeadline(apiBase() + "/auth/csrf", { method: "GET" }, 12000);
      if (r && r.ok) {
        const j = await r.json().catch(() => ({}));
        if (j && j.csrf_token) {
          setCsrfToken(String(j.csrf_token));
          return _csrfTokenMemory;
        }
      }
    } catch (_) {}
    // Fallback: read whatever the server (re)set as cookie.
    const c = _readCsrfCookie();
    if (c) _csrfTokenMemory = c;
    return _csrfTokenMemory;
  }
  function _isWriteMethod(m) {
    const x = String(m || "GET").toUpperCase();
    return x !== "GET" && x !== "HEAD" && x !== "OPTIONS";
  }
  /** True only when the response failed CSRF (403 + body code). */
  function _isCsrfRejection(status, bodyText) {
    if (Number(status) !== 403) return false;
    const t = String(bodyText || "");
    if (t.indexOf("csrf_invalid") >= 0) return true;
    try {
      const j = JSON.parse(t);
      const code = j && (j.code || j.detail);
      if (typeof code === "string" && code.toLowerCase().indexOf("csrf") >= 0) return true;
    } catch (_) {}
    return false;
  }

  function escapeHtml(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  const _lastHtmlByEl = new WeakMap();

  /** Parsed HTML fragment (no assignment to Element.innerHTML). */
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

  /**
   * Tagged template: escapes every interpolation (use for any server/user-facing string).
   * Static HTML in template literals stays literal; only ${values} are escaped.
   */
  function hx(strings, ...values) {
    let out = "";
    for (let i = 0; i < strings.length; i++) {
      out += strings[i];
      if (i < values.length) out += escapeHtml(values[i]);
    }
    return out;
  }

  /** Replace a route container’s markup; caller must escape dynamic parts (escapeHtml / hx). */
  function mountView(el, html) {
    if (!el) return;
    el.replaceChildren(parseHtmlToFragment(String(html == null ? "" : html)));
  }

  /** Parse one SSE block (RFC 8895-style, LF / CRLF). */
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

  /** Read chunked text/event-stream; invokes onFrame(type, payload) where type is "message"|"ping". */
  const SSE_PARSE_BUF_MAX = 262144;
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
      for (;;) {
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

  /** All dashboard clocks: Asia/Kuala_Lumpur (Malaysia, UTC+08, no DST). */
  const MY_TZ = "Asia/Kuala_Lumpur";
  const MY_OFFSET_HINT = "(UTC+08:00)";
  function fmtTs(v) {
    if (!v) return "—";
    const t = typeof v === "number" ? (v > 1e12 ? v : v * 1000) : Date.parse(v);
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
      hour12: false,
    }).format(d).replace(",", "");
    return `${base} ${MY_OFFSET_HINT}`;
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

  function maskPlatform(_raw) {
    return "e**********";
  }

  /** Audit log: prefix of action before first "." (for styling). */
  function auditActionPrefix(action) {
    const s = String(action || "").trim();
    const i = s.indexOf(".");
    return i > 0 ? s.slice(0, i) : (s || "other");
  }

  /** Strip detail fields that duplicate the row's actor/target columns. */
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
      if (display.length > 220) display = `${display.slice(0, 217)}…`;
      rows.push({ k, v: display });
    }
    return rows;
  }

  /** Event detail: skip keys that duplicate the row (actor, target, device, owner). */
  function eventDetailDedupedRows(detail, e) {
    if (!detail || typeof detail !== "object" || Array.isArray(detail)) return [];
    const actor = String((e && e.actor) || "").trim();
    const target = String((e && e.target) || "").trim();
    const dev = String((e && e.device_id) || "").trim();
    const owner = String((e && e.owner_admin) || "").trim();
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
      if (display.length > 220) display = `${display.slice(0, 217)}…`;
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
      if (display.length > 200) display = `${display.slice(0, 197)}…`;
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
      signup: "audit-pfx-auth",
    };
    return map[p] || "audit-pfx-other";
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
    const method = String(opts.method || "GET").toUpperCase();
    // Attach CSRF header on cookie-authenticated writes; Bearer requests are
    // exempt server-side but harmless to skip.
    if (_isWriteMethod(method) && !token && !headers[CSRF_HEADER_NAME]) {
      const ctok = getCsrfToken();
      if (ctok) headers[CSRF_HEADER_NAME] = ctok;
    }
    const retryable = opts.retryable != null ? !!opts.retryable : (method === "GET" || method === "HEAD");
    const retries = Number.isFinite(Number(opts.retries)) ? Math.max(0, Number(opts.retries)) : (retryable ? 2 : 0);
    let csrfRetry = 0;
    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const r = await fetchWithDeadline(
          apiBase() + path,
          { method, headers, body },
          opts.timeoutMs,
        );
        if (r.status === 401) {
          setToken("");
          setCsrfToken("");
          state.me = null;
          try {
            await fetchWithDeadline(apiBase() + "/auth/logout", { method: "POST" }, 8000);
          } catch (_) {}
          if (location.hash !== "#/login") location.hash = "#/login";
          throw new Error("401 Unauthorized or session expired");
        }
        if (!r.ok) {
          // CSRF token may have rotated / never bootstrapped — refresh once
          // and retry the same write before bubbling the error.
          if (_isWriteMethod(method) && csrfRetry === 0 && Number(r.status) === 403) {
            const t403 = await r.clone().text().catch(() => "");
            if (_isCsrfRejection(403, t403)) {
              csrfRetry = 1;
              const fresh = await refreshCsrfToken();
              if (fresh) {
                headers[CSRF_HEADER_NAME] = fresh;
                // Don't let this iteration consume a retry budget — writes
                // default to retries=0, so without attempt-- we'd exit the
                // loop immediately and the refreshed token would never be
                // used. csrfRetry=1 guards against infinite loops.
                attempt--;
                continue;
              }
            }
          }
          if (retryable && attempt < retries && _isRetryableHttpStatus(Number(r.status))) {
            await _sleep(250 * (2 ** attempt));
            continue;
          }
          const t = await r.text().catch(() => "");
          let msg;
          try {
            const j = JSON.parse(t);
            let d = j.detail;
            if (Array.isArray(d)) {
              d = d.map((x) => (x && x.msg) ? x.msg : String(x)).join("; ");
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
          await _sleep(250 * (2 ** attempt));
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
      return (typeof fallback === "function") ? fallback(e) : fallback;
    }
  }
  function isGroupRouteMissingError(err) {
    const msg = String((err && err.message) || err || "");
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
      reboot_self_check: !!s.reboot_self_check,
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
            body: { grantee_username: user, can_view: canView, can_operate: canOperate },
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

  /**
   * Short-lived GET cache to coalesce identical in-flight requests only (ttlMs > 0 adds a brief stale window).
   * Overview / device list: prefer `api()` + server-side CACHE_TTL (see .env) so truth stays on the server.
   */
  const _apiGetCache = new Map();
  const _apiGetInflight = new Map();
  const _API_GET_CACHE_MAX_KEYS = 48;
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
    if (ent && (now - ent.t) < ttl) return ent.data;
    if (_apiGetInflight.has(path)) return _apiGetInflight.get(path);
    const p = (async () => {
      const data = await api(path, opts);
      _apiGetCacheSet(path, data);
      return data;
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

  /** Clear short-lived GET cache entries (server also invalidates on write). */
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
    return String(s == null ? "" : s)
      .trim()
      .toLowerCase()
      .replace(/^v+/, "");
  }
  function firmwareHintStillValid(devFw, hint) {
    if (!hint || !hint.update_available) return false;
    const t = normalizeFwLabel(hint.to_version);
    const c = normalizeFwLabel(devFw);
    if (c && t && c === t) return false;
    return true;
  }

  const FW_HINT_DLG_VER = "4";
  async function openGlobalFwHintDialog(hint, ctx) {
    ctx = ctx || {};
    if (!hint || !hint.update_available) return;
    if (ctx.deviceId) {
      try {
        const row = await api(`/devices/${encodeURIComponent(ctx.deviceId)}`, { timeoutMs: 16000 });
        if (row && row.fw != null) ctx = Object.assign({}, ctx, { currentFw: String(row.fw) });
        const h2 = row && row.firmware_hint;
        if (!h2 || !h2.update_available || !firmwareHintStillValid(row && row.fw, h2)) {
          toast("Firmware is up to date.", "ok");
          try { bustDeviceListCaches(); } catch (_) {}
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

    const curFw = String(ctx.currentFw != null ? ctx.currentFw : "").trim() || "—";
    const newFw = String(hint.to_version || "—").trim() || "—";
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
      cmp.innerHTML =
        `<span class="croc-fw-hint-dlg__ver mono" title="Current">${escapeHtml(curFw)}</span>` +
        `<span class="croc-fw-hint-dlg__ver-arrow" aria-hidden="true">→</span>` +
        `<span class="croc-fw-hint-dlg__ver mono croc-fw-hint-dlg__ver--new" title="New">${escapeHtml(newFw)}</span>`;
    }

    const pre = document.getElementById("crocFwHintPreflight");
    if (pre) {
      if (!ctx.deviceId || !can("can_send_command")) {
        pre.textContent = "Open a device with command permission to send OTA in one step.";
      } else if (ctx.canOperateThisDevice === false) {
        pre.textContent = "No operate permission on this device — OTA disabled.";
      } else {
        pre.textContent = "Send OTA verifies your session, firmware URL (server probe with OTA token), and operate access.";
      }
    }

    const closeBtn = document.getElementById("crocFwHintClose");
    if (closeBtn) {
      closeBtn.onclick = () => { try { dlg.close(); } catch (_) {} };
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
          fresh = await api(`/devices/${encodeURIComponent(did)}`, { timeoutMs: 16000 });
        } catch (_) { /* use hint */ }
        if (fresh) {
          const h3 = fresh.firmware_hint;
          if (!firmwareHintStillValid(fresh.fw, h3) || !h3 || !h3.update_available) {
            toast("Firmware is already up to date.", "ok");
            try { bustDeviceListCaches(); } catch (_) {}
            try { dlg.close(); } catch (_) {}
            return;
          }
        }
        if (!confirm(`Send OTA to this device?\n\n${did}\n\n${curFw} → ${fw}`)) return;
        otaBtn.disabled = true;
        if (pre) pre.textContent = "Checking…";
        try {
          if (!state.me) {
            throw new Error("Not signed in or session expired");
          }
          let canOp = true;
          if (ctx.canOperateThisDevice !== true) {
            const row = await api(`/devices/${encodeURIComponent(did)}`, { timeoutMs: 20000 });
            canOp = !!(row && row.can_operate);
          } else {
            canOp = true;
          }
          if (!canOp) {
            throw new Error("No operate permission on this device");
          }
          const probe = await api(`/ota/firmware-reachability?name=${encodeURIComponent(toFile)}`, { timeoutMs: 25000 });
          if (!probe || !probe.ok) {
            const det = probe && probe.detail ? String(probe.detail) : "probe failed";
            throw new Error(`Firmware URL probe failed: ${det}`);
          }
          if (pre) pre.textContent = "Sending OTA command…";
          await api(`/devices/${encodeURIComponent(did)}/commands`, {
            method: "POST",
            body: { cmd: "ota", params: { url, fw } },
          });
          toast("OTA command sent", "ok");
          try { bustDeviceListCaches(); } catch (_) {}
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

  /** All-devices list + device detail: sync Firmware row version + OTA-hint control from API model. */
  function syncDevicePageFirmwareHint(view, dev, deviceIdForOta) {
    const hasUpd = !!(dev && dev.firmware_hint && dev.firmware_hint.update_available && firmwareHintStillValid(dev && dev.fw, dev.firmware_hint));
    const stEl = $("#devFwStatus", view);
    if (stEl) {
      stEl.textContent = hasUpd ? "Update available · 有更新" : "Up to date · 已是最新";
      stEl.className = hasUpd ? "device-fw-state device-fw-state--update" : "device-fw-state device-fw-state--ok";
    }
    const hBtn = $("#devFwHintBtn", view);
    if (hBtn) {
      if (hasUpd) {
        hBtn.style.display = "inline-flex";
        hBtn.setAttribute("aria-pressed", "true");
        const h = dev.firmware_hint;
        const did = String(deviceIdForOta || (dev && dev.device_id) || "");
        const operate = !!(dev && dev.can_operate);
        hBtn.onclick = () => openGlobalFwHintDialog(h, {
          currentFw: String(dev && dev.fw != null ? dev.fw : ""),
          deviceId: did,
          canOperateThisDevice: operate,
        });
      } else {
        hBtn.style.display = "none";
        hBtn.removeAttribute("aria-pressed");
        hBtn.onclick = null;
      }
    }
    const vEl = $("#devFwVer", view);
    if (vEl) vEl.textContent = String(dev && dev.fw != null && dev.fw !== "" ? dev.fw : "—");
  }

  async function login(username, password) {
    const r = await fetchWithDeadline(
      apiBase() + "/auth/login",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      },
      DEFAULT_API_TIMEOUT_MS,
    );
    const text = await r.text();
    if (!r.ok) {
      if (r.status === 429) {
        const ra = r.headers.get("Retry-After");
        let detail = "Too many sign-in attempts. Please wait and try again.";
        try {
          const j = JSON.parse(text);
          if (j && j.detail) detail = String(j.detail);
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
      // Uses default API ceiling; slow Nginx/upstream still yields login page on failure.
      state.me = await api("/auth/me");
    } catch (e) {
      state.me = null;
    }
    // Reuse the (still-valid) cookie-issued CSRF token across reloads, and
    // proactively refresh before any write happens — avoids first-write 403.
    if (state.me) {
      const ck = _readCsrfCookie();
      if (ck) setCsrfToken(ck);
      if (!getCsrfToken()) {
        try { await refreshCsrfToken(); } catch (_) {}
      }
    } else {
      setCsrfToken("");
    }
    renderAuthState();
  }

  async function loadHealth() {
    try {
      // Public endpoint — do not use api() (no Authorization) so bad/expired JWT
      // never affects probes and we never trip the global 401 handler here.
      const r = await fetchWithDeadline(apiBase() + "/health", { method: "GET" }, 12000);
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

  // ------------------------------------------------------------------ layout
  function renderAuthState() {
    if (!state.me) clearHealthPollTimer();
    document.body.dataset.auth = state.me ? "ok" : "none";
    const who = $("#who");
    if (state.me) {
      const u = String(state.me.username || "").trim() || "—";
      const role = String(state.me.role || "").trim() || "—";
      const zt = (state.me.zones || []).map((z) => String(z)).filter(Boolean).join(", ") || "—";
      const initial = (u[0] || "?").toUpperCase();
      const av = String(state.me.avatar_url || "").trim();
      const avatarEl = av
        ? `<div class="who-card__avatar who-card__avatar--photo" aria-hidden="true"><img src="${escapeHtml(av)}" alt="" width="40" height="40" loading="lazy" decoding="async" referrerpolicy="no-referrer" /></div>`
        : `<div class="who-card__avatar" aria-hidden="true">${escapeHtml(initial)}</div>`;
      setChildMarkup(
        who,
        `<div class="who-card" title="${escapeHtml(u)}">` +
          avatarEl +
          `<div class="who-card__body">` +
            `<div class="who-card__name">${escapeHtml(u)}</div>` +
            `<div class="who-card__meta">` +
            `<span class="who-card__role">${escapeHtml(role)}</span>` +
            `<span class="who-card__zones" title="${escapeHtml(zt)}">${escapeHtml(zt)}</span>` +
            `</div>` +
          `</div>` +
        `</div>`,
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
          { once: true },
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
    try { applySidebarRail(); } catch (_) {}
  }

  function renderNav() {
    const nav = $("#nav");
    if (!nav) return;
    if (!state.me) { setHtmlIfChanged(nav, ""); return; }
    const hash = location.hash || "#/overview";
    const hashNoQuery = hash.split("?")[0];
    const coreParts = [];
    for (const g of NAV_GROUPS) {
      const items = g.items.filter((n) => hasRole(n.min));
      if (items.length === 0) continue;
      coreParts.push(`<div class="nav-section">${escapeHtml(g.title)}</div>`);
      for (const n of items) {
        const active = (n.path === "#/devices"
          // Highlight "All devices" on both the list and any device detail
          // (#/devices/:id) so mobile users keep their place in the nav.
          ? (hashNoQuery === "#/devices" || hashNoQuery.startsWith("#/devices/"))
          : n.path === "#/site"
            ? hashNoQuery === "#/site"
            : hash.startsWith(n.path))
          ? ` aria-current="page"`
          : "";
        coreParts.push(
          `<a href="${n.path}"${active} title="${escapeHtml(n.label)}"><span class="nav-ico" aria-hidden="true">${n.ico}</span><span class="nav-label">${escapeHtml(n.label)}</span></a>`,
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
    const mailTitle = sm.configured
      ? (mailOk ? "Mail worker running — verification email can be sent" : "Mail channel configured but worker not running — check API logs")
      : "Mail channel not configured on server";
    const tgTitle = tgOn
      ? (tgOk
        ? (tgErr ? `Telegram worker up — last API error: ${tgErr}` : "Telegram worker running — events at min_level+ are queued")
        : "Telegram enabled but worker not running — check API logs")
      : "Telegram disabled — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS (numeric chat id; start a chat with the bot first)";
    const mqttTitle = mqConn
      ? (mqDrop > 0
        ? `MQTT connected, but ingest dropped ${mqDrop} message(s); queue depth=${mqQ}. last_up=${mqLastUp ? fmtTs(mqLastUp) : "—"}`
        : `MQTT connected; ingest queue depth=${mqQ}. last_up=${mqLastUp ? fmtTs(mqLastUp) : "—"}`)
      : `MQTT disconnected — check broker/TLS/network. last_down=${mqLastDown ? fmtTs(mqLastDown) : "—"} reason=${mqLastReason || "—"}`;
    setHtmlIfChanged(el, `
      <span class="health-pill ${mqConn ? (mqDrop > 0 ? "warn" : "ok") : "off"}" title="${escapeHtml(mqttTitle)}">MQTT</span>
      <span class="health-pill ${mailOk ? "ok" : sm.configured ? "warn" : "off"}" title="${escapeHtml(mailTitle)}">MAIL</span>
      <span class="health-pill ${tgOk ? "ok" : tgOn ? "warn" : "off"}" title="${escapeHtml(tgTitle)}">TG</span>`);
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

  function applySidebarRail() {
    const m = window.matchMedia && window.matchMedia("(min-width: 901px)");
    if (!m || !m.matches) {
      try { document.body.removeAttribute("data-sidebar"); } catch (_) {}
    } else {
      try {
        const c = localStorage.getItem(LS.sidebarCollapsed) === "1";
        if (c) document.body.setAttribute("data-sidebar", "collapsed");
        else document.body.removeAttribute("data-sidebar");
      } catch (_) {
        try { document.body.removeAttribute("data-sidebar"); } catch (_) {}
      }
    }
    const btn = document.getElementById("sidebarRailToggle");
    if (btn) {
      const isCol = document.body.getAttribute("data-sidebar") === "collapsed";
      btn.setAttribute("aria-label", isCol ? "Expand sidebar" : "Collapse sidebar");
      btn.setAttribute("aria-expanded", isCol ? "false" : "true");
      btn.setAttribute("title", isCol ? "Expand sidebar" : "Collapse sidebar");
      const svgL = "<svg class=\"sidebar-rail-toggle__icon\" viewBox=\"0 0 24 24\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M15 6l-6 6 6 6\"/></svg>";
      const svgR = "<svg class=\"sidebar-rail-toggle__icon\" viewBox=\"0 0 24 24\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M9 6l6 6-6 6\"/></svg>";
      btn.innerHTML = isCol ? svgR : svgL;
    }
  }

  function toggleSidebarRail() {
    if (!window.matchMedia("(min-width: 901px)").matches) return;
    const cur = localStorage.getItem(LS.sidebarCollapsed) === "1";
    try { localStorage.setItem(LS.sidebarCollapsed, cur ? "0" : "1"); } catch (_) {}
    applySidebarRail();
  }

  /** Collapse drawer when viewport is desktop width (e.g. rotate phone / resize). */
  function syncNavForViewport() {
    try {
      if (window.matchMedia && window.matchMedia("(min-width: 901px)").matches) {
        document.body.dataset.nav = "";
      }
    } catch (_) {}
    try { applySidebarRail(); } catch (_) {}
  }

  // ------------------------------------------------------------------ router
  const routes = {};

  function registerRoute(id, handler) { routes[id] = handler; }
  function isRouteCurrent(seq) { return seq === state.routeSeq; }
  function clearRouteTickers() {
    const ticks = window.__routeTickers;
    if (!ticks) return;
    for (const t of ticks.values()) {
      try { clearTimeout(t); } catch (_) {}
    }
    ticks.clear();
  }
  function scheduleRouteTicker(routeSeq, key, fn, intervalMs) {
    window.__routeTickers = window.__routeTickers || new Map();
    const ticks = window.__routeTickers;
    const k = String(key || "");
    let running = false;
    const run = async () => {
      if (!isRouteCurrent(routeSeq)) return;
      if (document.visibilityState !== "visible") {
        const tid = setTimeout(run, intervalMs);
        ticks.set(k, tid);
        return;
      }
      if (running) {
        const tid = setTimeout(run, intervalMs);
        ticks.set(k, tid);
        return;
      }
      running = true;
      try { await fn(); } catch (_) {}
      running = false;
      if (!isRouteCurrent(routeSeq)) return;
      const tid = setTimeout(run, intervalMs);
      ticks.set(k, tid);
    };
    const old = ticks.get(k);
    if (old) { try { clearTimeout(old); } catch (_) {} }
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
      } catch (_) {}
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
      try { cancelAnimationFrame(window.__pendingEvListRaf); } catch (_) {}
      window.__pendingEvListRaf = 0;
    }
    clearRouteTickers();
    if (window.__fpCooldownTimer) {
      // Forgot-password resend countdown is a setInterval (clearTimeout won't
      // touch it), so clear it here when the user navigates mid-cooldown.
      try { clearInterval(window.__fpCooldownTimer); } catch (_) {}
      window.__fpCooldownTimer = 0;
    }
    if (window.__evReconnectTimer) {
      try { clearTimeout(window.__evReconnectTimer); } catch (_) {}
      window.__evReconnectTimer = 0;
    }
    if (window.__evFetchAbort) {
      try { window.__evFetchAbort.abort(); } catch (_) {}
      window.__evFetchAbort = null;
    }
    window.__eventsStreamResume = null;
    toggleNav(false);
    if (window.__evSSE) { try { window.__evSSE.close(); } catch {} window.__evSSE = null; }

    // Public-route ids and alias mapping come from src/routes/manifest.js
    // (the bundle splice rewrites these references so non-bundled local runs
    // still see the legacy literal sets). Edit the manifest, not this file.
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
    try { applySidebarRail(); } catch (_) {}
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
      mountView(view, hx`<div class="card"><h2>Load failed</h2><p class="muted">${e.message || e}</p></div>`);
    }
  }

  window.addEventListener("hashchange", renderRoute);

  // ------------------------------------------------------------------ pages
  //
  // Auth pages have been peeled off into src/routes/*.route.js (concatenated
  // back into this same scope by scripts/build-dashboard.mjs):
  //   • login.route.js              (#/login)
  //   • forgot-password.route.js    (#/forgot-password)
  //   • register.route.js           (#/register)
  //   • account-activate.route.js   (#/account-activate)
  //
  // Adding more routes? Drop a `<id>.route.js` in src/routes/ that calls
  // `registerRoute("<id>", async (view, args, routeSeq) => {...})` at the top
  // level — do NOT use ES `import`/`export`, the file is concatenated as raw
  // text so it shares scope with this monolith. See src/README.md.

  // route "account" extracted to src/routes/account.route.js

  // Overview
  // route "overview" extracted to src/routes/overview.route.js

  // route "site" extracted to src/routes/site.route.js

  // route "group" extracted to src/routes/group.route.js

  // Device list (no id) + device detail
  // route "devices" extracted to src/routes/devices.route.js

  // Bulk siren — extracted to src/routes/alerts.route.js.

  // Activate
  // route "activate" extracted to src/routes/activate.route.js

  // Event Center — global live + historical log stream
  // NOTE: Active stream lives on window.__evSSE (fetch shim); renderRoute closes it on navigation.
  // navTok: capture state.routeSeq up front so nested async (loadHistory, openStream) always see a
  // defined token even if a minifier / bad edit drops the 3rd handler param (avoids "routeSeq is not defined").
  // route "events" extracted to src/routes/events.route.js

  // Telegram self-service (user/admin/superadmin)
  // route "telegram" extracted to src/routes/telegram.route.js

  // Audit
  // route "audit" extracted to src/routes/audit.route.js

  // Admin
  // route "admin" extracted to src/routes/admin.route.js

  // Unified: device alarms + dashboard/API remote siren (who / what / when / where / fan-out)
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
        <div id="sigList"><p class="muted">Loading…</p></div>
      </div>`);
    const reload = async () => {
      const hours = parseInt($("#sig_hours").value, 10) || 168;
      const qs = new URLSearchParams({ limit: "200", since_hours: String(hours) });
      try {
        if (!isRouteCurrent(routeSeq)) return;
        const [d, sumR] = await Promise.all([
          api("/activity/signals?" + qs.toString(), { timeoutMs: 24000 }),
          api("/alarms/summary", { timeoutMs: 16000 }).catch(() => ({ last_24h: 0, last_7d: 0, top_sources_7d: [] })),
        ]);
        if (!isRouteCurrent(routeSeq)) return;
        const sigSummaryEl = $("#sigSummary", view);
        const sigListEl = $("#sigList", view);
        if (!sigSummaryEl || !sigListEl) return;
        setHtmlIfChanged(sigSummaryEl, [
          ["Alarms 24h", sumR.last_24h || 0, "device-side alarm rows"],
          ["Alarms 7d", sumR.last_7d || 0, "same scope"],
          ["Top source 7d", (sumR.top_sources_7d || []).slice(0, 1).map((x) => `${x.source_id} × ${x.c}`).join("") || "—", "by count"],
        ].map(([k, v, s]) => `<div class="stat"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div><div class="sub">${escapeHtml(s)}</div></div>`).join(""));
        const items = d.items || [];
        const whoLbl = (w) => ({
          remote_button: "GPIO / local button",
          network: "MQTT / network",
          api: "API / automation",
        }[w] || w);
        setHtmlIfChanged(sigListEl, items.length === 0
          ? `<p class="muted audit-empty">No rows in this window.</p>`
          : `<div class="audit-feed">${items.map((a) => {
            const dev = a.device_id === "*" ? "(bulk)" : a.device_id;
            const link = a.device_id && a.device_id !== "*"
              ? `<a class="mono audit-target" href="#/devices/${encodeURIComponent(a.device_id)}">${escapeHtml(dev)}</a>`
              : escapeHtml(dev);
            const em = a.email_sent ? "queued" : (a.email_detail || "—");
            const fo = a.kind && a.kind.startsWith("bulk") ? String(a.fanout_count || 0) : String(a.fanout_count ?? "—");
            const whoS = a.kind === "device_alarm" ? whoLbl(a.who) : (a.who || "—");
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
                <span class="chip">${escapeHtml(a.display_label || "—")}</span>
                <span class="chip">${escapeHtml(a.notification_group || "—")}</span>
              </div>
              <div class="audit-item-line muted" style="font-size:12.5px">Who: ${escapeHtml(String(whoS))} · Fan-out: ${escapeHtml(fo)} · Email: ${escapeHtml(em)}</div>
            </article>`;
          }).join("")}</div>`);
      } catch (e) {
        if (!isRouteCurrent(routeSeq)) return;
        toast(e.message || e, "err");
      }
    };
    $("#sig_reload").addEventListener("click", reload);
    reload();
    scheduleRouteTicker(routeSeq, "signals-live-reload", reload, 10000);
  }
  registerRoute("signals", renderSignalsPage);

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
          <p class="muted" style="margin:8px 0 0">租户侧 <strong>不</strong>再使用 Admin OTA 控制台。请在 <a href="#/devices">全部设备</a> 与设备详情查看版本旁的 <strong>↑ + 红点</strong>（有可用新固件时）。OTA 上传与 campaign 仅 <strong>superadmin</strong> 在侧栏「OTA (ops)」操作。</p>
          <p class="muted" style="margin:8px 0 0">There is <strong>no</strong> admin OTA console in this product. Use <a href="#/devices">All devices</a> and device detail for the <strong>↑ + red dot</strong> when an upgrade is available. Staging and campaigns are <strong>superadmin</strong> only (sidebar <strong>OTA (ops)</strong>).</p>
        </div>`);
      return;
    }

    const helpCard = `
      <div class="card ota-help-card">
        <h2 class="ui-section-title" style="margin:0">OTA & firmware · 使用说明</h2>
        <div class="ota-help__cols">
          <div>
            <h3 class="ota-help__h">中文</h3>
            <ul class="muted ota-help__ul">
              <li><strong>全员（含 admin）</strong>：只看 <a href="#/devices">全部设备</a> / 设备详情上的 <strong>↑ + 红点</strong> 与说明弹窗；不在此页对 campaign 做 Accept。</li>
              <li><strong>检测</strong>：服务器比较 <code>OTA_FIRMWARE_DIR</code> 中的 <code>.bin</code> 与设备 <code>fw</code>；需 <code>OTA_PUBLIC_BASE_URL</code> 才能在弹窗中给出下载 URL。</li>
              <li><strong>文件</strong>：推荐 <code>croc-版本号-8位hex.bin</code>；同名 <code>.txt</code> / <code>.md</code> 为 release notes。</li>
              <li><strong>Superadmin</strong>：在本页下方上传 / 从已存文件建 campaign（若仍使用后端 campaign 流，由 API 或其它流程让各租户设备拉取；控制台不再给 admin 提供 OTA 入口）。</li>
            </ul>
          </div>
          <div>
            <h3 class="ota-help__h">English</h3>
            <ul class="muted ota-help__ul">
              <li><strong>Everyone (including admin)</strong>: use <a href="#/devices">All devices</a> / device detail <strong>↑ + red dot</strong> + notes dialog only — <strong>no</strong> tenant OTA Accept UI here.</li>
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
        <h2 class="ui-section-title">Superadmin · Upload & campaign</h2>
        <p class="muted" style="margin:0 0 8px">Upload stages a <code>.bin</code> under <code>OTA_FIRMWARE_DIR</code> (upload password <code>OTA_UPLOAD_PASSWORD</code>). The API keeps at most <strong id="otaMaxBinsLbl">10</strong> <code>.bin</code> files and deletes the <strong>oldest by file mtime</strong> (and sidecars) when over limit — same rule as <code>POST /ota/firmware/upload</code>. The list below is <strong>fetched from this server</strong> (<code>GET /ota/firmwares</code>); click <strong>Refresh list</strong> after upload or if you copied files in by hand.</p>
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
        <h3 style="margin:0 0 6px">Publish from server-staged firmware / 使用服务器上的固件</h3>
        <p class="muted" style="margin:0 0 8px;font-size:12.5px">The dropdown is populated by <strong>pulling the current directory listing from the API</strong> (not from your PC). Pick a <code>.bin</code> already on the server, then create a campaign. <strong>Version</strong> is resolved on the server (<code>.version</code> sidecar or filename) — not hand-typed; it should match that build&rsquo;s <code>FW_VERSION</code>.</p>
        <div class="row wide" style="align-items:flex-end;flex-wrap:wrap;gap:10px;margin-bottom:6px">
          <label class="field wide" style="flex:1;min-width:220px;margin:0"><span>Firmware on server *</span><select id="otaFromSel"><option value="">Loading…</option></select></label>
          <button type="button" class="btn secondary btn-tap sm" id="otaFwListRefresh">Refresh list</button>
        </div>
        <label class="field wide"><span>Version (from server, read-only)</span><input type="text" id="otaFromResolvedVer" class="mono" readonly tabindex="-1" value="—" style="background:var(--bg-muted);cursor:default" aria-live="polite" /></label>
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
        ro.value = "—";
        return;
      }
      const i = Number(sel.selectedIndex);
      const opt = sel.options[i];
      const raw = opt && opt.getAttribute("data-fw-version");
      const v = (raw && String(raw).trim()) || "";
      ro.value = v || "—";
    };

    const refreshFirmwareSelect = async () => {
      if (!isSuper) return;
      const sel = $("#otaFromSel", view);
      if (!sel) return;
      try {
        const r = await api("/ota/firmwares", { timeoutMs: 20000 });
        if (!isRouteCurrent(routeSeq)) return;
        const items = r.items || [];
        const ret = r.retention;
        const mx = $("#otaMaxBinsLbl", view);
        if (mx && ret && ret.max_bins != null) mx.textContent = String(ret.max_bins);
        const inf = $("#otaRetentionInfo", view);
        if (inf) {
          inf.textContent = ret
            ? `Server directory: ${ret.stored_count || 0} / max ${ret.max_bins} .bin files (oldest mtime removed when over limit). Upload password: ${ret.upload_password_configured ? "configured" : "not set on server"}.`
            : "";
        }
        const fmtM = (ts) => {
          const t = Number(ts);
          if (!Number.isFinite(t) || t <= 0) return "";
          try {
            const d = new Date(t * 1000);
            return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
          } catch {
            return "";
          }
        };
        sel.innerHTML = items.length
          ? items.map((it) => {
            const vRaw = (it.fw_version && String(it.fw_version).trim()) || "";
            const dv = vRaw ? escapeHtml(vRaw) : "";
            const fv = vRaw
              ? ` · v${escapeHtml(vRaw)}`
              : "";
            const mt = fmtM(it.mtime);
            const mtS = mt ? ` · ${escapeHtml(mt)}` : "";
            return `<option value="${escapeHtml(it.name)}" data-fw-version="${dv}">${escapeHtml(it.name)}${fv} (${Math.round(Number(it.size || 0) / 1024)} KB${mtS})</option>`;
          }).join("")
          : "<option value=\"\">(no .bin in folder)</option>";
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
        } catch (_) {}
        finally { otaFwListRefresh.disabled = false; }
      });
    }
    const stBtn = $("#otaStBtn", view);
    if (stBtn) {
      stBtn.addEventListener("click", async () => {
        const inp = $("#otaStFile", view);
        const f = inp && inp.files && inp.files[0];
        const fw = String($("#otaStFw", view)?.value || "").trim();
        const upw = String($("#otaStUploadPwd", view)?.value || "");
        if (!f || !fw) { toast("Choose file and version label", "err"); return; }
        if (!upw) { toast("Enter the upload password (set OTA_UPLOAD_PASSWORD on the server).", "err"); return; }
        if (!confirm("Upload firmware to server (HEAD check against public /fw/ URL)?")) return;
        try {
          const fd = new FormData();
          fd.append("file", f);
          fd.append("fw_version", fw);
          fd.append("upload_password", upw);
          const r = await api("/ota/firmware/upload", { method: "POST", body: fd, timeoutMs: 180000 });
          if (!isRouteCurrent(routeSeq)) return;
          const resEl = $("#otaStResult", view);
          if (resEl) resEl.textContent = `Stored ${r.stored_as || ""} · head_ok=${r.head_ok} · ${r.verify || ""}`;
          toast("Upload finished", r.head_ok ? "ok" : "err");
          if (inp) inp.value = "";
          refreshFirmwareSelect();
        } catch (e) { toast(e.message || e, "err"); }
      });
    }
    const fromBtn = $("#otaFromBtn", view);
    if (fromBtn) {
      fromBtn.addEventListener("click", async () => {
        const fn = String($("#otaFromSel", view)?.value || "").trim();
        const notes = String($("#otaFromNotes", view)?.value || "").trim();
        const allCh = $("#otaFromAllAd", view);
        const rawAdm = String($("#otaFromAdmTxt", view)?.value || "").trim();
        const target_admins = (allCh && allCh.checked) ? ["*"] : (rawAdm ? rawAdm.split(/[\s,;]+/).filter(Boolean) : ["*"]);
        if (!fn) { toast("Select a firmware package from the list", "err"); return; }
        if (!confirm("Create OTA campaign from this stored file? The campaign version will be taken from the server (staged .version / filename), not the UI.")) return;
        try {
          const out = await api("/ota/campaigns/from-stored", {
            method: "POST",
            body: { filename: fn, notes: notes || undefined, target_admins },
          });
          toast(
            (out && out.fw_version) ? `Campaign created · v${out.fw_version}` : "Campaign created",
            "ok",
          );
          try { bustDeviceListCaches(); } catch (_) {}
        } catch (e) { toast(e.message || e, "err"); }
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

  // ------------------------------------------------------------------ boot
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
        await fetchWithDeadline(apiBase() + "/auth/logout", { method: "POST" }, 12000);
      } catch (_) {}
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
      } catch (_) {}
    }, true);

    await loadMe();
    syncNavForViewport();
    try { applySidebarRail(); } catch (_) {}
    if (!location.hash) location.hash = state.me ? "#/overview" : "#/login";
    else renderRoute();
    await loadHealth().catch(() => {});
    window.addEventListener("online", () => {
      loadHealth().catch(() => {});
      tickHealthIfVisible();
      if (typeof window.__eventsStreamResume === "function") {
        try {
          if (!window.__evSSE || window.__evSSE.readyState === EventSource.CLOSED) {
            window.__eventsStreamResume();
          } else {
            syncEventsLiveBadge();
          }
        } catch (_) {}
      }
    });
    document.addEventListener("visibilitychange", () => {
      document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
      if (document.visibilityState === "hidden") {
        /* Keep SSE open through tab switches — closing forced reconnect storms through proxies. */
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
        } catch (_) {}
      }
    });
    document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
