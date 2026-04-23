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
  };
  const OFFLINE_MS = 90 * 1000;

  /** Sidebar: grouped by function (paths unchanged). */
  const NAV_GROUPS = [
    {
      title: "Dashboard",
      items: [
        { id: "overview", label: "Overview", ico: "◎", path: "#/overview", min: "user" },
        { id: "devices", label: "All devices", ico: "▢", path: "#/devices", min: "user" },
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
        { id: "telegram", label: "Telegram", ico: "✆", path: "#/telegram", min: "user" },
        { id: "account", label: "Account", ico: "◍", path: "#/account", min: "user" },
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
    routeSeq: 0,
  };

  /** Group cards (Overview) are stored in localStorage; keep in sync when device group changes in profile. */
  function groupMetaStorageKey() {
    return (state.me && state.me.username) ? `croc.group.meta.v2.${state.me.username}` : "croc.group.meta.v2.anon";
  }
  function reconcileGroupMetaForDevice(deviceId, newGroupKey) {
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
      const ng = String(newGroupKey || "").trim();
      if (ng) {
        if (!meta[ng] || typeof meta[ng] !== "object") {
          meta[ng] = { display_name: ng, owner_name: "", phone: "", email: "", device_ids: [] };
        }
        const s = new Set((meta[ng].device_ids || []).map(String));
        s.add(id);
        meta[ng].device_ids = Array.from(s);
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
   * - Keeps display_name / owner / contact for groups that still exist or draft cards (0 devices, local only).
   * - Drops stale group keys that had local device_ids but no device on the server lists that group (unlink).
   */
  function syncGroupMetaWithDevices(meta, devices) {
    if (!meta || typeof meta !== "object") return meta;
    const list = Array.isArray(devices) ? devices : [];
    const notifMap = new Map();
    for (const d of list) {
      const g = String(d && d.notification_group != null ? d.notification_group : "").trim();
      if (!g) continue;
      if (!notifMap.has(g)) notifMap.set(g, []);
      notifMap.get(g).push(String(d.device_id));
    }
    for (const [g, ids] of notifMap.entries()) {
      const prev = meta[g] && typeof meta[g] === "object" ? meta[g] : {};
      const dn = (prev.display_name && String(prev.display_name).trim()) || g;
      meta[g] = {
        display_name: dn,
        owner_name: prev.owner_name != null ? String(prev.owner_name) : "",
        phone: prev.phone != null ? String(prev.phone) : "",
        email: prev.email != null ? String(prev.email) : "",
        device_ids: ids,
      };
    }
    for (const g of Object.keys(meta)) {
      if (notifMap.has(g)) continue;
      const m = meta[g];
      const ids = Array.isArray(m && m.device_ids) ? m.device_ids : [];
      if (ids.length > 0) delete meta[g];
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
    const limit = timeoutMs === false ? 0 : (timeoutMs != null ? timeoutMs : DEFAULT_API_TIMEOUT_MS);
    if (limit <= 0) return fetch(url, init || {});
    const ac = new AbortController();
    const tid = setTimeout(() => ac.abort(), limit);
    try {
      return await fetch(url, Object.assign({}, init || {}, { signal: ac.signal }));
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

  const MY_TZ = "Asia/Kuala_Lumpur";
  function fmtTs(v) {
    if (!v) return "—";
    const t = typeof v === "number" ? (v > 1e12 ? v : v * 1000) : Date.parse(v);
    if (!Number.isFinite(t)) return String(v);
    const d = new Date(t);
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: MY_TZ,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(d).replace(",", "");
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
    const retryable = opts.retryable != null ? !!opts.retryable : (method === "GET" || method === "HEAD");
    const retries = Number.isFinite(Number(opts.retries)) ? Math.max(0, Number(opts.retries)) : (retryable ? 2 : 0);
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
          state.me = null;
          if (location.hash !== "#/login") location.hash = "#/login";
          throw new Error("401 Unauthorized or session expired");
        }
        if (!r.ok) {
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
    return {
      trigger_mode: String(s.trigger_mode || "continuous"),
      trigger_duration_ms: Number(s.trigger_duration_ms || 10000),
      delay_seconds: Number(s.delay_seconds || 0),
      reboot_self_check: !!s.reboot_self_check,
    };
  }
  async function runGroupApplyOnAction(ctx) {
    const { groupKey, payload, apiCaps, saveApiCaps, tryApplyRoute, applyFallback } = ctx;
    if (apiCaps && apiCaps.apply && typeof tryApplyRoute === "function") {
      try {
        return await tryApplyRoute(groupKey);
      } catch (e) {
        if (isGroupRouteMissingError(e)) {
          apiCaps.apply = false;
          if (typeof saveApiCaps === "function") saveApiCaps(apiCaps);
          return await applyFallback(groupKey, payload);
        }
        throw e;
      }
    }
    return await applyFallback(groupKey, payload);
  }
  async function runGroupDeleteAction(ctx) {
    const { groupKey, apiCaps, saveApiCaps, tryDeletePostRoute, tryDeleteRoute, clearFallback } = ctx;
    if (apiCaps && apiCaps.delete === false) return await clearFallback(groupKey);
    try {
      return await tryDeletePostRoute(groupKey);
    } catch (e) {
      if (!isGroupRouteMissingError(e)) throw e;
      try {
        return await tryDeleteRoute(groupKey);
      } catch (e2) {
        if (isGroupRouteMissingError(e2)) {
          if (apiCaps) apiCaps.delete = false;
          if (typeof saveApiCaps === "function" && apiCaps) saveApiCaps(apiCaps);
          return await clearFallback(groupKey);
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
      // Uses default API ceiling; slow Nginx/upstream still yields login page on failure.
      state.me = await api("/auth/me");
    } catch (e) {
      state.me = null;
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
      setChildMarkup(
        who,
        `<div><strong>${escapeHtml(state.me.username)}</strong></div>` +
          `<div class="muted">${escapeHtml(state.me.role)} · ${escapeHtml((state.me.zones || []).join(", ") || "—")}</div>`,
      );
    } else {
      who.textContent = "Signed out";
    }
    renderNav();
    renderHealthPills();
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
          ? hashNoQuery === "#/devices"
          : hash.startsWith(n.path))
          ? ` aria-current="page"`
          : "";
        coreParts.push(
          `<a href="${n.path}"${active}><span class="nav-ico">${n.ico}</span>${escapeHtml(n.label)}</a>`,
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
        ? `MQTT connected, but ingest dropped ${mqDrop} message(s); queue depth=${mqQ}. last_up=${mqLastUp || "—"}`
        : `MQTT connected; ingest queue depth=${mqQ}. last_up=${mqLastUp || "—"}`)
      : `MQTT disconnected — check broker/TLS/network. last_down=${mqLastDown || "—"} reason=${mqLastReason || "—"}`;
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
  // Login
  registerRoute("login", async (view) => {
    setCrumb("Sign in");
    document.body.dataset.auth = "none";
    const AUTH_UI_REV = "UI rev 2026.04.22";
    const cleanAuthMessage = (raw) => {
      const s = String(raw || "").trim();
      if (!s) return "Request failed. Please try again.";
      const l = s.toLowerCase();
      if (l.includes("401")) return "Username or password is incorrect.";
      if (l.includes("invalid credentials")) return "Username or password is incorrect.";
      if (l.includes("session expired")) return "Session expired. Please sign in again.";
      if (l.includes("networkerror") || l.includes("failed to fetch")) return "Network error. Please check server/API.";
      return s.replace(/^error:\s*/i, "");
    };
    mountView(view, `
      <div class="auth-page auth-page-pro" role="main">
        <section class="auth-hero">
          <div class="auth-hero__tag">ESA Secure Platform</div>
          <h2>Unified fleet security console</h2>
          <p>Real-time monitoring, role-based control, and protected device operations in one place.</p>
          <ul class="auth-hero__bullets">
            <li>Live device visibility by role scope</li>
            <li>Secure command and trigger orchestration</li>
            <li>Audit-ready operations and recovery flow</li>
          </ul>
        </section>
        <div class="auth-card auth-card--pro" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-rev">${AUTH_UI_REV}</div>
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Sign in</h1>
            <p class="auth-card__lead">Welcome back. Continue to dashboard.</p>
          </header>
          <form class="auth-card__body" id="loginForm" autocomplete="on">
            <label class="field">
              <span>Username</span>
              <input name="username" autocomplete="username" required placeholder="your username" />
            </label>
            <label class="field field--spaced">
              <span>Password</span>
              <input name="password" type="password" autocomplete="current-password" required placeholder="your password" />
            </label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="submit" id="loginSubmit">Sign in</button>
            </div>
            <p class="auth-card__msg muted" id="loginMsg" aria-live="polite"></p>
            <nav class="auth-card__links" aria-label="Other sign-in options">
              <a class="auth-link" href="#/register">Create admin account</a>
              <a class="auth-link" href="#/account-activate">Activate with email code</a>
              <a class="auth-link" href="#/forgot-password">Forgot password</a>
            </nav>
          </form>
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
        btn.textContent = "Signing in…";
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

  // Forgot password — email + SHA code flow
  registerRoute("forgot-password", async (view) => {
    setCrumb("Forgot password");
    document.body.dataset.auth = "none";
    let enabled = true;
    try {
      const r = await fetch(apiBase() + "/auth/forgot/email/enabled");
      const j = await r.json();
      enabled = !!j.enabled;
    } catch { enabled = false; }
    mountView(view, `
      <div class="auth-page" role="main">
        <div class="auth-card auth-card--wide auth-card--prose" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Account recovery</h1>
            <p class="auth-card__lead">Email SHA code recovery</p>
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
            <label class="field field--spaced"><span>New password (≥8)</span><input id="fp_p1" type="password" autocomplete="new-password" /></label>
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
      if (fpCooldown <= 0) return;
      fpCooldownTimer = setInterval(() => {
        fpCooldown = Math.max(0, fpCooldown - 1);
        applyFpCooldownUi();
        if (fpCooldown <= 0) {
          clearInterval(fpCooldownTimer);
          fpCooldownTimer = 0;
        }
      }, 1000);
    };
    const parseCooldownFromMessage = (msg) => {
      const m = String(msg || "").match(/wait\s+(\d+)s/i);
      return m ? Math.max(1, Number(m[1])) : 0;
    };
    const doForgotSend = async () => {
      m1.textContent = "";
      const username = $("#fp_user").value.trim();
      const email = ($("#fp_email").value || "").trim().toLowerCase();
      if (!username || !email) { m1.textContent = "Enter username and email"; return false; }
      if (fpCooldown > 0) { m1.textContent = `Please wait ${fpCooldown}s before resending.`; return false; }
      const check = await fetch(apiBase() + "/auth/forgot/email/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email }),
      });
      const cj = await check.json().catch(() => ({}));
      if (!check.ok) {
        const det = cj.detail;
        const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || check.statusText);
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
        body: JSON.stringify({ username, email }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        const det = d.detail;
        const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || r.statusText);
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
      } catch (e) { m1.textContent = String(e.message || e); }
    });
    if (fpResendBtn) {
      fpResendBtn.addEventListener("click", async () => {
        try {
          const ok = await doForgotSend();
          if (ok) m2.textContent = `Code resent. Wait ${fpCooldown}s before next resend.`;
        } catch (e) { m2.textContent = String(e.message || e); }
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
      if (!email || !sha_code || !password) { m2.textContent = "Enter email, SHA code, and password"; return; }
      if (password !== password_confirm) { m2.textContent = "Passwords do not match"; return; }
      try {
        const r = await fetch(apiBase() + "/auth/forgot/email/complete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, email, sha_code, password, password_confirm }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
          const det = d.detail;
          const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || r.statusText);
          throw new Error(msg);
        }
        setChildMarkup(m2, `<span class="badge online">Password updated</span> Redirecting to sign in…`);
        toast("Password updated", "ok");
        scheduleRouteRedirect(1500, "#/login");
      } catch (e) { m2.textContent = String(e.message || e); }
    });
  });

  // Public admin signup
  registerRoute("register", async (view) => {
    setCrumb("Register admin");
    document.body.dataset.auth = "none";
    const AUTH_UI_REV = "UI rev 2026.04.22";
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
      <div class="auth-page auth-page-pro" role="main">
        <section class="auth-hero">
          <div class="auth-hero__tag">Admin Onboarding</div>
          <h2>Professional setup, immediate access</h2>
          <p>Register once, verify by email, then manage your own device fleet directly.</p>
          <ul class="auth-hero__bullets">
            <li>No superadmin approval required</li>
            <li>Email verification with cooldown protection</li>
            <li>Tenant-isolated admin workspace</li>
          </ul>
        </section>
        <div class="auth-card auth-card--wide auth-card--pro" data-auth-card>
          <header class="auth-card__head">
            <div class="auth-rev">${AUTH_UI_REV}</div>
            <div class="auth-card__logo" aria-hidden="true"></div>
            <h1 class="auth-card__title">Create admin</h1>
            <p class="auth-card__lead">Create your account with email verification.</p>
          </header>
          <div class="auth-card__body">
            <p class="auth-card__note muted">After verification, you can sign in immediately.</p>
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
      </div>`);
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
      } catch (e) { m1.textContent = cleanSignupMessage(e.message || e); }
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
        setChildMarkup(m2, `<span class="badge online">OK</span> Redirecting to sign in…`);
        scheduleRouteRedirect(1500, "#/login");
      } catch (e) { m2.textContent = cleanSignupMessage(e.message || e); }
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
      } catch (e) { m2.textContent = cleanSignupMessage(e.message || e); }
    });
  });

  // Account activation (admin-created users arrive here)
  registerRoute("account-activate", async (view) => {
    setCrumb("Activate account");
    document.body.dataset.auth = "none";
    mountView(view, `
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
      </div>`);
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
        setChildMarkup(msg, `<span class="badge online">Activated</span> Redirecting to sign in…`);
        scheduleRouteRedirect(1500, "#/login");
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

  registerRoute("account", async (view) => {
    setCrumb("Account");
    if (!hasRole("user")) { mountView(view, `<div class="card"><p class="muted">Sign in required.</p></div>`); return; }
    const me = state.me || { username: "", role: "" };
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
      <div class="card" style="border-color:color-mix(in srgb,var(--danger)35%,var(--border))">
        <h3>Close tenant · 注销管理员账号</h3>
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
      </div>`;
      }
      return `
      <div class="card">
        <h3>Delete account</h3>
        <p class="muted">This action is irreversible. Type <span class="mono">DELETE</span> and confirm your password.</p>
        <label class="field"><span>Current password</span><input id="accDelPw" type="password" autocomplete="current-password"/></label>
        <label class="field field--spaced"><span>Type DELETE</span><input id="accDelText" placeholder="DELETE"/></label>
        <div class="row" style="justify-content:flex-end;margin-top:10px">
          <button class="btn danger" id="accDeleteSelf">Delete my account</button>
        </div>
      </div>`;
    })();
    mountView(view, `
      <div class="card">
        <h2>My account</h2>
        <p class="muted">User: <span class="mono">${escapeHtml(me.username)}</span> · Role: <span class="mono">${escapeHtml(me.role)}</span></p>
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
    const accChangePwBtn = $("#accChangePw", view);
    if (accChangePwBtn) {
      accChangePwBtn.addEventListener("click", async () => {
      try {
        await api("/auth/me/password", {
          method: "PATCH",
          body: {
            current_password: ($("#acc_old", view).value || ""),
            new_password: ($("#acc_new1", view).value || ""),
            new_password_confirm: ($("#acc_new2", view).value || ""),
          },
        });
        toast("Password updated — please sign in again.", "ok");
        setToken("");
        state.me = null;
        clearHealthPollTimer();
        renderAuthState();
        location.hash = "#/login";
      } catch (e) { toast(e.message || e, "err"); }
      });
    }
    const accDeleteSelfBtn = $("#accDeleteSelf", view);
    if (accDeleteSelfBtn) {
      accDeleteSelfBtn.addEventListener("click", async () => {
      if (roleNorm === "superadmin") return;
      const msg = roleNorm === "admin"
        ? "Close this admin tenant permanently? All owned devices will be factory-unclaimed and sub-users deleted."
        : "Delete your account permanently?";
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
          password: ($("#accDelPw", view).value || ""),
          confirm_text: ($("#accDelText", view).value || "").trim(),
          acknowledge_admin_tenant_closure: roleNorm === "admin",
        };
        await api("/auth/me/delete", { method: "POST", body });
        toast(roleNorm === "admin" ? "Tenant closed" : "Account deleted", "ok");
        setToken("");
        state.me = null;
        clearHealthPollTimer();
        location.hash = "#/login";
        renderAuthState();
      } catch (e) { toast(e.message || e, "err"); }
      });
    }
  });

  // Overview
  registerRoute("overview", async (view, _args, routeSeq) => {
    setCrumb("Overview");
    const groupScope = (state.me && state.me.username) ? state.me.username : "anon";
    const GROUP_API_CAPS_LS_KEY = `croc.group.api.caps.v2.${groupScope}`;
    const loadGroupApiCaps = () => {
      try {
        const raw = localStorage.getItem(GROUP_API_CAPS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return {
          settings: obj && obj.settings === false ? false : true,
          apply: obj && obj.apply === false ? false : true,
          delete: obj && obj.delete === false ? false : true,
          prefix: (obj && (obj.prefix === "/api" || obj.prefix === "")) ? obj.prefix : "",
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
        prefix: (caps && caps.prefix === "/api") ? "/api" : "",
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
          const msg = String((e && e.message) || e || "");
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
        return await tryGroupApiCall("/settings", { timeoutMs: 12000, retries: 1 });
      } catch (e) {
        const msg = String((e && e.message) || e || "");
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
          api("/dashboard/overview", { timeoutMs: 22000, retries: 3 }),
          api("/devices", { timeoutMs: 22000, retries: 3 }),
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
      loadGroupSettingsCompat(),
    ]);
    let ov = (ovListRes.status === "fulfilled" && ovListRes.value && ovListRes.value.ov) ? ovListRes.value.ov : null;
    let list = (ovListRes.status === "fulfilled" && ovListRes.value && ovListRes.value.list) ? ovListRes.value.list : null;
    if (!ov || !list) {
      const cached = state.overviewCache;
      if (cached && cached.ov && cached.list) {
        ov = ov || cached.ov;
        list = list || cached.list;
        toast("Showing last known data — server is slow or offline; will retry on refresh.", "warn");
      }
    }
    if (!ov) ov = { mqtt_connected: false };
    if (!list) list = { items: [] };
    state.overviewCache = { ov, list, ts: Date.now() };
    const groupSettingsItems = (grpSetRes.status === "fulfilled" && grpSetRes.value && Array.isArray(grpSetRes.value.items))
      ? grpSetRes.value.items
      : [];
    let devices = list.items || [];
    let byId = new Map(devices.map((d) => [String(d.device_id), d]));

    const GROUP_META_LS_KEY = `croc.group.meta.v2.${groupScope}`;
    const GROUP_SETTINGS_LS_KEY = `croc.group.settings.v1.${groupScope}`;
    const loadGroupMeta = () => {
      try {
        const raw = localStorage.getItem(GROUP_META_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return (obj && typeof obj === "object") ? obj : {};
      } catch { return {}; }
    };
    const saveGroupMeta = (obj) => localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(obj || {}));
    const loadLocalGroupSettings = () => {
      try {
        const raw = localStorage.getItem(GROUP_SETTINGS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return (obj && typeof obj === "object") ? obj : {};
      } catch { return {}; }
    };
    const saveLocalGroupSettings = (obj) => localStorage.setItem(GROUP_SETTINGS_LS_KEY, JSON.stringify(obj || {}));
    const groupDelayTimers = new Map();
    const localGroupSettings = loadLocalGroupSettings();
    const groupSettingsMap = new Map();
    for (const [k, v] of Object.entries(localGroupSettings)) groupSettingsMap.set(String(k), v || {});
    for (const x of groupSettingsItems) groupSettingsMap.set(String(x.group_key || ""), x);
    const meta = loadGroupMeta();
    syncGroupMetaWithDevices(meta, devices);
    saveGroupMeta(meta);

    let selectedGroup = "";
    const hh = state.health || {};
    const mqConnected = !!(hh.mqtt_connected ?? ov.mqtt_connected);
    const mqQDepth = Number(hh.mqtt_ingest_queue_depth || 0);
    const mqDropped = Number(hh.mqtt_ingest_dropped || 0);
    const totalDevices = Number(ov.total_devices != null ? ov.total_devices : devices.length);
    const onlineDevices = Number((ov.presence && ov.presence.online != null) ? ov.presence.online : devices.filter(isOnline).length);
    const offlineDevices = Math.max(0, totalDevices - onlineDevices);
    const txBps = Number((ov.throughput && ov.throughput.tx_bps_total) || 0);
    const rxBps = Number((ov.throughput && ov.throughput.rx_bps_total) || 0);
    const bps = (v) => {
      v = Number(v || 0);
      if (v < 1024) return `${v.toFixed(0)} B/s`;
      if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
      return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
    };
    const mqStatus = !mqConnected ? "Disconnected" : (mqDropped > 0 || mqQDepth >= 300 ? "Warning" : "Healthy");
    const mqClass = !mqConnected ? "revoked" : (mqStatus === "Warning" ? "offline" : "online");
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
      <section class="stats">
        <div class="stat"><div class="k">Server</div><div class="v" id="ovServerV">—</div><div class="sub">MQTT broker link</div></div>
        <div class="stat"><div class="k">Devices</div><div class="v" id="ovDevicesV">—</div><div class="sub">total in scope</div></div>
        <div class="stat"><div class="k">Online</div><div class="v" id="ovOnlineV">—</div><div class="sub">active now</div></div>
        <div class="stat"><div class="k">Offline</div><div class="v" id="ovOfflineV">—</div><div class="sub">inactive now</div></div>
        <div class="stat"><div class="k">TX</div><div class="v" id="ovTxV">—</div><div class="sub">aggregate uplink</div></div>
        <div class="stat"><div class="k">RX</div><div class="v" id="ovRxV">—</div><div class="sub">aggregate downlink</div></div>
      </section>
      <section class="card">
        <div class="row">
          <h3 style="margin:0">MQTT risk</h3>
          <span class="badge ${mqClass}" id="ovMqttRisk">${mqStatus}</span>
        </div>
        <div class="divider"></div>
        <div class="muted">queue=<span class="mono" id="ovMqttQueue">0</span> · dropped=<span class="mono" id="ovMqttDropped">0</span></div>
      </section>
      <section class="card">
        <div class="row">
          <h2 style="margin:0">Group cards</h2>
          ${state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users"))) ? `<button class="btn sm secondary right" id="grpShareOpen">Sharing</button>` : ""}
          <button class="btn sm secondary right" id="grpNew">New group</button>
        </div>
        <div class="divider"></div>
        <div id="groupCards" class="device-grid"></div>
      </section>
      <div id="shareModal" class="grp-modal" style="display:none">
        <div class="grp-modal-card" style="max-width:760px;width:min(760px,96vw)">
          <h3 style="margin:0 0 8px">Share devices / group</h3>
          <p class="muted" id="shareTargetHint" style="margin:0 0 10px">Select devices, users, and permissions.</p>
          <div class="row" style="gap:10px;align-items:flex-start;flex-wrap:wrap">
            <div style="flex:1;min-width:280px">
              <div class="row" style="justify-content:space-between;align-items:center">
                <strong>Devices</strong>
                <label class="muted"><input type="checkbox" id="shareSelAllDevices" /> Select all</label>
              </div>
              <div id="shareDeviceList" class="grp-pick-list" style="max-height:260px;overflow:auto"></div>
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
          <label class="field"><span>Trigger duration (ms)</span><input id="gsDuration" type="number" min="500" max="300000" step="100" /></label>
          <label class="field field--spaced"><span>Trigger mode</span>
            <select id="gsMode">
              <option value="continuous">Continuous trigger</option>
              <option value="delay">Delay trigger</option>
            </select>
          </label>
          <label class="field field--spaced"><span>Delay seconds</span><input id="gsDelay" type="number" min="0" max="3600" step="1" /></label>
          <label class="field field--spaced"><span><input id="gsReboot" type="checkbox" /> Reboot + self-check this group after trigger</span></label>
          <div class="row" style="justify-content:flex-end;gap:8px;margin-top:10px">
            <button class="btn sm secondary" id="gsCancel" type="button">Cancel</button>
            <button class="btn sm secondary" id="gsApply" type="button">Apply now</button>
            <button class="btn sm" id="gsSave" type="button">Save</button>
          </div>
        </div>
      </div>
      <div id="grpModal" class="grp-modal" style="display:none">
        <div class="grp-modal-card">
          <h3 style="margin:0 0 8px">Edit group card</h3>
          <label class="field"><span>Group key</span><input id="gmKey" placeholder="e.g. Warehouse-A"/></label>
          <label class="field"><span>Display name</span><input id="gmName"/></label>
          <label class="field"><span>Owner name</span><input id="gmOwner"/></label>
          <label class="field"><span>Phone</span><input id="gmPhone"/></label>
          <label class="field"><span>Email</span><input id="gmEmail"/></label>
          <div class="field"><span>Devices</span><div id="gmDevices" class="grp-pick-list"></div></div>
          <div class="row" style="justify-content:flex-end;gap:8px;margin-top:10px">
            <button class="btn sm secondary" id="gmCancel" type="button">Cancel</button>
            <button class="btn sm" id="gmSave" type="button">Save</button>
          </div>
        </div>
      </div>`);
    patchOverviewHeader({
      server: mqConnected ? "Connected" : "Disconnected",
      devices: totalDevices,
      online: onlineDevices,
      offline: offlineDevices,
      tx: bps(txBps),
      rx: bps(rxBps),
      queue: mqQDepth,
      dropped: mqDropped,
      risk: mqStatus,
      riskClass: mqClass,
    });

    const groupCardsEl = $("#groupCards", view);
    const grpModalEl = $("#grpModal", view);
    const grpSetModalEl = $("#grpSetModal", view);
    const shareModalEl = $("#shareModal", view);
    if (!groupCardsEl || !grpModalEl || !grpSetModalEl) return;

    let editingGroup = "";
    const groupKeys = () => Object.keys(meta).sort((a, b) => a.localeCompare(b));
    const groupDeviceIds = (g) => {
      const ids = Array.isArray(meta[g] && meta[g].device_ids) ? meta[g].device_ids : [];
      return ids.filter((x) => byId.has(String(x)));
    };
    const groupSharedBy = (g) => {
      const rows = groupDeviceIds(g).map((id) => byId.get(String(id))).filter(Boolean);
      const sharedFrom = new Set(rows.map((d) => String(d.shared_by || "")).filter(Boolean));
      return Array.from(sharedFrom);
    };
    const renderDeviceCard = (d) => {
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
        <div class="meta">
          Platform: ${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}<br/>
          Manufacturer: ESA Sibu<br/>
          Updated: ${escapeHtml(fmtRel(d.updated_at))}
        </div>
      </a>`;
    };
    const buildGroupCardHtml = (g) => {
      const ids = groupDeviceIds(g);
      const rows = ids.map((id) => byId.get(String(id))).filter(Boolean);
      const total = rows.length;
      const on = rows.filter((d) => isOnline(d)).length;
      const off = Math.max(0, total - on);
      const m = meta[g] || {};
      const gs = groupSettingsMap.get(g) || {
        trigger_mode: "continuous",
        trigger_duration_ms: 10000,
        delay_seconds: 0,
        reboot_self_check: false,
      };
      const sharedBy = groupSharedBy(g);
      const isSharedGroup = sharedBy.length > 0;
      const modeLabel = String(gs.trigger_mode || "continuous") === "delay"
        ? `delay ${Number(gs.delay_seconds || 0)}s`
        : "continuous";
      const shareBtn = state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users")))
        ? `<button class="group-del-ico js-share-group" data-group="${escapeHtml(g)}" type="button" title="Share group" style="right:32px">⇪</button>`
        : "";
      return `<article class="device-card js-group-card ${selectedGroup === g ? "is-selected" : ""}" data-group="${escapeHtml(g)}" style="cursor:pointer;position:relative">
        ${shareBtn}
        <button class="group-del-ico js-del-group" data-group="${escapeHtml(g)}" type="button" ${isSharedGroup ? "disabled title=\"Shared group cannot be deleted\"" : "title=\"Delete group\""} aria-label="Delete group">✕</button>
        <h3><div class="device-primary-name">${escapeHtml(m.display_name || g)}</div><div class="device-id-sub mono">${escapeHtml(g)}</div></h3>
        <div class="meta" style="margin-bottom:8px">
          Trigger: <span class="mono">${escapeHtml(modeLabel)}</span> ·
          Duration: <span class="mono">${escapeHtml(String(gs.trigger_duration_ms || 10000))}ms</span> ·
          Reboot+self-check: <span class="mono">${gs.reboot_self_check ? "yes" : "no"}</span>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
          <span class="badge neutral">total ${total}</span>
          <span class="badge online">online ${on}</span>
          <span class="badge offline">offline ${off}</span>
          ${isSharedGroup ? `<span class="badge accent" title="shared group">shared by ${escapeHtml(sharedBy.join(", "))}</span>` : ""}
        </div>
        <div class="meta">Owner: ${escapeHtml(m.owner_name || "—")} · ${escapeHtml(m.phone || "—")} · ${escapeHtml(m.email || "—")}</div>
        <div class="row" style="margin-top:8px;gap:6px;flex-wrap:wrap">
          <button class="btn sm secondary js-group-settings" data-group="${escapeHtml(g)}" type="button" ${isSharedGroup ? "disabled title=\"Shared group follows owner settings\"" : ""}>Settings</button>
          <button class="btn sm secondary js-edit-group" data-group="${escapeHtml(g)}" type="button" ${isSharedGroup ? "disabled title=\"Shared group: device membership is read-only\"" : ""}>Edit</button>
          <button class="btn sm danger js-alert-on" data-group="${escapeHtml(g)}" type="button">Alarm ON</button>
          <button class="btn sm secondary js-alert-off" data-group="${escapeHtml(g)}" type="button">Alarm OFF</button>
        </div>
      </article>`;
    };
    const renderGroups = () => {
      const keys = groupKeys();
      if (keys.length === 0) {
        setChildMarkup(groupCardsEl, `<p class="muted">No groups yet.</p>`);
        return;
      }
      const existing = new Map(
        $$(".js-group-card", groupCardsEl).map((el) => [String(el.getAttribute("data-group") || ""), el]),
      );
      const frag = document.createDocumentFragment();
      for (const g of keys) {
        const html = buildGroupCardHtml(g);
        let node = existing.get(g) || null;
        if (!node || node.outerHTML !== html) {
          const frag = parseHtmlToFragment(html.trim());
          node = frag.firstElementChild;
        }
        if (node) frag.appendChild(node);
      }
      groupCardsEl.replaceChildren(frag);
    };
    let editingSettingsGroup = "";
    const openSettingsModal = (g) => {
      editingSettingsGroup = g || "";
      if (!editingSettingsGroup) return;
      const gs = groupSettingsMap.get(editingSettingsGroup) || {
        trigger_mode: "continuous",
        trigger_duration_ms: 10000,
        delay_seconds: 0,
        reboot_self_check: false,
      };
      $("#gsKeyLabel", view).textContent = `Group: ${editingSettingsGroup}`;
      $("#gsDuration", view).value = String(Number(gs.trigger_duration_ms || 10000));
      $("#gsMode", view).value = String(gs.trigger_mode || "continuous");
      $("#gsDelay", view).value = String(Number(gs.delay_seconds || 0));
      $("#gsReboot", view).checked = !!gs.reboot_self_check;
      grpSetModalEl.style.display = "flex";
    };
    const closeSettingsModal = () => { grpSetModalEl.style.display = "none"; };
    const collectSettingsPayload = () => {
      const mode = String($("#gsMode", view).value || "continuous");
      const duration = parseInt($("#gsDuration", view).value, 10);
      const delay = parseInt($("#gsDelay", view).value, 10);
      const reboot = !!$("#gsReboot", view).checked;
      if (!Number.isFinite(duration) || duration < 500 || duration > 300000) {
        throw new Error("Trigger duration must be 500-300000 ms");
      }
      if (!Number.isFinite(delay) || delay < 0 || delay > 3600) {
        throw new Error("Delay seconds must be 0-3600");
      }
      if (mode !== "continuous" && mode !== "delay") {
        throw new Error("Trigger mode invalid");
      }
      return {
        trigger_mode: mode,
        trigger_duration_ms: duration,
        delay_seconds: delay,
        reboot_self_check: reboot,
      };
    };
    const persistSettingsLocal = (groupKey, payload) => {
      const all = loadLocalGroupSettings();
      all[groupKey] = Object.assign({}, payload || {});
      saveLocalGroupSettings(all);
    };
    const saveGroupSettingsCompat = async (groupKey, payload) => {
      if (!groupApiCaps.settings) {
        persistSettingsLocal(groupKey, payload);
        return payload;
      }
      try {
        return await tryGroupApiCall(`/${encodeURIComponent(groupKey)}/settings`, {
          method: "PUT",
          body: payload,
        });
      } catch (e) {
        const msg = String((e && e.message) || e || "");
        if (msg.includes("404") || msg.includes("405") || msg.includes("501")) {
          groupApiCaps.settings = false;
          saveGroupApiCaps(groupApiCaps);
          persistSettingsLocal(groupKey, payload);
          return payload;
        }
        throw e;
      }
    };
    const applyGroupSettingsFallback = async (groupKey, payload) => {
      const ids = groupDeviceIds(groupKey);
      if (!ids.length) throw new Error("No devices in this group");
      if (!can("can_alert")) throw new Error("No can_alert capability");
      const durationMs = Number(payload.trigger_duration_ms || 10000);
      const delaySeconds = Number(payload.delay_seconds || 0);
      const prevTimer = groupDelayTimers.get(groupKey);
      if (prevTimer) {
        clearTimeout(prevTimer);
        groupDelayTimers.delete(groupKey);
      }
      if (String(payload.trigger_mode || "continuous") === "delay" && delaySeconds > 0) {
        const tid = setTimeout(async () => {
          try {
            await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
          } catch {}
        }, delaySeconds * 1000);
        groupDelayTimers.set(groupKey, tid);
      } else {
        await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
      }
      let rebootJobs = 0;
      let selfTests = 0;
      if (payload.reboot_self_check) {
        if (!can("can_send_command")) throw new Error("Reboot+self-check needs can_send_command");
        for (const did of ids) {
          await api(`/devices/${encodeURIComponent(did)}/self-test`, { method: "POST" });
          selfTests += 1;
          await api(`/devices/${encodeURIComponent(did)}/schedule-reboot`, {
            method: "POST",
            body: { delay_s: Math.max(5, delaySeconds + 5) },
          });
          rebootJobs += 1;
        }
      }
      return { ok: true, fallback: true, device_count: ids.length, self_tests: selfTests, reboot_jobs: rebootJobs };
    };
    $("#gsCancel", view).addEventListener("click", closeSettingsModal);
    $("#gsSave", view).addEventListener("click", async () => {
      try {
        if (!editingSettingsGroup) throw new Error("No group selected");
        const payload = collectSettingsPayload();
        const r = await saveGroupSettingsCompat(editingSettingsGroup, payload);
        groupSettingsMap.set(editingSettingsGroup, r || payload);
        renderGroups();
        closeSettingsModal();
        toast("Group settings saved", "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    $("#gsApply", view).addEventListener("click", async () => {
      try {
        if (!editingSettingsGroup) throw new Error("No group selected");
        const payload = collectSettingsPayload();
        await saveGroupSettingsCompat(editingSettingsGroup, payload);
        groupSettingsMap.set(editingSettingsGroup, payload);
        const r = await runGroupApplyOnAction({
          groupKey: editingSettingsGroup,
          payload,
          apiCaps: groupApiCaps,
          saveApiCaps: saveGroupApiCaps,
          tryApplyRoute: (gk) => tryGroupApiCall(`/${encodeURIComponent(gk)}/apply`, { method: "POST" }),
          applyFallback: applyGroupSettingsFallback,
        });
        renderGroups();
        closeSettingsModal();
        toast(`Applied to ${Number(r.device_count || 0)} devices${r && r.fallback ? " (fallback mode)" : ""}`, "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
    const clearGroupByDevicePatch = async (groupKey) => {
      const ids = groupDeviceIds(groupKey);
      if (!ids.length) return { ok: true, changed: 0 };
      let changed = 0;
      for (const id of ids) {
        await api(`/devices/${encodeURIComponent(id)}/profile`, {
          method: "PATCH",
          body: { notification_group: "" },
        });
        changed += 1;
      }
      return { ok: true, changed };
    };
    const deleteGroupCard = async (groupKey) => runGroupDeleteAction({
      groupKey,
      apiCaps: groupApiCaps,
      saveApiCaps: saveGroupApiCaps,
      tryDeletePostRoute: (gk) => tryGroupApiCall(`/${encodeURIComponent(gk)}/delete`, { method: "POST" }),
      tryDeleteRoute: (gk) => tryGroupApiCall(`/${encodeURIComponent(gk)}`, { method: "DELETE" }),
      clearFallback: clearGroupByDevicePatch,
    });
    const openGroupModal = (g) => {
      editingGroup = g || "";
      const m = meta[g] || { display_name: g || "", owner_name: "", phone: "", email: "", device_ids: [] };
      $("#gmKey", view).value = g || "";
      $("#gmName", view).value = m.display_name || "";
      $("#gmOwner", view).value = m.owner_name || "";
      $("#gmPhone", view).value = m.phone || "";
      $("#gmEmail", view).value = m.email || "";
      const sel = new Set((m.device_ids || []).map(String));
      const pick = $("#gmDevices", view);
      const isSharedGroup = groupSharedBy(g || "").length > 0;
      if (pick) {
        setChildMarkup(
          pick,
          devices.map((d) => `<label class="grp-pick-item"><input type="checkbox" value="${escapeHtml(d.device_id)}" ${sel.has(String(d.device_id)) ? "checked" : ""} ${isSharedGroup ? "disabled" : ""}/> <span>${escapeHtml(d.display_label || d.device_id)} <span class="mono">(${escapeHtml(d.device_id)})</span></span></label>`).join(""),
        );
        if (isSharedGroup) {
          prependChildMarkup(pick, `<p class="muted" style="margin:0 0 6px">Shared group: device membership is read-only.</p>`);
        }
      }
      grpModalEl.style.display = "flex";
    };
    const closeGroupModal = () => { grpModalEl.style.display = "none"; };
    let sharePrefillGroup = "";
    const openShareModal = async (prefillGroup) => {
      if (!shareModalEl) return;
      sharePrefillGroup = String(prefillGroup || "").trim();
      const devListEl = $("#shareDeviceList", view);
      const userListEl = $("#shareUserList", view);
      const hintEl = $("#shareTargetHint", view);
      const statEl = $("#shareBatchStat", view);
      if (!devListEl || !userListEl || !hintEl || !statEl) return;
      statEl.textContent = "";
      hintEl.textContent = sharePrefillGroup
        ? `Group: ${sharePrefillGroup} (you can still adjust selections).`
        : "Select devices, users, and permissions.";
      const picked = new Set(sharePrefillGroup ? groupDeviceIds(sharePrefillGroup).map(String) : []);
      setChildMarkup(
        devListEl,
        devices
          .filter((d) => !d.is_shared)
          .map((d) => `<label class="grp-pick-item"><input type="checkbox" value="${escapeHtml(d.device_id)}" ${picked.has(String(d.device_id)) ? "checked" : ""}/> <span>${escapeHtml(d.display_label || d.device_id)} <span class="mono">(${escapeHtml(d.device_id)})</span></span></label>`)
          .join("") || `<p class="muted">No own devices available.</p>`,
      );
      setChildMarkup(userListEl, `<p class="muted">Loading users…</p>`);
      try {
        const u = await api("/auth/users", { timeoutMs: 16000 });
        const users = (u.items || []).filter((x) => {
          const role = String(x.role || "");
          const st = String(x.status || "active");
          if (!(st === "active" || st === "")) return false;
          if (state.me && state.me.role === "admin") return role === "user";
          return role === "admin" || role === "user";
        });
        setChildMarkup(
          userListEl,
          users.map((x) =>
            `<label class="grp-pick-item"><input type="checkbox" value="${escapeHtml(x.username)}"/> <span>${escapeHtml(x.username)} <span class="mono">(${escapeHtml(x.role || "user")})</span></span></label>`,
          ).join("") || `<p class="muted">No active admin/user accounts.</p>`,
        );
      } catch (e) {
        setChildMarkup(userListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
      const allDev = $("#shareSelAllDevices", view);
      const allUsr = $("#shareSelAllUsers", view);
      if (allDev) {
        allDev.checked = false;
        allDev.onchange = () => {
          $$("#shareDeviceList input[type='checkbox']", view).forEach((x) => { x.checked = !!allDev.checked; });
        };
      }
      if (allUsr) {
        allUsr.checked = false;
        allUsr.onchange = () => {
          $$("#shareUserList input[type='checkbox']", view).forEach((x) => { x.checked = !!allUsr.checked; });
        };
      }
      shareModalEl.style.display = "flex";
    };
    const closeShareModal = () => { if (shareModalEl) shareModalEl.style.display = "none"; };
    $("#grpNew", view).addEventListener("click", () => openGroupModal(""));
    $("#gmCancel", view).addEventListener("click", closeGroupModal);
    const grpShareOpenBtn = $("#grpShareOpen", view);
    if (grpShareOpenBtn) grpShareOpenBtn.addEventListener("click", () => openShareModal(""));
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
        if (!deviceIds.length) { toast("Select at least one device", "err"); return; }
        if (!usernames.length) { toast("Select at least one user", "err"); return; }
        if (!canView && !canOperate) { toast("Select at least one permission", "err"); return; }
        const total = deviceIds.length * usernames.length;
        if (statEl) statEl.textContent = `Applying ${total} share grants…`;
        const res = await grantShareMatrix(
          deviceIds,
          usernames,
          { can_view: canView, can_operate: canOperate },
          (p) => { if (statEl) statEl.textContent = `Applied ${p.idx}/${p.total} · ok ${p.ok} · failed ${p.fail}`; },
        );
        const ok = Number(res.ok || 0);
        const fail = Number(res.fail || 0);
        if (fail === 0) {
          toast(`Sharing applied (${ok}/${total})`, "ok");
          closeShareModal();
        } else {
          toast(`Sharing done with failures (${ok} ok, ${fail} failed)`, "warn");
        }
      });
    }
    $("#gmSave", view).addEventListener("click", async () => {
      const key = String($("#gmKey", view).value || "").trim();
      if (!key) { toast("Group key required", "err"); return; }
      const oldKey = String(editingGroup || "").trim();
      const oldEntry = oldKey && Object.prototype.hasOwnProperty.call(meta, oldKey) ? meta[oldKey] : null;
      const display_name = String($("#gmName", view).value || "").trim();
      const owner_name = String($("#gmOwner", view).value || "").trim();
      const phone = String($("#gmPhone", view).value || "").trim();
      const email = String($("#gmEmail", view).value || "").trim();
      const picks = Array.from($$("#gmDevices input[type='checkbox']", view)).filter((x) => x.checked).map((x) => String(x.value || "").trim());
      if (groupSharedBy(key).length > 0) {
        const keepIds = (oldEntry && Array.isArray(oldEntry.device_ids)) ? oldEntry.device_ids.map((x) => String(x)) : [];
        if (editingGroup && editingGroup !== key && meta[editingGroup]) delete meta[editingGroup];
        meta[key] = { display_name, owner_name, phone, email, device_ids: keepIds };
        saveGroupMeta(meta);
        try { bustDeviceListCaches(); } catch (_) {}
        closeGroupModal();
        renderGroups();
        toast("Group card updated (shared group — device list is owner-managed)", "ok");
        return;
      }
      const previousDeviceIds = (oldEntry && Array.isArray(oldEntry.device_ids))
        ? oldEntry.device_ids.map((x) => String(x || "").trim())
        : [];
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
      if (editingGroup && editingGroup !== key && meta[editingGroup]) delete meta[editingGroup];
      meta[key] = { display_name, owner_name, phone, email, device_ids: picks };
      saveGroupMeta(meta);
      try { bustDeviceListCaches(); } catch (_) {}
      closeGroupModal();
      renderGroups();
      toast("Group saved — device notification groups synced for sibling alarm fan-out", "ok");
    });
    groupCardsEl.addEventListener("click", async (ev) => {
      const btn = ev.target.closest("button");
      if (btn) {
        const g = btn.dataset.group || "";
        if (!g) return;
        if (btn.classList.contains("js-edit-group")) {
          openGroupModal(g);
          return;
        }
        if (btn.classList.contains("js-group-settings")) {
          openSettingsModal(g);
          return;
        }
        if (btn.classList.contains("js-share-group")) {
          if (!(state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users"))))) {
            toast("No sharing permission", "err"); return;
          }
          openShareModal(g);
          return;
        }
        if (btn.classList.contains("js-del-group")) {
          if (groupSharedBy(g).length > 0) { toast("Shared group cannot be deleted", "err"); return; }
          if (!confirm(`Delete group card "${g}"?`)) return;
          try {
            await deleteGroupCard(g);
            delete meta[g];
            saveGroupMeta(meta);
            renderGroups();
            toast("Group deleted", "ok");
          } catch (e) {
            toast(e.message || e, "err");
          }
          return;
        }
        if (!can("can_alert")) { toast("No can_alert capability", "err"); return; }
        const ids = groupDeviceIds(g);
        if (ids.length === 0) { toast("No devices in this group", "warn"); return; }
        const action = btn.classList.contains("js-alert-on") ? "on" : "off";
        if (!confirm(`${action === "on" ? "Open" : "Close"} alarm for ${ids.length} devices in ${g}?`)) return;
        try {
          if (action === "on") {
            // Alarm ON should honor group settings (delay/continuous/reboot flow) via server apply.
            const payload = groupTriggerPayloadFromSettings(groupSettingsMap.get(g) || {});
            await runGroupApplyOnAction({
              groupKey: g,
              payload,
              apiCaps: groupApiCaps,
              saveApiCaps: saveGroupApiCaps,
              tryApplyRoute: (gk) => tryGroupApiCall(`/${encodeURIComponent(gk)}/apply`, { method: "POST" }),
              applyFallback: applyGroupSettingsFallback,
            });
          } else {
            const prevTimer = groupDelayTimers.get(g);
            if (prevTimer) {
              clearTimeout(prevTimer);
              groupDelayTimers.delete(g);
            }
            await api("/alerts", { method: "POST", body: { action, duration_ms: 10000, device_ids: ids } });
          }
          toast(`${action === "on" ? "Alarm ON" : "Alarm OFF"} · ${ids.length}`, "ok");
        } catch (e) {
          toast(e.message || e, "err");
        }
        return;
      }
      const card = ev.target.closest(".js-group-card");
      if (!card) return;
      const g = card.dataset.group || "";
      if (!g) return;
      location.hash = `#/group/${encodeURIComponent(g)}`;
    });
    const OVERVIEW_LIVE_MS = 7500;
    const refreshOverviewLive = async () => {
      if (!isRouteCurrent(routeSeq)) return;
      try {
        bustApiGetCachedPrefix("/dashboard/overview");
        bustApiGetCachedPrefix("/devices");
        const [ovN, listN] = await Promise.all([
          api("/dashboard/overview", { timeoutMs: 20000, retries: 2 }),
          api("/devices", { timeoutMs: 20000, retries: 2 }),
        ]);
        if (!isRouteCurrent(routeSeq)) return;
        ov = ovN || ov;
        list = listN || list;
        state.overviewCache = { ov, list, ts: Date.now() };
        devices = Array.isArray(list.items) ? list.items.slice() : [];
        byId = new Map(devices.map((d) => [String(d.device_id), d]));
        const hh = state.health || {};
        const mqConnected = !!(hh.mqtt_connected ?? ov.mqtt_connected);
        const mqQDepth = Number(hh.mqtt_ingest_queue_depth || 0);
        const mqDropped = Number(hh.mqtt_ingest_dropped || 0);
        const totalDevices = Number(ov.total_devices != null ? ov.total_devices : devices.length);
        const onlineDevices = Number((ov.presence && ov.presence.online != null) ? ov.presence.online : devices.filter(isOnline).length);
        const offlineDevices = Math.max(0, totalDevices - onlineDevices);
        const txBps = Number((ov.throughput && ov.throughput.tx_bps_total) || 0);
        const rxBps = Number((ov.throughput && ov.throughput.rx_bps_total) || 0);
        const bps = (v) => {
          v = Number(v || 0);
          if (v < 1024) return `${v.toFixed(0)} B/s`;
          if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
          return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
        };
        const mqStatus = !mqConnected ? "Disconnected" : (mqDropped > 0 || mqQDepth >= 300 ? "Warning" : "Healthy");
        const mqClass = !mqConnected ? "revoked" : (mqStatus === "Warning" ? "offline" : "online");
        patchOverviewHeader({
          server: mqConnected ? "Connected" : "Disconnected",
          devices: totalDevices,
          online: onlineDevices,
          offline: offlineDevices,
          tx: bps(txBps),
          rx: bps(rxBps),
          queue: mqQDepth,
          dropped: mqDropped,
          risk: mqStatus,
          riskClass: mqClass,
        });
        syncGroupMetaWithDevices(meta, devices);
        saveGroupMeta(meta);
        renderGroups();
      } catch (_) {}
    };
    scheduleRouteTicker(routeSeq, "overview-live", refreshOverviewLive, OVERVIEW_LIVE_MS);
    renderGroups();
  });

  registerRoute("group", async (view, args, routeSeq) => {
    const g = decodeURIComponent(args[0] || "").trim();
    if (!g) { location.hash = "#/overview"; return; }
    const groupScope = (state.me && state.me.username) ? state.me.username : "anon";
    const GROUP_META_LS_KEY = `croc.group.meta.v2.${groupScope}`;
    const GROUP_SETTINGS_LS_KEY = `croc.group.settings.v1.${groupScope}`;
    const GROUP_API_CAPS_LS_KEY = `croc.group.api.caps.v2.${groupScope}`;
    const loadGroupMeta = () => {
      try {
        const raw = localStorage.getItem(GROUP_META_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return (obj && typeof obj === "object") ? obj : {};
      } catch { return {}; }
    };
    const loadGroupSettings = () => {
      try {
        const raw = localStorage.getItem(GROUP_SETTINGS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return (obj && typeof obj === "object") ? obj : {};
      } catch { return {}; }
    };
    const loadGroupApiCaps = () => {
      try {
        const raw = localStorage.getItem(GROUP_API_CAPS_LS_KEY);
        const obj = raw ? JSON.parse(raw) : {};
        return {
          apply: obj && obj.apply === false ? false : true,
          delete: obj && obj.delete === false ? false : true,
        };
      } catch { return { apply: true, delete: true }; }
    };
    const saveGroupApiCaps = (caps) => localStorage.setItem(GROUP_API_CAPS_LS_KEY, JSON.stringify({
      apply: !!(caps && caps.apply),
      delete: !!(caps && caps.delete),
    }));
    window.__groupDelayTimers = window.__groupDelayTimers || new Map();
    const meta = loadGroupMeta();
    const gsMap = loadGroupSettings();
    const groupApiCaps = loadGroupApiCaps();
    const [listRes] = await Promise.allSettled([apiGetCached("/devices", { timeoutMs: 16000 }, 3000)]);
    let list = (listRes.status === "fulfilled" && listRes.value) ? listRes.value : { items: [] };
    let byId = new Map((list.items || []).map((d) => [String(d.device_id), d]));
    syncGroupMetaWithDevices(meta, list.items || []);
    try { localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta)); } catch (_) {}
    const gm = meta[g] || { display_name: g, owner_name: "", phone: "", email: "", device_ids: [] };
    let ids = Array.isArray(gm.device_ids) ? gm.device_ids.map(String) : [];
    let rows = ids.map((id) => byId.get(id)).filter(Boolean);
    const isSharedGroup = rows.some((d) => !!d.is_shared);
    const online = rows.filter((d) => isOnline(d)).length;
    const offline = Math.max(0, rows.length - online);
    setCrumb(`Group · ${gm.display_name || g}`);
    mountView(view, `
      <section class="card">
        <div class="row">
          <h2 style="margin:0">${escapeHtml(gm.display_name || g)}</h2>
          <button class="btn sm danger right" id="grpDelete" ${isSharedGroup ? "disabled title=\"Shared group cannot be deleted\"" : ""}>Delete group</button>
          <a href="#/overview" class="btn ghost right">← Back</a>
        </div>
        <div class="divider"></div>
        <div class="row" style="gap:6px;flex-wrap:wrap">
          <span class="badge neutral">total <span id="grpTotal">${rows.length}</span></span>
          <span class="badge online">online <span id="grpOnline">${online}</span></span>
          <span class="badge offline">offline <span id="grpOffline">${offline}</span></span>
          <span class="chip">${escapeHtml(g)}</span>
        </div>
        <p class="muted" style="margin-top:8px">Owner: ${escapeHtml(gm.owner_name || "—")} · ${escapeHtml(gm.phone || "—")} · ${escapeHtml(gm.email || "—")}</p>
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
        }).join("") : `<p class="muted">No devices in this group.</p>`,
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
    const deleteGroupCardCompat = async (groupKey) => runGroupDeleteAction({
      groupKey,
      apiCaps: groupApiCaps,
      saveApiCaps: saveGroupApiCaps,
      tryDeletePostRoute: async (gk) => {
        try { return await api(`/group-cards/${encodeURIComponent(gk)}/delete`, { method: "POST" }); } catch (e) {
          if (!isGroupRouteMissingError(e)) throw e;
        }
        return await api(`/api/group-cards/${encodeURIComponent(gk)}/delete`, { method: "POST" });
      },
      tryDeleteRoute: async (gk) => {
        try { return await api(`/group-cards/${encodeURIComponent(gk)}`, { method: "DELETE" }); } catch (e) {
          if (!isGroupRouteMissingError(e)) throw e;
        }
        return await api(`/api/group-cards/${encodeURIComponent(gk)}`, { method: "DELETE" });
      },
      clearFallback: clearGroupByDevicePatchCompat,
    });
    const applyGroupSettingsFallbackCompat = async (groupKey, payload) => {
      const durationMs = Number(payload.trigger_duration_ms || 10000);
      const delaySeconds = Number(payload.delay_seconds || 0);
      const prev = window.__groupDelayTimers.get(groupKey);
      if (prev) {
        clearTimeout(prev);
        window.__groupDelayTimers.delete(groupKey);
      }
      if (String(payload.trigger_mode || "continuous") === "delay" && delaySeconds > 0) {
        const tid = setTimeout(async () => {
          try { await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } }); } catch {}
        }, delaySeconds * 1000);
        window.__groupDelayTimers.set(groupKey, tid);
      } else {
        await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
      }
      return { ok: true, fallback: true, device_count: ids.length };
    };
    const tryApplyRouteCompat = async (groupKey) => {
      try { return await api(`/group-cards/${encodeURIComponent(groupKey)}/apply`, { method: "POST" }); } catch (e) {
        if (!isGroupRouteMissingError(e)) throw e;
      }
      return await api(`/api/group-cards/${encodeURIComponent(groupKey)}/apply`, { method: "POST" });
    };
    const sendAlert = async (action) => {
      if (!can("can_alert")) { toast("No can_alert capability", "err"); return; }
      if (ids.length === 0) { toast("No devices in this group", "warn"); return; }
      if (!confirm(`${action === "on" ? "Open" : "Close"} alarm for ${ids.length} devices in ${g}?`)) return;
      if (action === "on") {
        const payload = groupTriggerPayloadFromSettings(gsMap[g] || {});
        await runGroupApplyOnAction({
          groupKey: g,
          payload,
          apiCaps: groupApiCaps,
          saveApiCaps: saveGroupApiCaps,
          tryApplyRoute: tryApplyRouteCompat,
          applyFallback: applyGroupSettingsFallbackCompat,
        });
      } else {
        const prev = window.__groupDelayTimers.get(g);
        if (prev) {
          clearTimeout(prev);
          window.__groupDelayTimers.delete(g);
        }
        await api("/alerts", { method: "POST", body: { action: "off", duration_ms: 10000, device_ids: ids } });
      }
      toast(`${action === "on" ? "Alarm ON" : "Alarm OFF"} · ${ids.length}`, "ok");
    };
    const alarmOnBtn = $("#grpAlarmOn", view);
    const alarmOffBtn = $("#grpAlarmOff", view);
    const delGroupBtn = $("#grpDelete", view);
    if (alarmOnBtn) alarmOnBtn.addEventListener("click", () => sendAlert("on"));
    if (alarmOffBtn) alarmOffBtn.addEventListener("click", () => sendAlert("off"));
    if (delGroupBtn) {
      delGroupBtn.addEventListener("click", async () => {
        if (isSharedGroup) { toast("Shared group cannot be deleted", "err"); return; }
        if (!confirm(`Delete group card "${g}"?`)) return;
        try {
          await deleteGroupCardCompat(g);
          delete meta[g];
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
      const latest = await apiGetCached("/devices", { timeoutMs: 16000 }, 2000);
      if (!isRouteCurrent(routeSeq)) return;
      list = latest || { items: [] };
      byId = new Map((list.items || []).map((d) => [String(d.device_id), d]));
      syncGroupMetaWithDevices(meta, list.items || []);
      try { localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta)); } catch (_) {}
      const gm2 = meta[g] || { display_name: g, owner_name: "", phone: "", email: "", device_ids: [] };
      ids = Array.isArray(gm2.device_ids) ? gm2.device_ids.map(String) : [];
      rows = ids.map((id2) => byId.get(id2)).filter(Boolean);
      renderGroupDevices();
    };
    scheduleRouteTicker(routeSeq, `group-live-${g}`, refreshGroupLive, 10000);
  });

  // Device list (no id) + device detail
  registerRoute("devices", async (view, args, routeSeq) => {
    const id = decodeURIComponent(args[0] || "");
    if (!id) {
      setCrumb("All devices");
      let allItems = [];
      const deviceListCard = (d) => {
        const on = isOnline(d);
        const primary = escapeHtml(d.display_label || d.device_id || "unknown");
        const subId = d.display_label ? `<div class="device-id-sub mono">${escapeHtml(d.device_id || "")}</div>` : "";
        const letter = escapeHtml((d.display_label || d.device_id || "?").slice(0, 1).toUpperCase());
        let subMeta = "";
        if (state.me && state.me.role === "superadmin" && d.owner_admin) {
          subMeta = `Owner: ${escapeHtml(String(d.owner_admin))}<br/>`;
        } else if (d.is_shared && d.shared_by) {
          subMeta = `Shared: ${escapeHtml(String(d.shared_by))}<br/>`;
        }
        return `<a class="device-card device-card--row-thumb" href="#/devices/${encodeURIComponent(d.device_id)}" style="text-decoration:none;color:inherit">` +
          `<div class="device-thumb device-thumb--list" aria-hidden="true">${letter}</div>` +
          `<div class="device-card--row-body">` +
          `<h3 style="margin:0"><div class="device-primary-name">${primary}</div>${subId}</h3>` +
          `<div><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>` +
          (d.zone ? ` <span class="chip">${escapeHtml(d.zone)}</span>` : "") +
          (d.fw ? ` <span class="chip">v${escapeHtml(d.fw)}</span>` : "") +
          (d.is_shared ? ` <span class="badge accent" title="shared device">shared</span>` : "") +
          `</div>` +
          `<div class="meta" style="margin-top:4px">${subMeta}Updated: ${escapeHtml(fmtRel(d.updated_at))}</div>` +
          `</div></a>`;
      };
      const applyFilter = () => {
        const inp = $("#allDevFilter", view);
        const q = inp ? String(inp.value || "").trim().toLowerCase() : "";
        const items = allItems.filter((d) => {
          if (!q) return true;
          const did = String(d.device_id || "").toLowerCase();
          const nm = String(d.display_label || "").toLowerCase();
          const grp = String(d.notification_group || "").toLowerCase();
          return did.includes(q) || nm.includes(q) || grp.includes(q);
        });
        const grid = $("#allDevicesGrid", view);
        if (!grid) return;
        if (allItems.length === 0) {
          setChildMarkup(grid, `<p class="muted" style="padding:8px 0">No devices in your scope.</p>`);
          return;
        }
        setChildMarkup(
          grid,
          items.length === 0
            ? `<p class="muted" style="padding:8px 0">No matches.</p>`
            : items.map(deviceListCard).join(""),
        );
      };
      const load = async () => {
        if (!isRouteCurrent(routeSeq)) return;
        const r = await api("/devices", { timeoutMs: 20000, retries: 2 });
        if (!isRouteCurrent(routeSeq)) return;
        allItems = Array.isArray(r.items) ? r.items : [];
        applyFilter();
      };
      mountView(view, `
        <div class="card" style="margin:0 0 12px">
          <h2 class="ui-section-title" style="margin:0">All devices</h2>
          <p class="muted" style="margin:8px 0 0">Thumbnails and quick status. Click a card for full device controls.</p>
          <div class="inline-form" style="margin-top:12px">
            <label class="field" style="max-width:min(100%, 360px)">
              <span>Filter</span>
              <input type="search" id="allDevFilter" placeholder="id / name / group" autocomplete="off" />
            </label>
          </div>
        </div>
        <div id="allDevicesGrid" class="device-grid">
          <p class="muted">Loading…</p>
        </div>
      `);
      const f = $("#allDevFilter", view);
      if (f) f.addEventListener("input", () => { applyFilter(); });
      await load();
      scheduleRouteTicker(routeSeq, "devices-list-live", load, 12000);
      return;
    }
    const isSuperViewer = !!(state.me && state.me.role === "superadmin");

    let d = await api(`/devices/${encodeURIComponent(id)}`);
    window.__devicePollLocks = window.__devicePollLocks || new Map();
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
    setCrumb(d.display_label ? `Device · ${d.display_label}` : `Device · ${id}`);
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
    const deviceLiveModel = (dev) => {
      const on = isOnline(dev);
      const s = dev.last_status_json || {};
      const reason = s.disconnect_reason || (on ? "none" : "network_lost");
      const outV = (s.vbat == null || s.vbat < 0) ? "—" : `${Number(s.vbat).toFixed(2)} V`;
      const rssi = (s.rssi == null || s.rssi === -127) ? "—" : `${s.rssi} dBm`;
      const netT = String(s.net_type || dev.net_type || "");
      const wifiSsidDd = netT === "wifi"
        ? ((s.wifi_ssid != null && String(s.wifi_ssid).length > 0)
          ? escapeHtml(String(s.wifi_ssid))
          : `<span class="muted">Not associated</span>`)
        : `<span class="muted">N/A (${escapeHtml(netT || "—")})</span>`;
      const wifiChDd = (netT === "wifi" && s.wifi_channel != null && Number(s.wifi_channel) > 0)
        ? escapeHtml(String(s.wifi_channel))
        : "—";
      return { on, s, reason, outV, rssi, wifiSsidDd, wifiChDd };
    };
    const dm = deviceLiveModel(d);
    const rawCommandDrawer = (state.me && state.me.role === "superadmin") ? `
      <details class="card device-drawer">
        <summary class="device-drawer__summary">
          <span class="device-drawer__title">Raw command</span>
          <span class="device-drawer__hint muted">Superadmin · manual MQTT cmd</span>
        </summary>
        <div class="device-drawer__body">
          <label class="field"><span>cmd</span><input id="cmdName" placeholder="get_info / ota" ${can("can_send_command") ? "" : "disabled"} /></label>
          <label class="field" style="margin-top:8px"><span>params (JSON)</span><textarea id="cmdParams" placeholder='{"key":"value"}' ${can("can_send_command") ? "" : "disabled"}></textarea></label>
          <div class="row" style="margin-top:8px;justify-content:flex-end">
            <button class="btn" id="sendCmd" ${can("can_send_command") ? "" : "disabled"}>Send</button>
          </div>
        </div>
      </details>` : "";
    const canUseSharePanel = !!(
      state.me
      && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users")))
      && (!d.is_shared || state.me.role === "superadmin")
    );
    const sharePanel = canUseSharePanel ? `
      <div class="card" id="sharePanel">
        <div class="row">
          <h3 style="margin:0">Sharing</h3>
          <span class="muted">Grant or revoke per-account access (admin: your users only)</span>
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
    const renderMsgFeed = (items) => {
      const msgItems = Array.isArray(items) ? items : [];
      if (msgItems.length === 0) return `<p class="muted audit-empty">No messages.</p>`;
      return `<div class="audit-feed">${msgItems.map((m) => {
        const plRows = messagePayloadRows(m.payload || {});
        const extra = plRows.length
          ? `<div class="audit-extra">${plRows.map((row) =>
              `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`,
          ).join("")}</div>`
          : "";
        return `<article class="audit-item">
          <div class="audit-item-top">
            <div class="audit-time">
              <span class="audit-ts mono">${escapeHtml((m.ts_received || "").replace("T", " ").replace(/\..*/, ""))}</span>
              <span class="muted audit-rel">${escapeHtml(fmtRel(m.ts_received))}</span>
            </div>
            <span class="chip">${escapeHtml(m.channel || "—")}</span>
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
          <div class="audit-feed-wrap" id="devMsgsList"><p class="muted">Expand to load…</p></div>
        </details>
      </div>` : "";
    mountView(view, `
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
            <a href="#/overview" class="btn ghost right">← Overview</a>
          </div>
          <div class="device-hero-card">
            <div class="device-thumb">${escapeHtml((d.display_label || id || "?").slice(0, 1).toUpperCase())}</div>
            <div class="device-hero-meta">
              <div class="device-hero-line"><span class="muted">Firmware</span><span class="mono">${escapeHtml(d.fw || "—")}</span></div>
              <div class="device-hero-line"><span class="muted">Platform</span><span class="mono">${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}</span></div>
              <div class="device-hero-line"><span class="muted">Network</span><span class="mono" id="devNetRow">${escapeHtml(d.net_type || "—")} · ${escapeHtml(dm.s.ip || "—")}</span></div>
              <div class="device-hero-line"><span class="muted">Wi‑Fi</span><span id="devWifiSsid">${dm.wifiSsidDd}</span></div>
              <div class="device-hero-line"><span class="muted">Output V</span><span class="mono" id="devOutV">${escapeHtml(dm.outV)}</span></div>
              <div class="device-hero-line"><span class="muted">Tx / Rx</span><span class="mono" id="devTxRx">${escapeHtml(bps(dm.s.tx_bps))} / ${escapeHtml(bps(dm.s.rx_bps))}</span></div>
              <div class="device-hero-line"><span class="muted">RSSI</span><span class="mono" id="devRssi">${escapeHtml(dm.rssi)}</span></div>
              <div class="device-hero-line"><span class="muted">Wi‑Fi CH</span><span class="mono" id="devWifiCh">${dm.wifiChDd}</span></div>
              <div class="device-hero-line"><span class="muted">Uptime</span><span class="mono" id="devUptime">${escapeHtml((dm.s.uptime_s ? `${Math.floor(dm.s.uptime_s / 3600)}h ${Math.floor((dm.s.uptime_s % 3600) / 60)}m` : "—"))}</span></div>
              <div class="device-hero-line"><span class="muted">Heap</span><span class="mono" id="devHeap">${escapeHtml(dm.s.free_heap ? `${dm.s.free_heap} B (min ${dm.s.min_free_heap || "?"} B)` : "—")}</span></div>
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
              <div><span class="muted">Account</span><span class="mono">${escapeHtml(d.owner_admin || d.shared_by || "—")}</span></div>
              <div><span class="muted">Email</span><span class="mono">${escapeHtml(d.owner_email || "—")}</span></div>
              <div><span class="muted">Shared</span><span class="mono">${d.is_shared ? `yes · by ${escapeHtml(d.shared_by || "?")}` : "no"}</span></div>
            </div>
            <div class="row" style="margin-top:12px;gap:8px;flex-wrap:wrap">
              <button class="btn danger" id="deleteReset" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Unbind (delete & reset)</button>
              ${(state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_send_command"))))
                ? `<button class="btn danger" id="factoryUnregister" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Rollback to unregistered</button>`
                : ""}
            </div>
          </div>
          <div class="card" style="margin:12px 0 0">
            <h3 style="margin:0 0 8px;font-size:13px;color:var(--text-muted)">Notifications</h3>
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
        </aside>
      </div>

      <div class="split device-quick-split">
        <div class="card">
          <h3>Quick actions</h3>
          ${d.is_shared ? `<p class="muted" style="margin:0 0 8px">Shared by <span class="mono">${escapeHtml(d.shared_by || "?")}</span>. Delete/Revoke actions are disabled for shared devices.</p>` : ""}
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
            <button class="btn danger" id="revoke" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Revoke</button>
            <button class="btn secondary" id="unrevoke" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Unrevoke</button>
          </div>
        </div>
      </div>
      ${sharePanel}

      <details class="card device-drawer" id="wifiCtlCard">
        <summary class="device-drawer__summary">
          <span class="device-drawer__title">Wi‑Fi (device)</span>
          <span class="device-drawer__hint muted">Provision · NVS · expand</span>
        </summary>
        <div class="device-drawer__body">
          <p class="muted" style="margin:0 0 10px">Online/offline unified provisioning: create a Wi‑Fi task, then poll until success/fail. Credentials are saved to device NVS and device reboots.</p>
          ${can("can_send_command") ? `
          <div class="inline-form" style="margin-top:4px">
            <label class="field grow"><span>New SSID</span><input id="wifiNewSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz network name" /></label>
            <label class="field grow"><span>Password</span><input id="wifiNewPass" type="password" maxlength="64" autocomplete="new-password" placeholder="empty if open network" /></label>
            <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:8px">
              <button class="btn btn-tap" type="button" id="wifiApplyBtn">Start provision task</button>
              <button class="btn danger btn-tap" type="button" id="wifiClearBtn">Clear saved Wi‑Fi & reboot</button>
            </div>
          </div>
          <div style="margin-top:8px">
            <progress id="wifiTaskProgress" value="0" max="100" style="width:100%;height:12px"></progress>
          </div>
          <p class="muted" id="wifiScanStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span>.</p>`}
        </div>
      </details>

      <details class="card device-drawer" id="triggerPolicyCard">
        <summary class="device-drawer__summary">
          <span class="device-drawer__title">Trigger policy</span>
          <span class="device-drawer__hint muted">Server · group scope · expand</span>
        </summary>
        <div class="device-drawer__body">
          <p class="muted" style="margin:0 0 10px">Scope: owner account + group <span class="mono">${escapeHtml(d.notification_group || "(default)")}</span>. Siblings = same tenant + same <span class="mono">notification_group</span> (+ zone match). Remote #1 = silent linkage; #2 = loud to siblings only; panic = local siren + optional sibling fan-out.</p>
          ${can("can_send_command") ? `
          <div class="inline-form" style="margin-top:4px;gap:12px;flex-wrap:wrap">
            <label class="field"><span>Panic local siren</span><input type="checkbox" id="tpPanicLocal" /></label>
            <label class="field"><span>Panic sibling link</span><input type="checkbox" id="tpPanicLink" /></label>
            <label class="field"><span>Remote silent link</span><input type="checkbox" id="tpSilentLink" /></label>
            <label class="field"><span>Remote loud link</span><input type="checkbox" id="tpLoudLink" /></label>
            <label class="field"><span>Exclude self</span><input type="checkbox" id="tpExcludeSelf" /></label>
            <label class="field"><span>Loud duration (ms)</span><input id="tpLoudDur" type="number" min="500" max="300000" value="10000" /></label>
            <div class="row wide" style="justify-content:flex-end">
              <button class="btn secondary btn-tap" type="button" id="tpRefresh">Refresh policy</button>
              <button class="btn btn-tap" type="button" id="tpSave">Save policy</button>
            </div>
          </div>
          <p class="muted" id="tpStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span>.</p>`}
        </div>
      </details>

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
      const setText = (idSel, txt) => { const el = $(idSel, view); if (el) el.textContent = String(txt); };
      const setHtml = (idSel, txt) => { const el = $(idSel, view); if (el) setChildMarkup(el, String(txt)); };
      setText("#devNetRow", `${dev.net_type || "—"} · ${m.s.ip || "—"}`);
      setHtml("#devWifiSsid", m.wifiSsidDd);
      setHtml("#devWifiCh", m.wifiChDd);
      setText("#devRssi", m.rssi);
      setText("#devOutV", m.outV);
      setText("#devTxRx", `${bps(m.s.tx_bps)} / ${bps(m.s.rx_bps)}`);
      setText("#devDisconnect", m.reason);
      setText("#devUptime", m.s.uptime_s ? `${Math.floor(m.s.uptime_s / 3600)}h ${Math.floor((m.s.uptime_s % 3600) / 60)}m` : "—");
      setText("#devHeap", m.s.free_heap ? `${m.s.free_heap} B (min ${m.s.min_free_heap || "?"} B)` : "—");
      setText("#devUpdated", `${fmtTs(dev.updated_at)} (${fmtRel(dev.updated_at)})`);
    };
    scheduleRouteTicker(routeSeq, `device-live-${id}`, async () => {
      if (!isRouteCurrent(routeSeq)) return;
      const latest = await apiGetCached(`/devices/${encodeURIComponent(id)}`, { timeoutMs: 16000 }, 2000);
      if (!isRouteCurrent(routeSeq) || !latest) return;
      d = latest;
      patchDeviceLive(latest);
    }, 8000);
    if (isSuperViewer) {
      const det = $("#mqttMsgDetails", view);
      const box = $("#devMsgsList", view);
      let loaded = false;
      const loadDebugMsgs = async () => {
        if (loaded || !box) return;
        loaded = true;
        setChildMarkup(box, `<p class="muted">Loading…</p>`);
        try {
          const msgs = await api(`/devices/${encodeURIComponent(id)}/messages?limit=25`, { timeoutMs: 16000 });
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
        const newGroup = ($("#notifGroup").value || "").trim();
        await api(`/devices/${encodeURIComponent(id)}/profile`, {
          method: "PATCH",
          body: {
            display_label: ($("#dispLabel").value || "").trim(),
            notification_group: newGroup,
          },
        });
        reconcileGroupMetaForDevice(id, newGroup);
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
        bustDeviceListCaches();
        toast("Revoked", "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });
    $("#unrevoke").addEventListener("click", withDev(async () => {
      await api(`/devices/${encodeURIComponent(id)}/unrevoke`, { method: "POST" });
      bustDeviceListCaches();
    }));
    const deleteResetBtn = $("#deleteReset", view);
    if (deleteResetBtn) {
      deleteResetBtn.addEventListener("click", async () => {
        if (!confirm("Delete this device from current account records? You can re-add and reconfigure later.")) return;
        const typed = String(prompt(`Type device ID to confirm delete/reset:\n${id}`) || "").trim();
        if (typed.toUpperCase() !== String(id).toUpperCase()) { toast("Confirmation mismatch", "err"); return; }
        try {
          const dr = await api(`/devices/${encodeURIComponent(id)}/delete-reset`, {
            method: "POST",
            body: { confirm_text: typed },
          });
          removeDeviceIdFromAllGroupMeta(id);
          bustDeviceListCaches();
          const okNv = dr && (dr.nvs_purge_sent === true);
          toast(`Device removed from account.${okNv ? " Device cleared WiFi+claim in NVS (rebooting)." : " If it was offline, use WiFi clear or reflash; deploy latest API+firmware to auto-clear on delete."} Re-add from Activate.`, "ok");
          location.hash = "#/overview";
        } catch (e) { toast(e.message || e, "err"); }
      });
    }
    const factoryUnregisterBtn = $("#factoryUnregister", view);
    if (factoryUnregisterBtn) {
      factoryUnregisterBtn.addEventListener("click", async () => {
        const isSa = !!(state.me && state.me.role === "superadmin");
        const msg = isSa
          ? "Superadmin: rollback this device to UNREGISTERED (factory serial kept). Continue?"
          : "Rollback YOUR device to UNREGISTERED (factory serial kept). You can claim again later. Continue?";
        if (!confirm(msg)) return;
        const typed = String(prompt(`Type device ID to confirm factory-unregister:\n${id}`) || "").trim();
        if (typed.toUpperCase() !== String(id).toUpperCase()) { toast("Confirmation mismatch", "err"); return; }
        try {
          const fr = await api(`/devices/${encodeURIComponent(id)}/factory-unregister`, {
            method: "POST",
            body: { confirm_text: typed },
          });
          removeDeviceIdFromAllGroupMeta(id);
          bustDeviceListCaches();
          const okNv = fr && (fr.nvs_purge_sent === true);
          toast(
            `Server: unclaimed / factory list updated.${okNv ? " Board received unclaim_reset (WiFi+creds cleared, rebooting)." : " If the board was offline, WiFi may still be in NVS — use WiFi clear, or flash API+firmware with unclaim_reset."} Serial in factory table preserved.`,
            "ok",
          );
          location.hash = "#/overview";
        } catch (e) { toast(e.message || e, "err"); }
      });
    }

    const sendCmdBtn = $("#sendCmd");
    if (sendCmdBtn) {
      sendCmdBtn.addEventListener("click", async () => {
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
    }

    const waitForCmdAck = async (expectedCmd) => runPollDedup(`ack:${id}:${String(expectedCmd || "")}`, async () => {
      for (let i = 0; i < 36; i++) {
        await new Promise((r) => setTimeout(r, 500));
        const d2 = await api(`/devices/${encodeURIComponent(id)}`);
        const a = d2.last_ack_json || {};
        if (a.cmd === expectedCmd && typeof a.ok === "boolean") {
          return a;
        }
      }
      return null;
    });

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
          toast("已预填认领页保存的 Wi‑Fi；设备在线时可在下方启动下发。", "ok");
        }
      }
    } catch (_) {}
    const wifiTaskProgress = $("#wifiTaskProgress");
    const setWifiProgress = (n) => {
      if (!wifiTaskProgress) return;
      const v = Math.max(0, Math.min(100, Number(n || 0)));
      wifiTaskProgress.value = v;
    };
    const pollWifiTask = async (taskId) => runPollDedup(`wifi-task:${id}:${String(taskId || "")}`, async () => {
      const st = $("#wifiScanStatus");
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        try {
          const t = await api(`/devices/${encodeURIComponent(id)}/provision/wifi-task/${encodeURIComponent(taskId)}`, { timeoutMs: 16000 });
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
        const ssid = ($("#wifiNewSsid").value || "").trim();
        const password = $("#wifiNewPass").value || "";
        const st = $("#wifiScanStatus");
        if (!ssid) { toast("Enter SSID", "err"); return; }
        if (!confirm("Save Wi‑Fi on device and reboot? You may lose contact until it joins the new network.")) return;
        try {
          wifiApplyBtn.disabled = true;
          setWifiProgress(10);
          if (st) st.textContent = "Creating provision task…";
          const r = await api(`/devices/${encodeURIComponent(id)}/provision/wifi-task`, {
            method: "POST",
            body: { ssid, password },
          });
          setWifiProgress(r.progress || 35);
          if (st) st.textContent = `Task ${r.task_id} running…`;
          await pollWifiTask(r.task_id);
        } catch (e) { toast(e.message || e, "err"); if (st) st.textContent = String(e.message || e); }
        finally { wifiApplyBtn.disabled = false; }
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

    const tpPanicLocal = $("#tpPanicLocal");
    const tpPanicLink = $("#tpPanicLink");
    const tpSilentLink = $("#tpSilentLink");
    const tpLoudLink = $("#tpLoudLink");
    const tpExcludeSelf = $("#tpExcludeSelf");
    const tpLoudDur = $("#tpLoudDur");
    const tpStatus = $("#tpStatus");
    const loadTriggerPolicy = async () => {
      if (!tpPanicLocal || !tpPanicLink || !tpSilentLink || !tpLoudLink || !tpExcludeSelf || !tpLoudDur) return;
      try {
        if (tpStatus) tpStatus.textContent = "Loading policy…";
        const r = await api(`/devices/${encodeURIComponent(id)}/trigger-policy`, { timeoutMs: 16000 });
        const p = r.policy || {};
        tpPanicLocal.checked = !!p.panic_local_siren;
        if (tpPanicLink) tpPanicLink.checked = p.panic_link_enabled !== false;
        tpSilentLink.checked = !!p.remote_silent_link_enabled;
        tpLoudLink.checked = !!p.remote_loud_link_enabled;
        tpExcludeSelf.checked = !!p.fanout_exclude_self;
        tpLoudDur.value = String(Number(p.remote_loud_duration_ms || 10000));
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
          const duration = parseInt((tpLoudDur && tpLoudDur.value) || "10000", 10);
          if (!Number.isFinite(duration) || duration < 500 || duration > 300000) {
            throw new Error("Loud duration must be 500-300000 ms");
          }
          if (tpStatus) tpStatus.textContent = "Saving policy…";
          await api(`/devices/${encodeURIComponent(id)}/trigger-policy`, {
            method: "PUT",
            body: {
              panic_local_siren: !!(tpPanicLocal && tpPanicLocal.checked),
              panic_link_enabled: !!(tpPanicLink && tpPanicLink.checked),
              remote_silent_link_enabled: !!(tpSilentLink && tpSilentLink.checked),
              remote_loud_link_enabled: !!(tpLoudLink && tpLoudLink.checked),
              fanout_exclude_self: !!(tpExcludeSelf && tpExcludeSelf.checked),
              remote_loud_duration_ms: duration,
            },
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
      setChildMarkup(shareListEl, `<p class="muted">Loading shares…</p>`);
      try {
        const r = await api(`/admin/devices/${encodeURIComponent(id)}/shares`, { timeoutMs: 16000 });
        const items = r.items || [];
        setChildMarkup(
          shareListEl,
          `
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
        `,
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
            } catch (e) { toast(e.message || e, "err"); }
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
    let list;
    try {
      list = await apiGetCached("/devices", { timeoutMs: 16000 }, 4000);
    } catch (e) {
      devicesLoadErr = String((e && e.message) || e || "load failed");
      list = { items: [] };
    }
    const devices = list.items || [];

    mountView(view, `
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
            <input id="dur" type="number" value="10000" min="500" max="300000" />
          </label>
          <label class="field wide"><span>Targets (empty = all visible)</span>
            <select id="targets" multiple size="6"></select>
          </label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn danger" id="fire" ${enabled ? "" : "disabled"}>Run</button>
          </div>
        </div>
      </div>`);

    const sel = $("#targets");
    setChildMarkup(sel, devices.map((d) => {
      const lab = d.display_label ? `${escapeHtml(d.display_label)}` : escapeHtml(d.device_id);
      const serial = d.display_label ? ` · ${escapeHtml(d.device_id)}` : "";
      const grp = d.notification_group ? `[${escapeHtml(d.notification_group)}] ` : "";
      const z = d.zone ? ` · ${escapeHtml(d.zone)}` : "";
      return `<option value="${escapeHtml(d.device_id)}">${grp}${lab}${serial}${z}</option>`;
    }).join(""));

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
    if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`); return; }
    const canClaim = can("can_claim_device");

    mountView(view, `
      <div class="activate-shell">
        <section class="card activate-hero">
          <p class="activate-kicker">Field · Claim</p>
          <h2 class="activate-title">认领设备</h2>
          <p class="muted activate-lead">
            清单内序列号必须先<strong>通电并联网</strong>才会变为「可认领」。可先在此填写<strong>目标 Wi‑Fi</strong>（保存在本浏览器）；认领成功后会预填设备页的「Wi‑Fi (device)」下发表单（设备在线后即可下发）。
          </p>
          <ol class="activate-steps">
            <li><span class="n">1</span>填写目标 Wi‑Fi（可选，推荐）</li>
            <li><span class="n">2</span>输入贴纸序列号或粘贴完整 <span class="mono">CROC|…</span></li>
            <li><span class="n">3</span>识别 → 可认领则核对资料并完成认领</li>
          </ol>
          ${canClaim ? "" : `<p class="badge revoked" style="margin-top:12px">当前账号无 <span class="mono">can_claim_device</span>，请联系管理员。</p>`}
        </section>

        <section class="card activate-main">
          <div class="activate-wifi-row">
            <button type="button" class="btn secondary btn-tap" style="width:100%" id="activateWifiOpenBtn">① 填写目标 Wi‑Fi（SSID / 密码）</button>
            <p class="muted activate-wifi-status" id="activateWifiStatus"></p>
          </div>
          <div class="inline-form activate-serial-block">
            <label class="field wide"><span>② 序列号或整段 QR（CROC|…）</span>
              <input id="idn_input" class="activate-serial-input" placeholder="SN-… 或粘贴整行 CROC|…" autocomplete="off"/>
            </label>
            <div class="row wide activate-actions">
              <button class="btn btn-tap activate-id-btn" id="idn_go" ${canClaim ? "" : "disabled"}>③ 识别</button>
            </div>
          </div>
          <div id="idnResult" class="activate-result"></div>
        </section>

        <dialog id="activateWifiDialog" class="activate-wifi-dlg">
          <div class="activate-wifi-dlg__inner">
            <h3 class="activate-wifi-dlg__title">目标 Wi‑Fi</h3>
            <p class="muted activate-wifi-dlg__lead">
              设备<strong>从未联网</strong>时，服务器无法直接把 Wi‑Fi 发到板子；此处仅把 SSID/密码保存在<strong>本浏览器</strong>，认领后在设备页填入并下发（MQTT）。开放网络可留空密码。
            </p>
            <label class="field wide"><span>SSID</span>
              <input type="text" id="activateDlgSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz 网络名称" />
            </label>
            <label class="field wide"><span>密码</span>
              <input type="password" id="activateDlgPass" maxlength="64" autocomplete="new-password" placeholder="开放网络可留空" />
            </label>
            <label class="field" style="margin-bottom:0"><span></span>
              <span><input type="checkbox" id="activateDlgShowPass" /> 显示密码</span>
            </label>
            <div class="activate-wifi-dlg__actions">
              <button type="button" class="btn secondary" id="activateWifiDlgClear">清除草稿</button>
              <button type="button" class="btn ghost" id="activateWifiDlgClose">关闭</button>
              <button type="button" class="btn" id="activateWifiDlgSave">保存到本浏览器</button>
            </div>
          </div>
        </dialog>

        <section class="card activate-pending-card">
          <div class="row between" style="flex-wrap:wrap;gap:8px;align-items:center">
            <h3 style="margin:0">最近上报（待认领）</h3>
            <span class="muted" style="font-size:13px">MQTT <span class="mono">bootstrap.register</span></span>
            <button class="btn secondary btn-tap" id="reload">刷新</button>
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
      } catch (_) {}
      return null;
    };
    const refreshWifiBanner = () => {
      const el = $("#activateWifiStatus", view);
      const d = readWifiDraft();
      if (!el) return;
      el.textContent = d
        ? `已保存目标 Wi‑Fi：「${d.ssid}」。认领成功后会打开设备页并预填「Wi‑Fi (device)」表单（需设备在线才能下发）。`
        : "可先填写将要使用的 Wi‑Fi（仅保存在此浏览器）；也可跳过，稍后在设备页填写。";
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
        if (!ssid) { toast("请输入 Wi‑Fi 名称 (SSID)", "err"); return; }
        sessionStorage.setItem(ACTIVATE_WIFI_STORE, JSON.stringify({ ssid, password }));
        refreshWifiBanner();
        closeActivateWifiDialog();
        toast("已保存（仅本浏览器）", "ok");
      });
    }
    const wifiClrDlg = $("#activateWifiDlgClear", view);
    if (wifiClrDlg) {
      wifiClrDlg.addEventListener("click", () => {
        sessionStorage.removeItem(ACTIVATE_WIFI_STORE);
        refreshWifiBanner();
        closeActivateWifiDialog();
        toast("已清除 Wi‑Fi 草稿", "ok");
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
    const drawBadge = (kind, label) =>
      `<span class="badge ${kind === "ok" ? "online" : (kind === "err" ? "offline" : "")}">${escapeHtml(label)}</span>`;

    const showClaimForm = (serial, mac, qr) => {
      const draft = readWifiDraft();
      const draftNote = draft
        ? `<p class="muted" style="margin:0 0 12px">已保存目标 Wi‑Fi <span class="mono">${escapeHtml(draft.ssid)}</span> — 认领后将跳转设备页并预填「Wi‑Fi (device)」。</p>`
        : "";
      appendChildMarkup(
        resultBox,
        `
        <div class="card" style="margin-top:10px">
          <h4 style="margin-top:0">确认认领</h4>
          ${draftNote}
          <div class="inline-form">
            <label class="field"><span>device_id（一般为序列号）</span><input id="c_id" value="${escapeHtml(serial)}"/></label>
            <label class="field"><span>mac_nocolon</span><input id="c_mac" value="${escapeHtml(mac)}"/></label>
            <label class="field"><span>zone</span><input id="c_zone" value="all"/></label>
            <label class="field wide"><span>qr_code（可选）</span><input id="c_qr" value="${escapeHtml(qr || "")}"/></label>
            <div class="row wide" style="justify-content:flex-end">
              <button class="btn btn-tap" id="c_submit">确认认领</button>
            </div>
          </div>
        </div>`,
      );
      $("#c_submit").addEventListener("click", async () => {
        const body = {
          mac_nocolon: ($("#c_mac").value || "").trim().toUpperCase(),
          device_id: ($("#c_id").value || "").trim().toUpperCase(),
          zone: ($("#c_zone").value || "all").trim(),
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
              JSON.stringify({ device_id: did, ssid: preWifi.ssid, password: preWifi.password || "" }),
            );
          }
          sessionStorage.removeItem(ACTIVATE_WIFI_STORE);
          refreshWifiBanner();
          toast("认领成功", "ok");
          location.hash = `#/devices/${encodeURIComponent(did)}`;
        } catch (e) { toast(e.message || e, "err"); }
      });
    };

    $("#idn_go").addEventListener("click", async () => {
      setChildMarkup(resultBox, `<p class="muted">Identifying…</p>`);
      const raw = ($("#idn_input").value || "").trim();
      if (!raw) { setChildMarkup(resultBox, `<p class="muted">Enter serial or QR payload</p>`); return; }
      const body = raw.startsWith("CROC|") ? { qr_code: raw } : { serial: raw.toUpperCase() };
      try {
        const r = await api("/provision/identify", { method: "POST", body });
        const kv = (k, v) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(v)}</dd>`;
        switch (r.status) {
          case "ready":
            setChildMarkup(
              resultBox,
              `${drawBadge("ok", "Ready to claim")}
              <dl class="kv">${kv("Serial", r.serial)}${kv("MAC", r.mac_nocolon)}${kv("Firmware", r.fw || "—")}${kv("Last seen", r.last_seen_at || "—")}</dl>
              <p>${escapeHtml(r.message)}</p>`,
            );
            showClaimForm(r.serial, r.mac_nocolon, raw.startsWith("CROC|") ? raw : "");
            break;
          case "already_registered":
            const canSeeOwner = !!(state.me && state.me.role === "superadmin");
            const ownerKv = canSeeOwner ? kv("Owner admin", r.owner_admin || "—") : "";
            const byYou = !!r.by_you;
            setChildMarkup(
              resultBox,
              `${drawBadge("err", byYou ? "Already yours" : "Already registered")}
              <dl class="kv">${kv("Serial", r.serial)}${kv("device_id", r.device_id)}${ownerKv}${kv("Claimed at", r.claimed_at)}</dl>
              <p class="muted">${escapeHtml(r.message)}</p>
              ${byYou ? `<a class="btn secondary" href="#/devices/${encodeURIComponent(r.device_id)}">Open device</a>` : ""}`,
            );
            break;
          case "offline": {
            const dw = readWifiDraft();
            const draftNote = dw
              ? `<p class="muted" style="margin-top:10px">已在本机保存 Wi‑Fi：<strong>${escapeHtml(dw.ssid)}</strong>。设备上线并完成认领后，可在设备页下发该网络。</p>`
              : "";
            setChildMarkup(
              resultBox,
              `${drawBadge("", "Waiting for device")}
              <dl class="kv">${kv("Serial", r.serial)}${r.mac_hint ? kv("Factory MAC", r.mac_hint) : ""}</dl>
              <p>${escapeHtml(r.message)}</p>
              ${draftNote}
              <div class="activate-offline-actions">
                <button type="button" class="btn secondary btn-tap" id="activateOfflineWifiBtn">填写 / 更改目标 Wi‑Fi</button>
                <button type="button" class="btn btn-tap" id="idn_retry_offline">已通电联网 · 重新识别</button>
              </div>`,
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
      } catch (e) { setChildMarkup(resultBox, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`); }
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
    } catch (_) {}

    let pendingErr = "";
    const data = await apiOr("/provision/pending", (e) => {
      pendingErr = String((e && e.message) || e || "load failed");
      return { items: [] };
    }, { timeoutMs: 16000 });
    const items = data.items || [];
    const pendListEl = view.querySelector("#pendList");
    if (!pendListEl) return;
    setChildMarkup(
      pendListEl,
      `
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
      </table></div>`,
    );
  });

  // Event Center — global live + historical log stream
  // NOTE: Active stream lives on window.__evSSE (fetch shim); renderRoute closes it on navigation.
  // navTok: capture state.routeSeq up front so nested async (loadHistory, openStream) always see a
  // defined token even if a minifier / bad edit drops the 3rd handler param (avoids "routeSeq is not defined").
  registerRoute("events", async (view, _args) => {
    const navTok = state.routeSeq;
    setCrumb("Events");
    const me = state.me || { username: "", role: "" };
    const isSuper = me.role === "superadmin";
    const scopeLabel = isSuper ? "System-wide" : (me.role === "admin" ? "Your tenant" : "Your account");

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
      <div class="ui-shell card audit-page" style="margin-top:12px">
        <div id="evList" class="audit-feed-wrap muted">Connecting…</div>
      </div>`);

    let paused = false;
    let buffer = [];  // newest first
    const BUFFER_MAX = 180;
    const RENDER_LIMIT = 150;
    let evRenderTimer = 0;
    let evReconnectBackoffMs = 800;

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
      const primary = (e.summary && String(e.summary).trim()) || (e.event_type || "—");
      const tsShort = (e.ts || "").replace("T", " ").replace(/\..*/, "");
      const typeDiffers = e.event_type && String(e.event_type) !== String(primary);
      const extras = eventDetailDedupedRows(
        (e.detail && typeof e.detail === "object" && !Array.isArray(e.detail)) ? e.detail : {},
        e,
      );
      const devLink = e.device_id
        ? `<a class="mono audit-target" href="#/devices/${encodeURIComponent(e.device_id)}">${escapeHtml(e.device_id)}</a>`
        : "";
      const targetStr = (e.target && e.target !== e.device_id) ? String(e.target) : "";
      const typeTag = typeDiffers
        ? ` · <span class="mono" style="font-size:12px;opacity:0.88">${escapeHtml(e.event_type)}</span>`
        : "";
      const extraBlock = extras.length
        ? `<div class="audit-extra">${extras.map((row) =>
            `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`,
        ).join("")}</div>`
        : "";
      return `<article class="audit-item" data-level="${escapeHtml(e.level || "")}">
        <div class="audit-item-top">
          <div class="audit-time">
            <span class="audit-ts mono">${escapeHtml(tsShort)}</span>
            <span class="muted audit-rel">${escapeHtml(fmtRel(e.ts))}</span>
          </div>
          <span class="badge ${badgeClass(e.level)}">${escapeHtml(e.level || "")}</span>
          <span class="badge ${catClass(e.category)}">${escapeHtml(e.category || "")}</span>
        </div>
        <div class="audit-item-line" style="font-weight:600">${escapeHtml(primary)}${typeTag}</div>
        <div class="audit-item-line" style="font-size:12.5px;flex-wrap:wrap">
          <span class="audit-actor">${e.actor ? escapeHtml(e.actor) : "—"}</span>
          ${targetStr ? ` <span class="audit-arrow">→</span> <span class="mono audit-target">${escapeHtml(targetStr)}</span>` : ""}
          ${devLink ? ` · ${devLink}` : ""}
          ${e.owner_admin ? ` <span class="chip" title="owner_admin">@${escapeHtml(e.owner_admin)}</span>` : ""}
        </div>
        ${extraBlock}
      </article>`;
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
          if (sj.length > 12000) {
            row = Object.assign({}, ev, {
              detail: { _truncated: true, _approx_bytes: sj.length },
            });
          }
        }
      } catch (_) {}
      buffer.unshift(row);
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
        if (!isRouteCurrent(navTok)) return;
        const p = currentFilters(); p.set("limit", "200");
        const r = await api("/events?" + p.toString(), { timeoutMs: 16000 });
        if (!isRouteCurrent(navTok)) return;
        buffer = (r.items || []).slice();
        if (evRenderTimer) { clearTimeout(evRenderTimer); evRenderTimer = 0; }
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
        try { clearTimeout(window.__evReconnectTimer); } catch (_) {}
        window.__evReconnectTimer = 0;
      }
      if (window.__evSSE) {
        try { window.__evSSE.close(); } catch (_) {}
        window.__evSSE = null;
      }
      if (window.__evFetchAbort) {
        try { window.__evFetchAbort.abort(); } catch (_) {}
        window.__evFetchAbort = null;
      }
      const live = $("#evLive");
      if (live) { live.textContent = "Offline"; live.className = "badge offline"; }
    }
    /**
     * Live events: use fetch() + ReadableStream instead of EventSource so we can send
     * Authorization (JWT never appears in URL query — fewer proxy/logging issues).
     * Server still emits ping keepalives for buffered proxies.
     */
    function openStream() {
      if (!isRouteCurrent(navTok)) return;
      closeStream();
      const p = currentFilters();
      p.set("backlog", String(Math.min(100, BUFFER_MAX - buffer.length)));
      const qs = p.toString();
      const tok = getToken();
      const ac = new AbortController();
      window.__evFetchAbort = ac;
      const shim = {
        readyState: EventSource.CONNECTING,
        close() {
          try { ac.abort(); } catch (_) {}
          window.__evFetchAbort = null;
          this.readyState = EventSource.CLOSED;
        },
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
        evReconnectBackoffMs = Math.min(8000, Math.floor(evReconnectBackoffMs * 1.5));
      };

      const run = async () => {
        if (!tok) {
          shim.readyState = EventSource.CLOSED;
          const live = $("#evLive");
          if (live && isRouteCurrent(navTok)) {
            live.textContent = "Offline";
            live.className = "badge offline";
          }
          return;
        }
        const url = apiBase() + "/events/stream" + (qs ? "?" + qs : "");
        try {
          const r = await fetch(url, {
            method: "GET",
            headers: {
              Authorization: "Bearer " + tok,
              Accept: "text/event-stream",
              "Cache-Control": "no-store",
            },
            signal: ac.signal,
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
            } catch (_) {}
          });
          if (ac.signal.aborted || !isRouteCurrent(navTok)) return;
          shim.readyState = EventSource.CLOSED;
          if (!paused && isRouteCurrent(navTok)) {
            evReconnectBackoffMs = 800;
            const live = $("#evLive");
            if (live) {
              live.textContent = "Reconnecting…";
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
            live.textContent = "Reconnecting…";
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
      if (evRenderTimer) { clearTimeout(evRenderTimer); evRenderTimer = 0; }
      flushEvRender();
    });
    $("#evApply").addEventListener("click", () => { loadHistory().then(openStream); });
    $("#evReload").addEventListener("click", loadHistory);
    $("#evStats").addEventListener("click", async () => {
      try {
        if (!isRouteCurrent(navTok)) return;
        const r = await api("/events/stats/by-device?hours=168&limit=200", { timeoutMs: 16000 });
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
          `<div class="table-wrap"><table class="t"><thead><tr><th>Device</th><th>Count</th></tr></thead><tbody>${
            items.map((x) => `<tr><td class="mono">${escapeHtml(x.device_id)}</td><td>${x.count}</td></tr>`).join("")
          }</tbody></table></div>`,
        );
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
      if (!isRouteCurrent(navTok)) return;
      openStream();
    };
  });

  // Telegram self-service (user/admin/superadmin)
  registerRoute("telegram", async (view) => {
    setCrumb("Telegram");
    if (!hasRole("user")) { mountView(view, `<div class="card"><p class="muted">Sign in required.</p></div>`); return; }
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
      setChildMarkup(mineEl, `<p class="muted">Loading…</p>`);
      try {
        const d = await api("/admin/telegram/bindings", { timeoutMs: 16000 });
        const items = d.items || [];
        setChildMarkup(
          mineEl,
          items.length === 0
            ? `<p class="muted">No bindings yet.</p>`
            : `<div class="table-wrap"><table class="t">
              <thead><tr><th>chat_id</th><th>enabled</th><th>updated</th><th></th><th></th></tr></thead>
              <tbody>${items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.chat_id || "")}</td>
                  <td>${it.enabled ? `<span class="badge online">on</span>` : `<span class="badge offline">off</span>`}</td>
                  <td>${escapeHtml(fmtTs(it.updated_at || it.created_at))}</td>
                  <td><button class="btn sm secondary js-tg-toggle" data-chat="${escapeHtml(String(it.chat_id || ""))}" data-en="${it.enabled ? "1" : "0"}">${it.enabled ? "Disable" : "Enable"}</button></td>
                  <td><button class="btn sm danger js-tg-unbind" data-chat="${escapeHtml(String(it.chat_id || ""))}">Unbind</button></td>
                </tr>`).join("")}</tbody>
            </table></div>`,
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
          deep
            ? `<div class="ui-status-strip">
               <div class="ui-status-item"><div class="k">Step 1</div><div class="v"><a class="btn" href="${escapeHtml(openChat || deep)}" target="_blank" rel="noopener">Open bot chat</a></div></div>
               <div class="ui-status-item"><div class="k">Step 2</div><div class="v"><a class="btn secondary" href="${escapeHtml(deep)}" target="_blank" rel="noopener">Run one-click bind</a></div></div>
             </div>
             <p class="muted mono" style="margin-top:8px">${escapeHtml(deep)}</p>`
            : `<p class="muted">Set <span class="mono">TELEGRAM_BOT_USERNAME</span> on server, then retry.<br/>Fallback: send <span class="mono">/start ${escapeHtml(payload)}</span> in your bot chat.</p>`,
        );
      } catch (e) {
        setChildMarkup(linkEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    });
    $("#tgManualBind", view).addEventListener("click", async () => {
      const chatId = ($("#tgManualChatId", view).value || "").trim();
      const enabled = !!$("#tgManualEnabled", view).checked;
      if (!chatId) { toast("Enter chat_id", "err"); return; }
      try {
        await api("/admin/telegram/bind-self", { method: "POST", body: { chat_id: chatId, enabled } });
        toast("Bound", "ok");
        loadMine();
      } catch (e) { toast(e.message || e, "err"); }
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
        } catch (e) { toast(e.message || e, "err"); }
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
        } catch (e) { toast(e.message || e, "err"); }
      }
    });
    loadMine();
  });

  // Audit
  registerRoute("audit", async (view, _args, routeSeq) => {
    setCrumb("Audit");
    if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`); return; }
    mountView(view, `
      <div class="ui-shell card audit-page">
        <div class="ui-section-head">
          <div>
            <h2 class="ui-section-title">Audit</h2>
            <p class="ui-section-sub">Who did what, when — extra fields only when they add information beyond actor / target.</p>
          </div>
          <div class="ui-section-actions audit-filters">
            <label class="field compact"><span>Actor</span><input id="f_actor" type="search" autocomplete="off" placeholder="username" /></label>
            <label class="field compact"><span>Action</span><input id="f_action" type="search" autocomplete="off" placeholder="prefix e.g. provision" /></label>
            <label class="field compact"><span>Target</span><input id="f_target" type="search" autocomplete="off" placeholder="device or user" /></label>
            <button class="btn secondary btn-tap" id="f_reload" type="button">Apply</button>
          </div>
        </div>
        <div class="ui-status-strip" id="auditStrip">
          <span class="ui-status-item"><strong id="auditCount">—</strong> entries</span>
          <span class="ui-status-item muted">Newest first · max 200</span>
        </div>
        <div class="divider"></div>
        <div id="auditList" class="audit-feed-wrap"></div>
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
        d = await api("/audit?" + qs.toString(), { timeoutMs: 24000 });
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
        const extrasHtml = extras.length
          ? `<div class="audit-extra">${extras.map((row) =>
              `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`,
            ).join("")}</div>`
          : "";
        const tgtHtml = tgt
          ? `<span class="audit-target mono" title="target">${escapeHtml(tgt)}</span>`
          : `<span class="muted">—</span>`;
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
              <span class="audit-arrow" aria-hidden="true">→</span>
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
    scheduleRouteTicker(routeSeq, "audit-live-reload", reload, 12000);
  });

  // Admin
  registerRoute("admin", async (view) => {
    setCrumb("Admin");
    if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`); return; }
    const isSuper = state.me.role === "superadmin";
    let admins = [];
    if (isSuper) {
      try { admins = (await api("/auth/admins", { timeoutMs: 16000 })).items || []; } catch { admins = []; }
    }

    mountView(view, `
      <div class="card">
        <h2>Users</h2>
        <p class="muted">${isSuper
          ? "Superadmin: create admin/user, assign manager_admin and policies."
          : "Admin: manage users under you and toggle their capabilities."}</p>
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
      </div>` : ""}`);

    const $v = (sel) => $(sel, view);

    // users
    const loadUsers = async () => {
      try {
        const d = await api("/auth/users", { timeoutMs: 16000 });
        const users = d.items || [];
        const userTableEl = $v("#userTable");
        if (!userTableEl) return;
        setChildMarkup(
          userTableEl,
          users.length === 0
            ? `<p class="muted">No users.</p>`
            : `<div class="table-wrap"><table class="t">
              <thead><tr><th>User</th><th>Role</th><th>manager</th><th>tenant</th><th>Created</th><th></th></tr></thead>
              <tbody>${users.map((u) => {
                const isUser = u.role === "user";
                const isAdminRow = u.role === "admin";
                const self = u.username === (state.me && state.me.username);
                const closeTenantBtn = isSuper && isAdminRow && !self
                  ? `<button type="button" class="btn sm danger js-close-admin" data-u="${escapeHtml(u.username)}">Close tenant</button>`
                  : "";
                return `<tr>
                  <td><strong>${escapeHtml(u.username)}</strong></td>
                  <td><span class="chip">${escapeHtml(u.role)}</span></td>
                  <td class="mono">${escapeHtml(u.manager_admin || "—")}</td>
                  <td class="mono">${escapeHtml(u.tenant || "—")}</td>
                  <td>${escapeHtml(fmtTs(u.created_at))}</td>
                  <td>
                    ${isUser ? `<button type="button" class="btn sm secondary js-pol" data-u="${escapeHtml(u.username)}">Policy</button>` : ""}
                    ${closeTenantBtn}
                    ${self ? "" : (isAdminRow ? "" : `<button type="button" class="btn sm danger js-del" data-u="${escapeHtml(u.username)}">Delete</button>`)}
                  </td>
                </tr><tr class="sub" style="display:none" data-pol-row="${escapeHtml(u.username)}"><td colspan="6"></td></tr>`;
              }).join("")}</tbody></table></div>`,
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
      setChildMarkup(listEl, `<p class="muted">Loading shares…</p>`);
      try {
        const d = await api("/admin/shares?" + qs.toString(), { timeoutMs: 16000 });
        const items = d.items || [];
        setChildMarkup(
          listEl,
          items.length === 0
            ? `<p class="muted">No matching shares.</p>`
            : `<div class="table-wrap"><table class="t">
              <thead><tr><th>Device</th><th>Owner</th><th>Grantee</th><th>Role</th><th>View</th><th>Operate</th><th>Granted by</th><th>Status</th><th></th></tr></thead>
              <tbody>${items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.device_id || "")}</td>
                  <td class="mono">${escapeHtml(it.owner_admin || "—")}</td>
                  <td class="mono">${escapeHtml(it.grantee_username || "")}</td>
                  <td>${escapeHtml(it.grantee_role || "—")}</td>
                  <td>${it.can_view ? "yes" : "no"}</td>
                  <td>${it.can_operate ? "yes" : "no"}</td>
                  <td class="mono">${escapeHtml(it.granted_by || "")}</td>
                  <td>${it.revoked_at ? `<span class="badge offline">revoked</span>` : `<span class="badge online">active</span>`}</td>
                  <td>${it.revoked_at ? "" : `<button class="btn sm danger js-gs-revoke" data-device="${escapeHtml(it.device_id || "")}" data-user="${escapeHtml(it.grantee_username || "")}">Revoke</button>`}</td>
                </tr>`).join("")}</tbody></table></div>`,
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

    if (isSuper) {
      $v("#gs_query").addEventListener("click", loadGlobalShares);
      $v("#gs_grant").addEventListener("click", async () => {
        const device = ($v("#gs_device").value || "").trim();
        const user = ($v("#gs_user").value || "").trim();
        const canView = !!$v("#gs_view").checked;
        const canOperate = !!$v("#gs_operate").checked;
        if (!device || !user) { toast("Device ID and grantee required", "err"); return; }
        if (!canView && !canOperate) { toast("Select view and/or operate", "err"); return; }
        try {
          await api(`/admin/devices/${encodeURIComponent(device)}/share`, {
            method: "POST",
            body: { grantee_username: user, can_view: canView, can_operate: canOperate },
          });
          toast("Share updated", "ok");
          loadGlobalShares();
        } catch (e) { toast(e.message || e, "err"); }
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
        } catch (e) { toast(e.message || e, "err"); }
      });
      loadGlobalShares();
    }

    const openPolicy = async (username, trRow) => {
      const cell = trRow.querySelector("td");
      setChildMarkup(cell, `<span class="muted">Loading…</span>`);
      trRow.style.display = "";
      try {
          const p = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { timeoutMs: 16000 });
        setChildMarkup(cell, renderPolicyPanel(username, p));
        cell.querySelector(".js-save").addEventListener("click", async () => {
          const body = {};
          cell.querySelectorAll("input[type=checkbox][data-k]").forEach((i) => body[i.dataset.k] = !!i.checked);
          try {
            const r = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { method: "PUT", body });
            toast(`Policy updated for ${username}`, "ok");
            setChildMarkup(cell, renderPolicyPanel(username, r.policy || r));
            cell.querySelector(".js-save").addEventListener("click", () => openPolicy(username, trRow));
          } catch (e) { toast(e.message || e, "err"); }
        });
      } catch (e) { setChildMarkup(cell, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`); }
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
      if (t.classList.contains("js-close-admin")) {
        if (!isSuper) return;
        if (!u) return;
        if (!confirm(
          `Close admin tenant "${u}"?\n\n` +
            "· Devices: factory-unclaim all, OR transfer to another admin in the next prompt.\n" +
            "· All subordinate users under this admin will be deleted.\n" +
            "· That username and email are released for new signups."
        )) return;
        const transfer = window.prompt(
          "Optional: target admin username to receive ALL this admin’s devices (leave empty to unclaim every device):"
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
            body: { confirm_text: "CLOSE TENANT", transfer_devices_to: transferTo },
          });
          toast(
            `Tenant closed — unclaimed ${Number(r.devices_unclaimed || 0)}, transferred ${Number(r.devices_transferred || 0)}, removed ${Number(r.subordinate_users_deleted || 0)} user(s).`,
            "ok",
          );
          loadUsers();
        } catch (e) { toast(e.message || e, "err"); }
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
        const s = await api("/admin/smtp/status", { timeoutMs: 16000 });
        const smtpEl = $v("#smtpStatus");
        if (!smtpEl) return;
        const okBadge = s.enabled
          ? `<span class="badge online">Mail on</span>`
          : `<span class="badge offline">Mail off</span>`;
        const last = s.last_error ? `<span class="chip" title="last error">${escapeHtml(s.last_error)}</span>` : "";
        setChildMarkup(
          smtpEl,
          `${okBadge}
          <span class="chip">host: ${escapeHtml(s.host || "—")}:${escapeHtml(String(s.port || "—"))}</span>
          <span class="chip">mode: ${escapeHtml(s.mode || "—")}</span>
          <span class="chip">from: ${escapeHtml(s.sender || "—")}</span>
          <span class="chip">sent: ${s.sent_count || 0}</span>
          <span class="chip">failed: ${s.failed_count || 0}</span>
          <span class="chip">queue: ${s.queue_size ?? 0}/${s.queue_max ?? ""}</span>${last}`,
        );
      } catch (e) {
        const smtpEl = $v("#smtpStatus");
        if (!smtpEl) return;
        setChildMarkup(smtpEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
      }
    };
    const loadRecipients = async () => {
      try {
        const d = await api("/admin/alert-recipients", { timeoutMs: 16000 });
        const items = d.items || [];
        const listEl = $v("#recipientList");
        if (!listEl) return;
        setChildMarkup(
          listEl,
          items.length === 0
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
                </tr>`).join("")}</tbody></table></div>`,
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
        toast("Mail test sent", "ok");
        loadSmtpStatus();
      } catch (e) { toast(e.message || e, "err"); }
    });
    const loadTgStatus = async () => {
      try {
        const t = await api("/admin/telegram/status", { timeoutMs: 16000 });
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
        setChildMarkup(
          tgEl,
          `${badge}
          ${th}
          <span class="chip">worker: ${wk}</span>
          <span class="chip">chats: ${t.chats ?? 0}</span>
          <span class="chip">min_level: ${escapeHtml(t.min_level || "")}</span>
          <span class="chip">queue: ${t.queue_size ?? 0}</span>${modErr}${le}`,
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
      setChildMarkup(el, `<p class="muted">Loading bindings…</p>`);
      try {
        const d = await api("/admin/telegram/bindings", { timeoutMs: 16000 });
        const items = d.items || [];
        setChildMarkup(
          el,
          items.length === 0
            ? `<p class="muted">No bindings yet.</p>`
            : `<div class="table-wrap"><table class="t">
              <thead><tr><th>chat_id</th><th>username</th><th>enabled</th><th>updated</th><th></th></tr></thead>
              <tbody>${items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.chat_id || "")}</td>
                  <td>${escapeHtml(it.username || "")}</td>
                  <td>${it.enabled ? `<span class="badge online">on</span>` : `<span class="badge offline">off</span>`}</td>
                  <td>${escapeHtml(fmtTs(it.updated_at || it.created_at))}</td>
                  <td><button class="btn sm danger js-tg-unbind" data-chat="${escapeHtml(String(it.chat_id || ""))}">Unbind</button></td>
                </tr>`).join("")}</tbody></table></div>`,
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
      } catch (e) { toast(e.message || e, "err"); }
    });
    $v("#tgBindSelf").addEventListener("click", async () => {
      const chat_id = ($v("#tgBindChatId").value || "").trim();
      const enabled = !!$v("#tgBindEnabled").checked;
      if (!chat_id) { toast("Enter chat_id", "err"); return; }
      try {
        await api("/admin/telegram/bind-self", { method: "POST", body: { chat_id, enabled } });
        toast("Chat bound", "ok");
        loadTgBindings();
      } catch (e) { toast(e.message || e, "err"); }
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
    loadTgBindings();

    // Pending admin signups (superadmin approval queue)
    const loadPendAdmins = async () => {
      if (!isSuper) return;
      try {
        const d = await api("/auth/signup/pending", { timeoutMs: 16000 });
        const items = d.items || [];
        const pendEl = $v("#pendAdmins");
        if (!pendEl) return;
        setChildMarkup(
          pendEl,
          items.length === 0
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
              </tr>`).join("")}</tbody></table></div>`,
        );
      } catch (e) {
        const pendEl = $v("#pendAdmins");
        if (!pendEl) return;
        setChildMarkup(pendEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
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
        <div id="sigList"></div>
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
            const tShort = (a.ts || "").replace("T", " ").replace(/\..*/, "");
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

  registerRoute("ota", async (view, _args, routeSeq) => {
    setCrumb("OTA");
    const me = state.me || { username: "", role: "" };
    if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">OTA is available to admin and above.</p></div>`); return; }
    const isSuper = me.role === "superadmin";

    mountView(view, `
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
      <div id="campDetail"></div>`);

    async function loadCampaigns() {
      try {
        if (!isRouteCurrent(routeSeq)) return;
        const r = await api("/ota/campaigns", { timeoutMs: 30000 });
        if (!isRouteCurrent(routeSeq)) return;
        const list = r.items || [];
        const campListEl = $("#campList", view);
        if (!campListEl) return;
        if (list.length === 0) {
          setChildMarkup(campListEl, `<p class="muted">No OTA campaigns.</p>`);
          return;
        }
        setChildMarkup(
          campListEl,
          `<div class="table-wrap"><table class="t">
          <thead><tr><th>ID</th><th>Version</th><th>URL</th><th>State</th><th>Progress</th><th>My decision</th><th>Created</th><th></th></tr></thead>
          <tbody>${list.map((c) => renderOtaCampaignRow(c, me)).join("")}</tbody>
        </table></div>`,
        );

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
            if (!isRouteCurrent(routeSeq)) return;
            const campDetailEl = $("#campDetail", view);
            if (!campDetailEl) return;
            setChildMarkup(
              campDetailEl,
              `<div class="card">
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
            </div>`,
            );
          } catch (e) {
            if (!isRouteCurrent(routeSeq)) return;
            toast(e.message || e, "err");
          }
        }));
      } catch (e) {
        if (!isRouteCurrent(routeSeq)) return;
        const campListEl = $("#campList", view);
        if (!campListEl) return;
        setChildMarkup(campListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }
    }

    if (isSuper) {
      try {
        const fw = await api("/ota/firmwares", { timeoutMs: 30000 });
        if (!isRouteCurrent(routeSeq)) return;
        const fwListEl = $("#fwList", view);
        if (!fwListEl) return;
        setChildMarkup(
          fwListEl,
          (fw.items || []).length === 0
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
                </tr>`).join("")}</tbody></table></div>`,
        );
        view.querySelectorAll(".js-use").forEach((b) => {
          b.addEventListener("click", () => {
            const cUrl = $("#c_url", view);
            const cFw = $("#c_fw", view);
            const cSha = $("#c_sha", view);
            if (cUrl) cUrl.value = b.dataset.url;
            if (cFw) cFw.value = b.dataset.fw;
            if (cSha && b.dataset.sha) cSha.value = b.dataset.sha;
          });
        });
      } catch (e) {
        if (!isRouteCurrent(routeSeq)) return;
        const fwListEl = $("#fwList", view);
        if (fwListEl) setChildMarkup(fwListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
      }

      const cSend = $("#c_send", view);
      if (cSend) cSend.addEventListener("click", async () => {
        const url = (($("#c_url", view) && $("#c_url", view).value) || "").trim();
        const fw = (($("#c_fw", view) && $("#c_fw", view).value) || "").trim();
        const sha = (($("#c_sha", view) && $("#c_sha", view).value) || "").trim();
        const notes = (($("#c_notes", view) && $("#c_notes", view).value) || "").trim();
        const adminsRaw = (($("#c_admins", view) && $("#c_admins", view).value) || "").trim();
        const target_admins = adminsRaw ? adminsRaw.split(/[ ,;\n]+/).filter(Boolean) : ["*"];
        if (!url || !fw) { toast("Firmware version and URL required", "err"); return; }
        if (!confirm(`Create OTA campaign? Target admins: ${target_admins.join(", ") || "ALL"}`)) return;
        try {
          const r = await api("/ota/campaigns", { method: "POST", body: { fw_version: fw, url, sha256: sha || undefined, notes, target_admins } });
          if (!isRouteCurrent(routeSeq)) return;
          toast(`Campaign ${r.campaign_id} · ${r.target_admins.length} admin(s)`, "ok");
          const cUrl = $("#c_url", view);
          const cFw = $("#c_fw", view);
          const cSha = $("#c_sha", view);
          const cNotes = $("#c_notes", view);
          const cAdmins = $("#c_admins", view);
          if (cUrl) cUrl.value = "";
          if (cFw) cFw.value = "";
          if (cSha) cSha.value = "";
          if (cNotes) cNotes.value = "";
          if (cAdmins) cAdmins.value = "";
          loadCampaigns();
        } catch (e) { toast(e.message || e, "err"); }
      });
    }

    const campReload = $("#camp_reload", view);
    if (campReload) campReload.addEventListener("click", loadCampaigns);
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

    await (getToken() ? loadMe() : Promise.resolve());
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
