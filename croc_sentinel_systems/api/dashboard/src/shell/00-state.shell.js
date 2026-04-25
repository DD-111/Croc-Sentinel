/**
 * SPA shared state + group-meta storage + lifecycle timers.
 *
 * Concatenated as raw text by scripts/build-dashboard.mjs (NOT an ESM
 * module). Lives in the same IIFE scope as the monolith body and the
 * route files, which is why every other module can still reference
 * `state`, `_groupMetaSyncChain`, `healthPollTimer`, etc. without imports.
 *
 * Numeric prefix `00-` forces this to load first inside src/shell/ so the
 * mutable state declarations exist before any function that touches them
 * runs (function declarations in later shell files hoist; let/const here
 * does not).
 */
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
