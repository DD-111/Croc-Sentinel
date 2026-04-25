/**
 * Authenticated API layer (api / apiOr / apiGetCached + caching), CSRF-aware
 * write retry, group apply/delete fallbacks, share matrix, FW upgrade hint
 * dialog, and the auth lifecycle calls (login / loadMe / loadHealth).
 *
 * Concatenated as raw text by scripts/build-dashboard.mjs after
 * 00-state.shell.js so it can mutate state.me / state.health and call into
 * the timer helpers declared there. The pure HTTP helpers it depends on
 * (apiBase, fetchWithDeadline, _isWriteMethod, ...) come from
 * src/lib/api.js + src/lib/csrf.js via the bundle HEADER imports.
 */
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
