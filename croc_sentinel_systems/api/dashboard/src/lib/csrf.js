/**
 * CSRF token helpers (double-submit cookie pattern).
 *
 * Backend default: cookie `sentinel_csrf` (NOT HttpOnly) + header
 * `X-CSRF-Token`. Names overridable via <meta>; falls back to defaults that
 * match api/app.py CSRF_COOKIE_NAME / CSRF_HEADER_NAME.
 *
 * Like ./api.js, names starting with `_` are exported under their original
 * monolith name to keep call sites in console.raw.js + routes/*.route.js
 * unchanged after the lib/ split.
 */
import { apiBase, fetchWithDeadline } from "./api.js";

export const CSRF_COOKIE_NAME = (function () {
  const m = document.querySelector('meta[name="croc-csrf-cookie"]');
  return (m && m.getAttribute("content") || "sentinel_csrf").trim() || "sentinel_csrf";
})();

export const CSRF_HEADER_NAME = (function () {
  const m = document.querySelector('meta[name="croc-csrf-header"]');
  return (m && m.getAttribute("content") || "X-CSRF-Token").trim() || "X-CSRF-Token";
})();

let _csrfTokenMemory = "";

export function _readCsrfCookie() {
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

export function getCsrfToken() {
  if (_csrfTokenMemory) return _csrfTokenMemory;
  const c = _readCsrfCookie();
  if (c) _csrfTokenMemory = c;
  return _csrfTokenMemory;
}

export function setCsrfToken(t) { _csrfTokenMemory = String(t || ""); }

/** Best-effort refresh: GET /auth/csrf rotates cookie and returns the value. */
export async function refreshCsrfToken() {
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

/** True only when the response failed CSRF (403 + body code). */
export function _isCsrfRejection(status, bodyText) {
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
