/**
 * Cross-cutting glue helpers used by every other shell/route file.
 *
 * Concatenated as raw text by scripts/build-dashboard.mjs (NOT an ESM module).
 * Lives in the same IIFE scope as the monolith body, the rest of src/shell/,
 * and src/routes/*.route.js.
 *
 *   • getToken / setToken      Legacy localStorage JWT (now mostly unused;
 *                              session is HttpOnly cookie). setToken("")
 *                              also resets the group-meta sync chain so a
 *                              hard logout cannot replay queued writes.
 *   • roleWeight / hasRole     Numeric role comparison; reads state.me.role.
 *   • can(cap)                 Capability check against state.me.policy[cap].
 *   • isOnline(d)              Device online heuristic (boolean field or
 *                              freshness against OFFLINE_MS).
 *   • toast(msg, kind)         Tiny non-blocking toast surfaced at #toast.
 *
 * Numeric prefix `40-` keeps these after state/api/layout/router so they can
 * reference state without forward-declaring it.
 */

function getToken() { return localStorage.getItem(LS.token) || ""; }
function setToken(t) {
  t ? localStorage.setItem(LS.token, t) : localStorage.removeItem(LS.token);
  if (!t) {
    _groupMetaSyncChain = Promise.resolve();
  }
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
