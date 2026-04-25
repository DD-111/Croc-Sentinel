/**
 * REST base URL + retry/timeout helpers. Pure browser-env utilities used by
 * both the monolith body (console.raw.js) and the route files.
 *
 * Names that start with `_` are kept on purpose — every call site in
 * console.raw.js and src/routes/*.route.js used the underscore form before
 * the lib/ split, so re-exporting under the same names is a zero-rename
 * extraction. Treat them as the public surface of this module.
 */

/** Default ceiling so a stuck reverse-proxy / API cannot leave the SPA on "Loading…" forever. */
export const DEFAULT_API_TIMEOUT_MS = 45000;
/** Route-level async guard: full page handlers may await several API calls (slow links / cold DB). */
export const ROUTE_RENDER_TIMEOUT_MS = 90000;

/**
 * REST base URL. Production (Traefik + StripPrefix): index.html meta
 * `croc-api-base` is `/api`.  Direct access on published API ports
 * (no /api prefix): :8088 / :18088 / :18999.
 */
export function apiBase() {
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

/**
 * fetch() with AbortController timeout. opts.timeoutMs: number ms,
 * false = no limit.
 */
export async function fetchWithDeadline(url, init, timeoutMs) {
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

export function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function _isTransientFetchError(err) {
  const s = String((err && err.message) || err || "").toLowerCase();
  return (
    s.includes("timed out") ||
    s.includes("networkerror") ||
    s.includes("failed to fetch") ||
    s.includes("load failed") ||
    s.includes("temporarily unavailable")
  );
}

export function _isRetryableHttpStatus(code) {
  return code === 408 || code === 425 || code === 429 || code === 502 || code === 503 || code === 504;
}

export function _isWriteMethod(m) {
  const x = String(m || "GET").toUpperCase();
  return x !== "GET" && x !== "HEAD" && x !== "OPTIONS";
}
