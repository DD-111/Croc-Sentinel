/**
 * Single source of truth for SPA routes.
 *
 * Every hash route the app understands lives here. Three consumers read it:
 *   1) src/lib/constants.js exports `NAV_GROUPS` derived from this list, so the
 *      sidebar renders entries with a `group` field.
 *   2) src/console.raw.js expects a `registerRoute("<id>", handler)` for every
 *      `id` listed below; the build smoke check (scripts/smoke-routes.mjs)
 *      enforces that.
 *   3) Aliases (e.g. `#/alarm-log` → `signals`) live next to their canonical
 *      route so future modular splits cannot silently drop deep links.
 *
 * When you add a route:
 *   - Add an entry here.
 *   - Implement `registerRoute("<id>", handler)` in src/console.raw.js (or, in
 *     a future modular split, src/routes/<id>.js).
 *   - If it should appear in the sidebar, set `group` + `label` + `ico`.
 *   - If it can be reached by an unauthenticated user, set `public: true`.
 *   - If a different hash should resolve to the same handler, list it in
 *     `aliases`.
 */

/** @type {ReadonlyArray<RouteSpec>} */
export const ROUTES = Object.freeze([
  // -------------------------------------------------------------- public auth
  { id: "login", hash: "#/login", public: true },
  { id: "forgot-password", hash: "#/forgot-password", public: true },
  { id: "register", hash: "#/register", public: true },
  { id: "account-activate", hash: "#/account-activate", public: true },

  // -------------------------------------------------------------- account
  { id: "account", hash: "#/account", min: "user", group: "Account & admin", label: "Account", ico: "◍" },

  // -------------------------------------------------------------- dashboard
  { id: "overview", hash: "#/overview", min: "user", group: "Dashboard", label: "Overview", ico: "◎" },
  { id: "devices", hash: "#/devices", min: "user", group: "Dashboard", label: "All devices", ico: "▢" },
  { id: "site", hash: "#/site", min: "superadmin", group: "Dashboard", label: "Site", ico: "⌁" },
  // Deep link only (no nav entry): #/group/:key
  { id: "group", hash: "#/group", min: "user" },

  // -------------------------------------------------------------- monitoring
  { id: "signals", hash: "#/signals", min: "user", group: "Monitoring", label: "Signals", ico: "◉", aliases: ["#/alarm-log"] },
  { id: "events", hash: "#/events", min: "user", group: "Monitoring", label: "Events", ico: "≈" },
  { id: "ota", hash: "#/ota", min: "superadmin", group: "Monitoring", label: "OTA (ops)", ico: "↑" },

  // -------------------------------------------------------------- alerts/fleet
  { id: "alerts", hash: "#/alerts", min: "user", group: "Alerts & fleet", label: "Siren", ico: "!" },
  { id: "activate", hash: "#/activate", min: "admin", group: "Alerts & fleet", label: "Activate device", ico: "+" },

  // -------------------------------------------------------------- admin
  { id: "telegram", hash: "#/telegram", min: "user", group: "Account & admin", label: "Telegram", ico: "✆" },
  { id: "audit", hash: "#/audit", min: "admin", group: "Account & admin", label: "Audit", ico: "≡" },
  { id: "admin", hash: "#/admin", min: "admin", group: "Account & admin", label: "Admin & users", ico: "☼" },
]);

/** Display order (top → bottom) of nav groups. Anything else falls to the end. */
const GROUP_ORDER = ["Dashboard", "Monitoring", "Alerts & fleet", "Account & admin"];

/** Build NAV_GROUPS from ROUTES — `path` matches the legacy field name so the
 * sidebar renderer in console.raw.js does not need to change. */
export function buildNavGroups() {
  /** @type {Record<string, {title: string, items: any[]}>} */
  const byTitle = {};
  for (const r of ROUTES) {
    if (!r.group || !r.label) continue;
    const g = byTitle[r.group] || (byTitle[r.group] = { title: r.group, items: [] });
    g.items.push({
      id: r.id,
      label: r.label,
      ico: r.ico || "",
      path: r.hash,
      min: r.min || "user",
    });
  }
  return GROUP_ORDER
    .map((t) => byTitle[t])
    .concat(Object.keys(byTitle).filter((t) => !GROUP_ORDER.includes(t)).map((t) => byTitle[t]))
    .filter(Boolean);
}

/** Set of route ids that should be reachable without a signed-in session. */
export const PUBLIC_ROUTE_IDS = Object.freeze(new Set(ROUTES.filter((r) => r.public).map((r) => r.id)));

/** Map of alias hash → canonical route id (e.g. `#/alarm-log` → `signals`). */
export const ROUTE_ALIASES = Object.freeze(
  ROUTES.reduce((acc, r) => {
    if (Array.isArray(r.aliases)) {
      for (const a of r.aliases) acc[String(a)] = r.id;
    }
    return acc;
  }, /** @type {Record<string, string>} */ ({})),
);

/**
 * @typedef {Object} RouteSpec
 * @property {string} id           Unique route id (matches `registerRoute("...")`).
 * @property {string} hash         Canonical hash including `#/` prefix.
 * @property {string} [min]        Minimum role: "user" | "admin" | "superadmin".
 * @property {boolean} [public]    Reachable without a session (login flow etc.).
 * @property {string} [group]      Sidebar group title (omit for deep-link routes).
 * @property {string} [label]      Sidebar label (required when `group` is set).
 * @property {string} [ico]        Sidebar glyph.
 * @property {string[]} [aliases]  Alternate hashes that resolve to the same handler.
 */
