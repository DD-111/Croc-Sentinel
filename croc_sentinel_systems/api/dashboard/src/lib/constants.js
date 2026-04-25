/** LocalStorage keys + navigation constants */
import { buildNavGroups, PUBLIC_ROUTE_IDS, ROUTE_ALIASES, ROUTES } from "../routes/manifest.js";

export const LS = {
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

export const OFFLINE_MS = 90 * 1000;
/** Default remote siren / group loud duration (3 min). Panic sibling fan-out default (5 min) matches server. */
export const DEFAULT_REMOTE_SIREN_MS = 180000;
/** Panic sibling fan-out default (5 min) matches server. */
export const DEFAULT_PANIC_FANOUT_MS = 300000;

/** Sidebar groups derived from the canonical route manifest. Anyone modifying
 * navigation entries should edit src/routes/manifest.js, not this file. */
export const NAV_GROUPS = buildNavGroups();

export { PUBLIC_ROUTE_IDS, ROUTE_ALIASES, ROUTES };

export const ROLE_WEIGHT = { user: 1, admin: 2, superadmin: 3 };
