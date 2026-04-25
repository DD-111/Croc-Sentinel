/**
 * Smoke check that the SPA's runtime route surface matches the canonical
 * manifest in src/routes/manifest.js.
 *
 * Verifies:
 *   1. Every route id in ROUTES has a `registerRoute("<id>"` in assets/app.js.
 *   2. Every nav entry derived from ROUTES has a matching route id (no
 *      sidebar links pointing to nowhere).
 *   3. Every alias hash resolves to a real route id.
 *   4. No `registerRoute(...)` ids exist in the bundle that aren't covered by
 *      the manifest (catches stale duplicates if a route is renamed).
 *   5. Every `src/routes/<id>.route.js` file's id appears in the manifest
 *      (so a peeled-off route file can't drift away from `manifest.js`).
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const appPath = join(root, "assets", "app.js");
const routesDir = join(root, "src", "routes");
const manifestUrl = pathToFileURL(join(root, "src", "routes", "manifest.js")).href;

const { ROUTES, ROUTE_ALIASES, buildNavGroups } = await import(manifestUrl);

const src = readFileSync(appPath, "utf8");
const re = /registerRoute\(\s*"([^"]+)"/g;
const found = new Set();
let m;
while ((m = re.exec(src))) found.add(m[1]);

const expected = new Set(ROUTES.map((r) => r.id));

const missing = [...expected].filter((id) => !found.has(id));
const extra = [...found].filter((id) => !expected.has(id));

const navIds = new Set();
for (const g of buildNavGroups()) {
  for (const item of g.items) navIds.add(item.id);
}
const navMissing = [...navIds].filter((id) => !expected.has(id));

const aliasBroken = Object.entries(ROUTE_ALIASES).filter(([_alias, target]) => !expected.has(target));

// Cross-check src/routes/*.route.js filenames against the manifest. Each route
// file is named `<id>.route.js` and must register that exact id, otherwise the
// build would silently bundle dead code.
const routeFileIds = existsSync(routesDir)
  ? readdirSync(routesDir)
      .filter((f) => f.endsWith(".route.js"))
      .map((f) => f.slice(0, -".route.js".length))
  : [];
const routeFileOrphans = routeFileIds.filter((id) => !expected.has(id));

let fail = false;
if (missing.length) {
  console.error("Missing registerRoute() handlers in bundle:", missing);
  fail = true;
}
if (extra.length) {
  console.error("registerRoute() ids present in bundle but not in manifest:", extra);
  fail = true;
}
if (navMissing.length) {
  console.error("NAV entries point to ids not in manifest:", navMissing);
  fail = true;
}
if (aliasBroken.length) {
  console.error(
    "Aliases point at unknown route ids:",
    aliasBroken.map(([a, t]) => `${a} -> ${t}`),
  );
  fail = true;
}
if (routeFileOrphans.length) {
  console.error(
    "src/routes/*.route.js files whose id is not in manifest.js:",
    routeFileOrphans,
  );
  fail = true;
}
if (fail) process.exit(1);

console.log(
  "smoke-routes: OK — manifest=%d, registered=%d, nav=%d, aliases=%d, routeFiles=%d",
  expected.size,
  found.size,
  navIds.size,
  Object.keys(ROUTE_ALIASES).length,
  routeFileIds.length,
);
