# Dashboard source (`src/`)

- **`console.raw.js`** — main SPA: top-level helpers, state, the route registry, and the routes that haven't been peeled off yet. Edit here for cross-cutting changes.
- **`lib/`** — pure modules merged at build time via `import`:
  - `constants.js` — `LS`, `NAV_GROUPS`, timeouts, role weights, `PUBLIC_ROUTE_IDS`, `ROUTE_ALIASES`
  - `dom.js` — `$`, `escapeHtml`, `hx`, `mountView`, safe fragment helpers
  - `sse.js` — `parseSseFields`, `pumpSseBody`
  - `format.js` — timestamps, audit/event row helpers
- **`routes/`** — single source of truth for routes:
  - `manifest.js` — `ROUTES`, `buildNavGroups`, `PUBLIC_ROUTE_IDS`, `ROUTE_ALIASES`. Imported by `lib/constants.js`.
  - `*.route.js` — one route per file. **Concatenated** (raw text, not `import`-ed) into the bundle by `scripts/build-dashboard.mjs`, so each file runs in the same scope as `console.raw.js` and can call `registerRoute`, `mountView`, `api`, `$`, etc. directly. **Do not** add `import` / `export` here.

## Adding a new route

1. Add a row to `routes/manifest.js` (`ROUTES` array — `id`, `path`, `min`, optional `group`/`label`/`ico`/`public`).
2. Create `routes/<id>.route.js`:
   ```js
   /** Route: #/<id> — <one-line description>. */
   registerRoute("<id>", async (view, args, routeSeq) => {
     setCrumb("...");
     mountView(view, `<div class="card">...</div>`);
     // ...
   });
   ```
3. Run `npm run verify` (build + `node --check` + smoke). The smoke script ensures every manifest id has a matching `registerRoute(...)` and vice versa.
4. If the route hits a new backend path, run `pytest croc_sentinel_systems/api/tests` so `test_every_spa_call_hits_a_real_backend_route` blesses the new contract.

## Build pipeline

`scripts/build-dashboard.mjs` does, in order:

1. Reads `console.raw.js`, strips the outer IIFE wrapper, and splices out the duplicated blocks now living in `lib/*.js`.
2. Prepends `import { ... } from "./lib/...js"` for the helpers.
3. Appends every `routes/*.route.js` (sorted) to the body.
4. Hands the result to **esbuild**, which `import`-bundles `lib/*.js`, then re-wraps the whole thing in a single IIFE → `assets/app.js`.

After edits, run **`npm run build`** (or **`npm run verify`**: build + `node --check` + smoke) before committing or shipping.

**Overrides:** you may patch `assets/app.js` directly for a hotfix, but always backport to `src/`. For CSS partition maintenance, **`node scripts/split-css.mjs --force`** bypasses the guard.
