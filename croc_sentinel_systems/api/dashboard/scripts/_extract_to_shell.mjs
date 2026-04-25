/**
 * One-shot helper: peel four large state/coupled blocks out of console.raw.js
 * into src/shell/<NN>-<name>.shell.js. Shell files are concatenated as raw
 * text by scripts/build-dashboard.mjs (same trick that already powers
 * src/routes/*.route.js) so they share scope with the monolith — code can
 * still reference `state`, `mountView`, `api`, `$`, etc. without imports.
 *
 * The numeric prefix forces concat order: state must declare `state = {}`
 * before anything else uses it at module load time.
 *
 * Also deletes the already-extracted-to-lib/ auth-chrome block.
 *
 * Run once. Safe to re-run: missing markers are skipped.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const monolithPath = join(root, "src", "console.raw.js");
const shellDir = join(root, "src", "shell");
if (!existsSync(shellDir)) mkdirSync(shellDir, { recursive: true });

// Each entry: id (for log), start marker, end marker (exclusive),
// optional shellFile destination + header docblock (omit to delete only),
// breadcrumb that replaces the range in console.raw.js.
const PLAN = [
  {
    id: "auth-chrome",
    start: "  function authSiteFooterHtml() {",
    end:   "  // ------------------------------------------------------------------ state",
    // No shellFile — already lives at src/lib/auth-chrome.js (proper ESM).
    crumb:
      "  // authSiteFooterHtml / authAsideHtml → src/lib/auth-chrome.js\n" +
      "  // (imported by build-dashboard.mjs HEADER).\n" +
      "\n",
  },
  {
    id: "state",
    start: "  // ------------------------------------------------------------------ state",
    end:   "  // ------------------------------------------------------------------ utils",
    shellFile: "00-state.shell.js",
    docblock:
      "/**\n" +
      " * SPA shared state + group-meta storage + lifecycle timers.\n" +
      " *\n" +
      " * Concatenated as raw text by scripts/build-dashboard.mjs (NOT an ESM\n" +
      " * module). Lives in the same IIFE scope as the monolith body and the\n" +
      " * route files, which is why every other module can still reference\n" +
      " * `state`, `_groupMetaSyncChain`, `healthPollTimer`, etc. without imports.\n" +
      " *\n" +
      " * Numeric prefix `00-` forces this to load first inside src/shell/ so the\n" +
      " * mutable state declarations exist before any function that touches them\n" +
      " * runs (function declarations in later shell files hoist; let/const here\n" +
      " * does not).\n" +
      " */\n",
    crumb:
      "  // state object + group-meta storage + lifecycle timers (route redirect /\n" +
      "  // health poll / events live badge) → src/shell/00-state.shell.js.\n" +
      "\n",
  },
  {
    id: "api",
    start: "  // ------------------------------------------------------------------ api",
    end:   "  // ------------------------------------------------------------------ layout",
    shellFile: "10-api.shell.js",
    docblock:
      "/**\n" +
      " * Authenticated API layer (api / apiOr / apiGetCached + caching), CSRF-aware\n" +
      " * write retry, group apply/delete fallbacks, share matrix, FW upgrade hint\n" +
      " * dialog, and the auth lifecycle calls (login / loadMe / loadHealth).\n" +
      " *\n" +
      " * Concatenated as raw text by scripts/build-dashboard.mjs after\n" +
      " * 00-state.shell.js so it can mutate state.me / state.health and call into\n" +
      " * the timer helpers declared there. The pure HTTP helpers it depends on\n" +
      " * (apiBase, fetchWithDeadline, _isWriteMethod, ...) come from\n" +
      " * src/lib/api.js + src/lib/csrf.js via the bundle HEADER imports.\n" +
      " */\n",
    crumb:
      "  // api / apiOr / apiGetCached / FW hint dialog / login / loadMe / loadHealth\n" +
      "  // and the group apply/delete + share matrix helpers →\n" +
      "  // src/shell/10-api.shell.js.\n" +
      "\n",
  },
  {
    id: "layout",
    start: "  // ------------------------------------------------------------------ layout",
    end:   "  // ------------------------------------------------------------------ router",
    shellFile: "20-layout.shell.js",
    docblock:
      "/**\n" +
      " * App chrome: who-am-I card, sidebar nav, health pills, MQTT dot, theme\n" +
      " * toggle, mobile drawer + desktop rail collapse logic.\n" +
      " *\n" +
      " * Concatenated as raw text by scripts/build-dashboard.mjs after\n" +
      " * 10-api.shell.js. Layout reads state directly (state.me, state.health,\n" +
      " * state.mqttConnected) and writes to the live DOM via setHtmlIfChanged /\n" +
      " * setChildMarkup from src/lib/dom.js (HEADER import).\n" +
      " */\n",
    crumb:
      "  // renderAuthState / renderNav / renderHealthPills / renderMqttDot /\n" +
      "  // setCrumb / setTheme / initTheme / toggleNav / applySidebarRail /\n" +
      "  // toggleSidebarRail / syncNavForViewport → src/shell/20-layout.shell.js.\n" +
      "\n",
  },
  {
    id: "router",
    start: "  // ------------------------------------------------------------------ router",
    end:   "  // ------------------------------------------------------------------ pages",
    shellFile: "30-router.shell.js",
    docblock:
      "/**\n" +
      " * Hash router + per-route ticker registry. Owns the `routes` registry that\n" +
      " * src/routes/*.route.js populates via registerRoute(id, handler) at load\n" +
      " * time, plus the renderRoute() pipeline (auth gating, view-loading skeleton,\n" +
      " * timeout race, post-render nav refresh). Listens on hashchange.\n" +
      " *\n" +
      " * Concatenated AFTER state/api/layout but BEFORE the route files, so the\n" +
      " * registry is empty at concat-time but every routes/*.route.js sees\n" +
      " * registerRoute() in scope when its top-level call runs.\n" +
      " */\n",
    crumb:
      "  // registerRoute / renderRoute / clearRouteTickers / scheduleRouteTicker /\n" +
      "  // hashchange listener → src/shell/30-router.shell.js.\n" +
      "\n",
  },
];

let body = readFileSync(monolithPath, "utf8").replace(/\r\n/g, "\n");

// Compute every (start, end) pair against the *original* body, then apply in
// descending order of start so earlier offsets stay valid.
const ops = [];
for (const r of PLAN) {
  const s = body.indexOf(r.start);
  let e = -1;
  if (s !== -1) e = body.indexOf(r.end, s + r.start.length);
  if (s === -1 || e === -1) {
    console.log(`SKIP ${r.id}: marker missing (start=${s}, end=${e}) — assumed already moved`);
    continue;
  }
  const slice = body.slice(s, e);
  ops.push({ ...r, s, e, slice });
}

// Write shell/<file> first (in plan order, so file order matches log order).
for (const op of ops) {
  if (!op.shellFile) continue;
  // Dedent: every line currently has a 2-space prefix because it lives inside
  // the IIFE body. Strip exactly two leading spaces so the shell file reads
  // as ordinary top-level code (matches the convention in src/routes/).
  const dedented = op.slice
    .split("\n")
    .map((line) => (line.startsWith("  ") ? line.slice(2) : line))
    .join("\n");
  // Make sure the file ends with exactly one newline.
  const out = op.docblock + dedented.replace(/\n+$/, "") + "\n";
  const dest = join(shellDir, op.shellFile);
  writeFileSync(dest, out, "utf8");
  console.log(`WRITE src/shell/${op.shellFile}: ${dedented.split("\n").length} lines`);
}

// Now strip the ranges from console.raw.js (descending so offsets stay valid).
ops.sort((a, b) => b.s - a.s);
let removed = 0;
for (const op of ops) {
  body = body.slice(0, op.s) + op.crumb + body.slice(op.e);
  removed += op.e - op.s;
  console.log(`STRIP ${op.id}: ${op.e - op.s} bytes → breadcrumb (${op.crumb.length} bytes)`);
}

writeFileSync(monolithPath, body, "utf8");
console.log("---");
console.log(`Total stripped: ${removed} bytes; console.raw.js rewritten.`);
