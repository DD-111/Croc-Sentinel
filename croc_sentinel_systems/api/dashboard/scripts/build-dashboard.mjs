/**
 * Splices modular imports into console.raw.js (IIFE monolith) and bundles to assets/app.js.
 *
 * Two parallel split mechanisms:
 *   • src/lib/<name>.js  — proper ES modules. Imported by HEADER. Pure helpers
 *                          (no shared state, no DOM-tree references).
 *   • src/shell/<NN>-<name>.shell.js + src/routes/<id>.route.js — concatenated
 *                          as raw text after the spliced monolith body. NOT
 *                          ES modules. Share scope with console.raw.js so
 *                          they can call `registerRoute`, `mountView`, `api`,
 *                          `$`, mutate `state`, etc. directly. Numeric prefix
 *                          on shell files forces concat order
 *                          (00-state → 10-api → 20-layout → 30-router →
 *                          routes/* alphabetic).
 *
 * Final order:
 *   HEADER imports
 *   → spliced console.raw body (auth chrome + glue + boot only)
 *   → src/shell/*.shell.js  (sorted)
 *   → src/routes/*.route.js (sorted)
 *   → esbuild wraps the whole thing in an IIFE.
 */
import * as esbuild from "esbuild";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const rawPath = join(root, "src", "console.raw.js");
const shellDir = join(root, "src", "shell");
const routesDir = join(root, "src", "routes");

const HEADER = `/* Croc Sentinel Console — bundled from dashboard/src/ (npm run build) */
"use strict";
import { LS, OFFLINE_MS, DEFAULT_REMOTE_SIREN_MS, DEFAULT_PANIC_FANOUT_MS, NAV_GROUPS, ROLE_WEIGHT, PUBLIC_ROUTE_IDS, ROUTE_ALIASES } from "./lib/constants.js";
import { $, $$, escapeHtml, hx, mountView, parseHtmlToFragment, setChildMarkup, prependChildMarkup, appendChildMarkup, setHtmlIfChanged, setTextIfChanged } from "./lib/dom.js";
import { parseSseFields, pumpSseBody, SSE_PARSE_BUF_MAX } from "./lib/sse.js";
import { fmtTs, fmtRel, maskPlatform, auditActionPrefix, auditDetailDedupedRows, eventDetailDedupedRows, messagePayloadRows, auditChipClass } from "./lib/format.js";
import { DEFAULT_API_TIMEOUT_MS, ROUTE_RENDER_TIMEOUT_MS, apiBase, fetchWithDeadline, _sleep, _isTransientFetchError, _isRetryableHttpStatus, _isWriteMethod } from "./lib/api.js";
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME, _readCsrfCookie, getCsrfToken, setCsrfToken, refreshCsrfToken, _isCsrfRejection } from "./lib/csrf.js";
import { authSiteFooterHtml, authAsideHtml } from "./lib/auth-chrome.js";

`;

function spliceMonolith(raw) {
  // console.raw.js used to ship literal copies of every block now exported
  // from src/lib/*.js, and this function virtual-spliced them out at build
  // time so esbuild only saw one copy. Those duplicates have since been
  // physically removed from console.raw.js (see scripts/_strip_lib_dups.mjs),
  // so all splice rules are gone — the only remaining transform is stripping
  // the outer IIFE wrapper. esbuild re-adds an IIFE around the whole bundle.
  //
  // If anyone re-adds a duplicate lib/* declaration here (e.g. another
  // `function escapeHtml(v) { ... }` in console.raw.js), esbuild will fail
  // with a duplicate-binding error because HEADER already imports the same
  // name — that is the desired behaviour, do not "fix" by re-introducing a
  // splice; fix by deleting the duplicate.
  let body = raw.replace(/\r\n/g, "\n");
  body = body.replace(/\(function \(\) \{\s*\n  ["']use strict["'];\s*\n/, "");
  body = body.replace(/\n\}\)\(\);\s*$/, "");
  return HEADER + body;
}

function loadShellFiles() {
  if (!existsSync(shellDir)) return "";
  const entries = readdirSync(shellDir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".shell.js"))
    .map((e) => e.name)
    .sort();
  if (entries.length === 0) return "";
  let out = "\n// ============================================================\n";
  out += "// === Shell spliced from src/shell/*.shell.js ================\n";
  out += "// === (state / api / layout / router; raw concat, shared) ====\n";
  out += "// ============================================================\n";
  for (const name of entries) {
    const txt = readFileSync(join(shellDir, name), "utf8").replace(/\r\n/g, "\n");
    out += `\n// ── ${name} ─────────────────────────────────────\n` + txt + "\n";
  }
  return out;
}

function loadRouteFiles() {
  if (!existsSync(routesDir)) return "";
  const entries = readdirSync(routesDir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".route.js"))
    .map((e) => e.name)
    .sort();
  if (entries.length === 0) return "";
  let out = "\n// ============================================================\n";
  out += "// === Routes spliced from src/routes/*.route.js ==============\n";
  out += "// ============================================================\n";
  for (const name of entries) {
    const txt = readFileSync(join(routesDir, name), "utf8").replace(/\r\n/g, "\n");
    out += `\n// ── ${name} ─────────────────────────────────────\n` + txt + "\n";
  }
  return out;
}

const raw = readFileSync(rawPath, "utf8");
const contents = spliceMonolith(raw) + loadShellFiles() + loadRouteFiles();

const result = await esbuild.build({
  stdin: {
    contents,
    resolveDir: join(root, "src"),
    sourcefile: "virtual-console.js",
    loader: "js",
  },
  bundle: true,
  outfile: join(root, "assets", "app.js"),
  platform: "browser",
  format: "iife",
  legalComments: "none",
  // Linked sourcemap → DevTools shows the original src/routes/*.route.js,
  // src/shell/*.shell.js, and src/lib/*.js paths instead of one giant
  // assets/app.js. This is the single most effective fix for "I edited
  // something and the change didn't show up" — open DevTools → Sources and
  // you can confirm exactly which source file is live.
  sourcemap: "linked",
  banner: {
    js: [
      "/* ============================================================",
      " * Croc Sentinel Console — BUILD OUTPUT (do NOT hand-edit).",
      " * Source of truth lives under dashboard/src/ and dashboard/assets/css/.",
      " * Rebuild:   cd croc_sentinel_systems/api/dashboard && npm run build",
      " * Cheat sheet: see dashboard/README.md (top of file).",
      " * ============================================================ */",
    ].join("\n"),
  },
});

if (result.errors && result.errors.length) {
  console.error(result.errors);
  process.exit(1);
}

console.log("OK: wrote assets/app.js");
