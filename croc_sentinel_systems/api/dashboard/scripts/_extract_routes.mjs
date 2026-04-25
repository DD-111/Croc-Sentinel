/**
 * One-shot helper: extract several `registerRoute("<id>", ...)` blocks from
 * console.raw.js into individual src/routes/<id>.route.js files (bottom-up so
 * earlier line numbers are stable across edits).
 *
 * Each block is validated: first line must contain `registerRoute("<id>"`,
 * last line must be exactly `  });`. Leading 2-space indent is stripped so
 * the route file matches the convention of the existing 5 split routes.
 *
 * The slice in console.raw.js is replaced with a single stub comment line.
 *
 * Usage: node scripts/_extract_routes.mjs
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const monolithPath = join(root, "src", "console.raw.js");
const routesDir = join(root, "src", "routes");

// Bottom-up so earlier line numbers don't shift while we splice.
// Each entry: [id, startLine, endLine, oneLineSummary].
const ROUTES = [
  ["admin",    5276, 5909, "Admin & users console (list, role edit, pending signups)"],
  ["audit",    5173, 5273, "Audit log viewer (per-tenant)"],
  ["telegram", 5043, 5170, "Telegram bot link/unlink + test message"],
  ["events",   4671, 5040, "Live events stream (SSE) + filters"],
  ["activate", 4370, 4665, "Admin: activate/claim a device into the tenant"],
  ["devices",  3438, 4365, "All devices grid + per-row actions"],
  ["group",    3181, 3435, "Single group/site detail (deep link only)"],
  ["site",     3095, 3179, "Tenant site overview (superadmin)"],
  ["overview", 1837, 3093, "Dashboard overview / hero KPIs / recent activity"],
  ["account",  1649, 1834, "Logged-in user account & sessions panel"],
];

function header(id, summary) {
  return `/**
 * Route: #/${id} — ${summary}.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

`;
}

const raw = readFileSync(monolithPath, "utf8");
const lines = raw.split(/\r?\n/);

let working = lines.slice();
let extractedTotal = 0;
const summary = [];

for (const [id, start, end, oneLineSummary] of ROUTES) {
  const outPath = join(routesDir, `${id}.route.js`);
  if (existsSync(outPath)) {
    console.error(`SKIP ${id}: ${outPath} already exists`);
    continue;
  }
  const sliceFirst = working[start - 1];
  const sliceLast = working[end - 1];
  if (!sliceFirst || !sliceFirst.includes(`registerRoute("${id}"`)) {
    console.error(`FAIL ${id}: line ${start} does not start with registerRoute("${id}":`, JSON.stringify(sliceFirst));
    process.exit(2);
  }
  if (sliceLast.trim() !== "});") {
    console.error(`FAIL ${id}: line ${end} is not '});':`, JSON.stringify(sliceLast));
    process.exit(2);
  }
  const block = working.slice(start - 1, end);
  // Strip leading 2-space indent from each line (preserve totally-empty lines).
  const dedented = block.map((l) => (l.startsWith("  ") ? l.slice(2) : l));
  const fileText = header(id, oneLineSummary) + dedented.join("\n") + "\n";
  writeFileSync(outPath, fileText, "utf8");

  const stub = `  // route "${id}" extracted to src/routes/${id}.route.js`;
  working = working.slice(0, start - 1).concat([stub], working.slice(end));

  const removed = end - start + 1;
  extractedTotal += removed - 1;
  summary.push({ id, start, end, removed });
  console.log(`OK ${id}: removed L${start}-${end} (${removed} lines), wrote ${outPath}`);
}

writeFileSync(monolithPath, working.join("\n"), "utf8");
console.log(`---`);
console.log(`Extracted ${summary.length} routes; net -${extractedTotal} lines from console.raw.js.`);
