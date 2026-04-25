/**
 * One-shot helper: extract `signals` and `ota` routes (which use the
 * "thin registerRoute wrapper + named helper function" pattern, so the
 * generic `_extract_routes.mjs` validator that requires `  });` as the last
 * line of a slice does not apply).
 *
 * signals: helper `renderSignalsPage(...)` + `registerRoute("signals", renderSignalsPage);`
 * ota:     `registerRoute("ota", async (...) => __renderOtaFirmwareRoute(...))`
 *          + helper `__renderOtaFirmwareRoute(...)`
 *
 * Slices are validated against expected first/last line markers and replaced
 * with a stub comment in console.raw.js.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const monolithPath = join(root, "src", "console.raw.js");
const routesDir = join(root, "src", "routes");

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

const PLAN = [
  {
    id: "signals",
    summary: "Signal log — device alarms + dashboard/API remote siren",
    start: 1681, // leading comment "// Unified: device alarms + ..."
    end:   1760, // `  registerRoute("signals", renderSignalsPage);`
    expectFirst: "// Unified: device alarms",
    expectLast:  'registerRoute("signals", renderSignalsPage);',
  },
  {
    id: "ota",
    summary: "OTA & firmware (superadmin staging + tenant-side upgrade hint)",
    start: 1762, // `  registerRoute("ota", async ...`
    end:   1984, // closing `  }` of `async function __renderOtaFirmwareRoute`
    expectFirst: 'registerRoute("ota"',
    expectLast:  "}",
  },
];

const raw = readFileSync(monolithPath, "utf8");
let lines = raw.split(/\r?\n/);

// Splice top-down won't work (later line numbers would shift); we plan
// indices from the same snapshot, so do bottom-up by sorting plans by start.
const plans = PLAN.slice().sort((a, b) => b.start - a.start);

let totalRemoved = 0;
const stubs = [];

for (const p of plans) {
  const outPath = join(routesDir, `${p.id}.route.js`);
  if (existsSync(outPath)) {
    console.error(`SKIP ${p.id}: ${outPath} already exists`);
    continue;
  }
  const first = lines[p.start - 1] ?? "";
  const last = lines[p.end - 1] ?? "";
  if (!first.includes(p.expectFirst)) {
    console.error(`FAIL ${p.id}: line ${p.start} does not start with ${JSON.stringify(p.expectFirst)}:`, JSON.stringify(first));
    process.exit(2);
  }
  if (last.trim() !== p.expectLast) {
    console.error(`FAIL ${p.id}: line ${p.end} != ${JSON.stringify(p.expectLast)}:`, JSON.stringify(last));
    process.exit(2);
  }

  const block = lines.slice(p.start - 1, p.end);
  const dedented = block.map((l) => (l.startsWith("  ") ? l.slice(2) : l));
  writeFileSync(outPath, header(p.id, p.summary) + dedented.join("\n") + "\n", "utf8");

  const stub = `  // route "${p.id}" extracted to src/routes/${p.id}.route.js`;
  lines = lines.slice(0, p.start - 1).concat([stub], lines.slice(p.end));
  const removed = p.end - p.start + 1;
  totalRemoved += removed - 1;
  stubs.push({ id: p.id, removed });
  console.log(`OK ${p.id}: removed L${p.start}-${p.end} (${removed} lines), wrote ${outPath}`);
}

writeFileSync(monolithPath, lines.join("\n"), "utf8");
console.log(`---`);
console.log(`Extracted ${stubs.length} routes; net -${totalRemoved} lines from console.raw.js.`);
