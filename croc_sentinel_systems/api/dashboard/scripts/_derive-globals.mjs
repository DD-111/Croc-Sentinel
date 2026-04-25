#!/usr/bin/env node
// Derive cross-file global names for ESLint's no-undef rule.
//
// The dashboard bundle is built by raw-concatenating console.raw.js +
// src/shell/*.shell.js + src/routes/*.route.js into a single IIFE, plus
// HEADER imports from src/lib/*.js. ESLint linting a single file at a
// time has no way to know which `function` / `const` declared in a
// sibling file is actually defined — so we collect those names here
// and feed them to eslint.config.mjs as predefined globals.
//
// Run: node scripts/_derive-globals.mjs > scripts/_globals.json

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const SRC = path.join(ROOT, "src");

const libDir = path.join(SRC, "lib");
const shellDir = path.join(SRC, "shell");
const routesDir = path.join(SRC, "routes");
const monolith = path.join(SRC, "console.raw.js");

const libFiles = fs.readdirSync(libDir).filter((f) => f.endsWith(".js")).map((f) => path.join(libDir, f));
const shellFiles = fs.readdirSync(shellDir).filter((f) => f.endsWith(".shell.js")).map((f) => path.join(shellDir, f));
const routeFiles = fs.readdirSync(routesDir).filter((f) => f.endsWith(".route.js")).map((f) => path.join(routesDir, f));

function readSafe(p) {
  return fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}

// Extract `export ... <name>` for ESM lib files. Covers:
//   export function NAME(
//   export async function NAME(
//   export const NAME =
//   export let NAME =
//   export class NAME
//   export { NAME, ALIAS as OTHER }
function extractLibExports(src) {
  const names = new Set();
  const reFn = /^export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm;
  const reConst = /^export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)/gm;
  const reClass = /^export\s+class\s+([A-Za-z_$][\w$]*)/gm;
  const reBrace = /^export\s*\{([^}]+)\}/gm;
  for (const m of src.matchAll(reFn)) names.add(m[1]);
  for (const m of src.matchAll(reConst)) names.add(m[1]);
  for (const m of src.matchAll(reClass)) names.add(m[1]);
  for (const m of src.matchAll(reBrace)) {
    for (const part of m[1].split(",")) {
      const p = part.trim();
      if (!p) continue;
      const asMatch = p.match(/^(?:[A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/);
      const id = asMatch ? asMatch[1] : p.match(/^[A-Za-z_$][\w$]*/)?.[0];
      if (id) names.add(id);
    }
  }
  return names;
}

// Extract top-level `function`, `const`, `let`, `var`, `class` declarations.
// "Top-level" approximated as: declaration must start at column 0 (monolith
// IIFE has 2-space indent; shell/route files were dedented to column 0 by
// the extraction script). For console.raw.js we additionally allow 2-space
// indent to catch the surviving glue helpers (getToken / hasRole / can / ...).
function extractTopLevelDecls(src, { allowTwoSpace = false } = {}) {
  const names = new Set();
  const indent = allowTwoSpace ? "(?:  )?" : "";
  const reFn = new RegExp(`^${indent}(?:async\\s+)?function\\s+([A-Za-z_$][\\w$]*)`, "gm");
  const reConst = new RegExp(`^${indent}(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)`, "gm");
  const reClass = new RegExp(`^${indent}class\\s+([A-Za-z_$][\\w$]*)`, "gm");
  for (const m of src.matchAll(reFn)) names.add(m[1]);
  for (const m of src.matchAll(reConst)) names.add(m[1]);
  for (const m of src.matchAll(reClass)) names.add(m[1]);
  return names;
}

const libExports = new Set();
for (const f of libFiles) {
  for (const n of extractLibExports(readSafe(f))) libExports.add(n);
}

const shellDecls = new Set();
for (const f of shellFiles) {
  for (const n of extractTopLevelDecls(readSafe(f))) shellDecls.add(n);
}

const routeDecls = new Set();
for (const f of routeFiles) {
  for (const n of extractTopLevelDecls(readSafe(f))) routeDecls.add(n);
}

const monolithDecls = extractTopLevelDecls(readSafe(monolith), { allowTwoSpace: true });

// Cross-file globals visible to every shell/route/monolith file:
const concatGlobals = new Set([
  ...libExports,
  ...shellDecls,
  ...routeDecls,
  ...monolithDecls,
]);

// `arguments` and similar are filtered: nothing here should match those.
const out = {
  libExports: [...libExports].sort(),
  shellDecls: [...shellDecls].sort(),
  routeDecls: [...routeDecls].sort(),
  monolithDecls: [...monolithDecls].sort(),
  concatGlobals: [...concatGlobals].sort(),
};

const outPath = path.join(__dirname, "_globals.json");
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.log(`derive-globals: wrote ${outPath}`);
console.log(`  lib exports     : ${out.libExports.length}`);
console.log(`  shell decls     : ${out.shellDecls.length}`);
console.log(`  route decls     : ${out.routeDecls.length}`);
console.log(`  monolith decls  : ${out.monolithDecls.length}`);
console.log(`  concat globals  : ${out.concatGlobals.length}`);
