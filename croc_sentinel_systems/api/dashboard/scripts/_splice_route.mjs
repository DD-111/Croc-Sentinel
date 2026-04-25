/**
 * One-shot helper: remove a contiguous registerRoute block from console.raw.js
 * by line numbers, replacing it with a single stub comment line.
 *
 * Usage: node scripts/_splice_route.mjs <startLine> <endLine> <stub>
 *   startLine, endLine: 1-based, inclusive
 *   stub: replacement comment (no leading whitespace; 2 spaces are added)
 *
 * Validates that the first line of the slice contains "registerRoute(" and the
 * last line is exactly "  });" so we can't accidentally cut into other code.
 */
import { readFileSync, writeFileSync } from "node:fs";

const [, , startArg, endArg, ...stubParts] = process.argv;
const start = Number(startArg);
const end = Number(endArg);
const stub = stubParts.join(" ").trim();
if (!Number.isInteger(start) || !Number.isInteger(end) || start <= 0 || end < start || !stub) {
  console.error("usage: node _splice_route.mjs <startLine> <endLine> <stub>");
  process.exit(2);
}

const path = "src/console.raw.js";
const text = readFileSync(path, "utf8");
const lines = text.split(/\r?\n/);
if (end > lines.length) {
  console.error(`endLine ${end} > file length ${lines.length}`);
  process.exit(2);
}

const sliceFirst = lines[start - 1];
const sliceLast = lines[end - 1];
if (!sliceFirst.includes("registerRoute(") && !lines[start].includes("registerRoute(")) {
  console.error("first line of slice does not contain registerRoute(:", JSON.stringify(sliceFirst));
  process.exit(3);
}
if (sliceLast.trim() !== "});") {
  console.error("last line of slice is not '});':", JSON.stringify(sliceLast));
  process.exit(3);
}

const before = lines.slice(0, start - 1);
const after = lines.slice(end);
const replacement = ["  // " + stub.replace(/^\/\/\s*/, "")];
writeFileSync(path, [...before, ...replacement, ...after].join("\n"), "utf8");
const removed = end - start + 1;
console.log(`OK: removed L${start}-${end} (${removed} lines), inserted stub`);
