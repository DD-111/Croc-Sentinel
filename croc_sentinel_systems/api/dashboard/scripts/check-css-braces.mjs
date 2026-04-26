import fs from "node:fs";
import path from "node:path";

const target = process.argv[2] || "croc_sentinel_systems/api/dashboard/assets/css/01-base-shell.css";
const file = path.resolve(target);
const raw = fs.readFileSync(file, "utf8");
const stripped = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
const lines = stripped.split("\n");

let depth = 0;
const transitions = [];
for (let li = 0; li < lines.length; li++) {
  const text = lines[li];
  const inDepth = depth;
  for (const ch of text) {
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
  }
  const outDepth = depth;
  transitions.push({ line: li + 1, inDepth, outDepth, text });
}

console.log(`Final depth: ${depth}`);
console.log("Lines where depth crosses 0->? (start of top-level rule):");
for (const t of transitions) {
  if (t.inDepth === 0 && t.outDepth >= 1) {
    console.log(`  line ${t.line}: depth ${t.inDepth}->${t.outDepth}  | ${t.text.trim().slice(0, 90)}`);
  }
}
console.log("\nLines where depth crosses ?->0 (end of top-level rule):");
for (const t of transitions) {
  if (t.inDepth >= 1 && t.outDepth === 0) {
    console.log(`  line ${t.line}: depth ${t.inDepth}->${t.outDepth}  | ${t.text.trim().slice(0, 90)}`);
  }
}
