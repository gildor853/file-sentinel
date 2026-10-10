/** Local long mutation fuzz: ≥200k mutated inputs. Usage: node scripts/fuzz-long.mjs */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync, deflateRawSync } from "node:zlib";
import { scanSync } from "../dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const enc = (s) => new TextEncoder().encode(s);
const FIX = join(root, "test/fixtures");

function mutate(src, seed) {
  const b = src.slice();
  const n = 1 + (seed % 12);
  for (let k = 0; k < n; k++) {
    if (!b.length) break;
    const i = (seed * 1103515245 + k * 12345) >>> 0;
    const idx = i % b.length;
    b[idx] = (b[idx] ^ (1 + (seed + k) % 255)) & 0xff;
  }
  // occasional truncation / extension
  if (seed % 7 === 0) return b.subarray(0, Math.max(0, b.length - (seed % 64)));
  if (seed % 11 === 0) {
    const e = new Uint8Array(b.length + 16);
    e.set(b);
    for (let i = 0; i < 16; i++) e[b.length + i] = (seed + i) & 0xff;
    return e;
  }
  return b;
}

const templates = [];
for (const dir of ["clean", "constructs", "fp-clean"]) {
  const d = join(FIX, dir);
  try {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      try {
        templates.push({ name, bytes: new Uint8Array(readFileSync(p)) });
      } catch { /* skip dirs */ }
    }
  } catch { /* missing */ }
}
// synthetic templates
templates.push(
  { name: "s.pdf", bytes: enc("%PDF-1.4\n1 0 obj<< /S /JavaScript /JS (x) >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n") },
  { name: "s.rtf", bytes: enc("{\\rtf1\\ansi{\\object{\\*\\objdata 4d5a}}}") },
  { name: "s.svg", bytes: enc('<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>') },
  { name: "s.html", bytes: enc("<html><script>eval(atob('YQ=='))</script></html>") },
  { name: "s.gz", bytes: new Uint8Array(gzipSync(enc("hello"))) },
);

const TARGET = Number(process.env.FUZZ_COUNT || 200_000);
const t0 = Date.now();
let count = 0;
let errors = 0;
for (let seed = 0; seed < TARGET; seed++) {
  const t = templates[seed % templates.length];
  const b = mutate(t.bytes, seed);
  try {
    scanSync(b, {
      filename: t.name,
      limits: { maxOperations: 1_000_000, maxBytes: 4_000_000, maxDecompressedBytes: 4_000_000, maxEntries: 500 },
    });
  } catch (e) {
    errors++;
    if (errors < 5) console.error("throw", seed, e);
  }
  count++;
  if (seed > 0 && seed % 50_000 === 0) {
    const dt = (Date.now() - t0) / 1000;
    console.log(`… ${seed} inputs in ${dt.toFixed(1)}s (${(seed / dt).toFixed(0)}/s), throws=${errors}`);
  }
}
const dt = (Date.now() - t0) / 1000;
const summary = { count, errors, seconds: dt, perSec: +(count / dt).toFixed(1) };
console.log(JSON.stringify(summary));
if (errors > 0) process.exit(2);
if (count < TARGET) process.exit(1);
writeFileSync(join(root, "artifacts-fuzz-long.json"), JSON.stringify(summary, null, 2));
