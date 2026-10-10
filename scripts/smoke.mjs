// Runtime smoke test of the built package (ESM), run by CI on older Node.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, scanSync, RULES, DEFAULT_LIMITS, isFileSentinelError, FileSentinelError } from "file-sentinel";

const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
const r = scanSync(svg, { filename: "a.svg" });
assert.equal(r.verdict, "malicious-indicators");
assert.ok(r.findings.some((f) => f.id === "SVG_SCRIPT"));
assert.ok(RULES.SVG_SCRIPT);
assert.ok(DEFAULT_LIMITS.maxBytes > 0);
assert.equal(isFileSentinelError(new FileSentinelError("InvalidInput", "x")), true);
const asyncR = await scan(svg, { filename: "a.svg" });
assert.equal(asyncR.verdict, "malicious-indicators");

const root = dirname(fileURLToPath(import.meta.url));
const cli = join(root, "../dist/cli.js");
const help = spawnSync(process.execPath, [cli, "--help"], { encoding: "utf8" });
assert.equal(help.status, 0);
assert.match(help.stdout, /file-sentinel/);
const ver = spawnSync(process.execPath, [cli, "--version"], { encoding: "utf8" });
assert.equal(ver.status, 0);

console.log(`ESM smoke test passed on Node ${process.version}`);
