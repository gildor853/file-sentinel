// Runtime smoke test of the built package (CJS).
const assert = require("node:assert/strict");
const { scanSync, RULES, DEFAULT_LIMITS, isFileSentinelError, FileSentinelError } = require("file-sentinel");

const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
const r = scanSync(svg, { filename: "a.svg" });
assert.equal(r.verdict, "malicious-indicators");
assert.ok(r.findings.some((f) => f.id === "SVG_SCRIPT"));
assert.ok(RULES.SVG_SCRIPT);
assert.ok(DEFAULT_LIMITS.maxBytes > 0);
assert.equal(isFileSentinelError(new FileSentinelError("InvalidInput", "x")), true);

console.log(`CJS smoke test passed on Node ${process.version}`);
