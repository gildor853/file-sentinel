#!/usr/bin/env node
/**
 * Enforces legal docs: DISCLAIMER.md present with the canonical marker,
 * README links to it, SECURITY.md mentions it, and relative markdown links
 * in README / SECURITY / CHANGELOG / DISCLAIMER resolve to existing files.
 *
 * Run: node scripts/check-legal.mjs
 * Exit 0 on success, 1 on failure.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const CANONICAL = "<!-- disclaimer-canonical: 2026-10-10-v2 -->";
const REQUIRED_HEADINGS = [
  "## No warranty",
  "## Limitation of liability",
  "## Use at your own risk",
  "## Not advice; no professional relationship",
  "## No audit; no maintenance obligation",
  "## No affiliation or endorsement",
  "## Third-party data and services",
  "## Indemnity",
  "## Precedence and interpretation",
];

const errors = [];
const warn = (m) => errors.push(m);

function read(rel) {
  const p = join(root, rel);
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8");
}

// --- DISCLAIMER.md ---
const disclaimer = read("DISCLAIMER.md");
if (!disclaimer) warn("DISCLAIMER.md is missing");
else {
  if (!disclaimer.includes(CANONICAL)) warn(`DISCLAIMER.md missing canonical marker: ${CANONICAL}`);
  for (const h of REQUIRED_HEADINGS) {
    if (!disclaimer.includes(h)) warn(`DISCLAIMER.md missing required heading: ${h}`);
  }
  if (!disclaimer.includes("TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW")) {
    warn("DISCLAIMER.md missing maximum-extent liability language");
  }
  if (!disclaimer.includes("AS IS") && !disclaimer.includes("“AS IS”") && !disclaimer.includes('"AS IS"')) {
    warn("DISCLAIMER.md missing AS IS language");
  }
  if (!existsSync(join(root, "LICENSE"))) warn("LICENSE is missing (DISCLAIMER.md links to it)");
}

// --- README ---
const readme = read("README.md");
if (!readme) warn("README.md is missing");
else {
  if (!/DISCLAIMER\.md/.test(readme)) warn("README.md does not mention DISCLAIMER.md");
  if (!/\[([^\]]*Disclaimer[^\]]*|DISCLAIMER\.md)\]\(\.\/DISCLAIMER\.md\)/i.test(readme) && !/\[([^\]]*)\]\(\.?\/?DISCLAIMER\.md\)/i.test(readme)) {
    warn("README.md lacks a relative markdown link to ./DISCLAIMER.md");
  }
  if (!/without warranty/i.test(readme)) warn("README.md should state 'without warranty' near the top");
  if (!/^## Disclaimer\b/m.test(readme)) warn("README.md missing a ## Disclaimer section");
}

// --- SECURITY.md (libraries) ---
const security = read("SECURITY.md");
if (security) {
  if (!/DISCLAIMER\.md/.test(security)) warn("SECURITY.md does not reference DISCLAIMER.md");
}

// --- package.json files (libraries) ---
const pkgPath = join(root, "package.json");
if (existsSync(pkgPath)) {
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    const files = pkg.files;
    if (Array.isArray(files)) {
      if (!files.includes("DISCLAIMER.md")) warn('package.json "files" must include DISCLAIMER.md');
      if (!files.includes("LICENSE")) warn('package.json "files" must include LICENSE');
    }
  } catch (e) {
    warn(`package.json unreadable: ${e instanceof Error ? e.message : e}`);
  }
}

// --- Broken relative links in markdown ---
const mdFiles = ["README.md", "SECURITY.md", "CHANGELOG.md", "DISCLAIMER.md"].filter((f) => existsSync(join(root, f)));
const linkRe = /\[([^\]]*)\]\(([^)]+)\)/g;
for (const file of mdFiles) {
  const text = read(file) ?? "";
  let m;
  while ((m = linkRe.exec(text)) !== null) {
    let target = m[2].trim();
    if (/^(https?:|mailto:|#|data:)/i.test(target)) continue;
    // strip anchors and titles
    target = target.replace(/\s+".*"$/, "").split("#")[0];
    if (!target) continue;
    if (!target.endsWith(".md") && !target.endsWith(".txt") && !target.includes("/")) {
      // might be LICENSE without extension
      if (target !== "LICENSE" && target !== "./LICENSE") continue;
    }
    const resolved = normalize(resolve(root, dirname(join(root, file)) === root ? "." : dirname(file), target));
    // Only check paths that stay inside the repo
    if (!resolved.startsWith(root)) continue;
    if (!existsSync(resolved)) warn(`${file}: broken relative link → ${m[2].trim()}`);
  }
}

if (errors.length) {
  console.error("check-legal failed:\n" + errors.map((e) => `  - ${e}`).join("\n"));
  process.exit(1);
}
console.log("check-legal: OK");
