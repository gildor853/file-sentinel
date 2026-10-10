/** Generates the rules table in README.md from RULES. */
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BEGIN = "<!-- rules-table:begin -->";
const END = "<!-- rules-table:end -->";

/** @param {Record<string, { id: string, severity: string, title: string, description: string, scope: string, references: readonly string[] }>} RULES */
export function rulesTable(RULES) {
  const byScope = new Map();
  for (const r of Object.values(RULES)) {
    // group by first token of scope for readability
    const key = r.scope.split(",")[0].trim();
    if (!byScope.has(key)) byScope.set(key, []);
    byScope.get(key).push(r);
  }
  const order = [...byScope.keys()].sort((a, b) => {
    const rank = (s) => {
      if (s === "all" || s === "filename") return 0;
      if (s.startsWith("svg") || s === "xml" || s.startsWith("html")) return 1;
      if (s === "pdf") return 2;
      if (s.startsWith("doc") || s.startsWith("xls") || s.startsWith("ppt") || s === "rtf") return 3;
      if (s === "zip" || s.startsWith("7z") || s === "gzip" || s === "tar") return 4;
      if (s.startsWith("pe") || s.startsWith("js") || s === "lnk") return 5;
      if (s.startsWith("png") || s.startsWith("jpeg")) return 6;
      return 7;
    };
    return rank(a) - rank(b) || a.localeCompare(b);
  });
  const rows = [
    "| Id | Severity | Scope | Title |",
    "| --- | --- | --- | --- |",
  ];
  for (const key of order) {
    for (const r of byScope.get(key).sort((a, b) => a.id.localeCompare(b.id))) {
      rows.push(`| \`${r.id}\` | ${r.severity} | ${r.scope.replace(/\|/g, "\\|")} | ${r.title.replace(/\|/g, "\\|")} |`);
    }
  }
  return `${BEGIN}\n${rows.join("\n")}\n${END}`;
}

/** @param {string} readme @param {Record<string, unknown>} RULES */
export function renderReadme(readme, RULES) {
  const table = rulesTable(RULES);
  if (!readme.includes(BEGIN) || !readme.includes(END)) {
    throw new Error(`README.md is missing ${BEGIN} … ${END} markers`);
  }
  const re = new RegExp(`${BEGIN}[\\s\\S]*?${END}`);
  return readme.replace(re, table);
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const write = process.argv.includes("--write");
  const require = createRequire(import.meta.url);
  // Prefer built package
  let RULES;
  try {
    ({ RULES } = await import(pathToFileURL(join(root, "dist/index.js")).href));
  } catch {
    ({ RULES } = require(join(root, "dist/index.cjs")));
  }
  const path = join(root, "README.md");
  const before = readFileSync(path, "utf8");
  const after = renderReadme(before, RULES);
  if (write) {
    writeFileSync(path, after);
    console.log("README.md rules table updated");
  } else if (after !== before) {
    console.error("README.md rules table is out of date. Run: node scripts/rules-table.mjs --write");
    process.exit(1);
  } else {
    console.log("README.md rules table is up to date");
  }
}
