import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { RULES, SEVERITIES } from "../src/index.js";
import { REFERENCE_URLS } from "../src/rules.js";

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

describe("README", () => {
  it("has the GitHub install snippet and no npm badge", () => {
    expect(readme).toContain("npm install github:gildor853/file-sentinel#v1.0.0");
    expect(readme).not.toMatch(/img\.shields\.io\/npm/);
    expect(readme).not.toContain("npm version");
  });

  it("states honest positioning and no liability for missed threats", () => {
    expect(readme).toMatch(/not an antivirus/i);
    expect(readme).toMatch(/none of the checked constructs/i);
    expect(readme).toMatch(/no liability for missed threats/i);
    expect(readme).toMatch(/ClamAV|CDR/i);
  });

  it("documents single-author / no external PRs", () => {
    expect(readme).toMatch(/External pull requests are not accepted/i);
  });
});

describe("README rules table sync", () => {
  it("matches RULES via scripts/rules-table.mjs", async () => {
    // @ts-expect-error plain JS helper without type declarations
    const { renderReadme } = await import("../scripts/rules-table.mjs");
    expect(renderReadme(readme, RULES)).toBe(readme);
    expect(readme).toContain("<!-- rules-table:begin -->");
    expect(Object.keys(RULES).length).toBe(90);
  });
});

describe("rules documentation consistency", () => {
  it("every rule id is a stable SCREAMING_SNAKE name", () => {
    for (const id of Object.keys(RULES)) expect(id).toMatch(/^[A-Z][A-Z0-9_]+$/);
  });

  it("severities are the five documented levels", () => {
    expect([...SEVERITIES]).toEqual(["info", "low", "medium", "high", "critical"]);
  });

  it("reference URL list is non-empty", () => {
    expect(REFERENCE_URLS.length).toBeGreaterThan(20);
  });
});
