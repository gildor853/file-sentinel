import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures/fp-clean");

describe("false-positive corpus", () => {
  it("0 findings above info on generated clean files", () => {
    const files = readdirSync(DIR).filter((n) => statSync(join(DIR, n)).isFile());
    expect(files.length).toBeGreaterThanOrEqual(15);
    let above = 0;
    const details: string[] = [];
    for (const name of files) {
      const r = scanSync(new Uint8Array(readFileSync(join(DIR, name))), { filename: name });
      const bad = r.findings.filter((f) => f.severity !== "info");
      if (bad.length) {
        above++;
        details.push(`${name}: ${bad.map((f) => f.id).join(",")}`);
      }
    }
    expect(details, `FP rate ${(above / files.length) * 100}%`).toEqual([]);
    expect(above / files.length).toBe(0);
  });
});
