import { describe, expect, it } from "vitest";
import { FileSentinelError, RULES, SEVERITIES, scan, scanSync } from "../src/index.js";
import { REFERENCE_URLS } from "../src/rules.js";
import { applyPolicy, verdictOf } from "../src/scan.js";

describe("scanSync", () => {
  it("scans a clean SVG", () => {
    const r = scanSync(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>'), { filename: "a.svg" });
    expect(r.verdict).toBe("clean");
    expect(r.detectedType.format).toBe("svg");
    expect(r.stats.bytes).toBeGreaterThan(0);
  });

  it("accepts Buffer, ArrayBuffer and views", () => {
    const u8 = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(scanSync(u8).detectedType.format).toBe("png");
    expect(scanSync(u8.buffer).detectedType.format).toBe("png");
    expect(scanSync(u8.subarray(0)).detectedType.format).toBe("png");
  });

  it("throws FileSentinelError for bad input", () => {
    expect(() => scanSync("nope" as never)).toThrow(FileSentinelError);
    expect(() => scanSync(new Uint8Array(0), { limits: { maxBytes: -1 } as never })).toThrow(FileSentinelError);
    expect(() => scanSync(new Uint8Array(0), { policy: { ignore: ["NOPE"] } as never })).toThrow(FileSentinelError);
  });

  it("never throws on hostile content", () => {
    const junk = new Uint8Array(4096);
    for (let i = 0; i < junk.length; i++) junk[i] = i * 17;
    expect(() => scanSync(junk)).not.toThrow();
    expect(scanSync(new Uint8Array([0xff, 0xff, 0xff])).verdict).not.toBe("error");
  });

  it("respects maxBytes truncation", () => {
    const r = scanSync(new Uint8Array(1000).fill(0x41), { filename: "a.txt", limits: { maxBytes: 100 } });
    expect(r.truncated).toBe(true);
    expect(r.limitsHit).toContain("maxBytes");
  });

  it("applies policy", () => {
    const bytes = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>');
    const full = scanSync(bytes, { filename: "a.svg" });
    expect(full.findings.some((f) => f.id === "SVG_SCRIPT")).toBe(true);
    const filtered = scanSync(bytes, { filename: "a.svg", policy: { ignore: ["SVG_SCRIPT"] } });
    expect(filtered.findings.every((f) => f.id !== "SVG_SCRIPT")).toBe(true);
    const bumped = scanSync(bytes, { filename: "a.svg", policy: { severity: { SVG_SCRIPT: "critical" } } });
    expect(bumped.findings.find((f) => f.id === "SVG_SCRIPT")?.severity).toBe("critical");
    const min = scanSync(bytes, { filename: "a.svg", policy: { minSeverity: "critical" } });
    expect(min.findings).toHaveLength(0);
  });
});

describe("scan (async)", () => {
  it("wraps scanSync", async () => {
    const r = await scan(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]));
    expect(r.detectedType.format).toBe("pdf");
  });

  it("accepts a Blob", async () => {
    const r = await scan(new Blob([new Uint8Array([0x50, 0x4b, 0x05, 0x06])]));
    expect(r.detectedType.format).toBe("zip");
  });
});

describe("rules catalogue", () => {
  it("every rule has severity, title, description and references (except SCAN_ERROR)", () => {
    for (const [id, r] of Object.entries(RULES)) {
      expect(SEVERITIES.includes(r.severity), id).toBe(true);
      expect(r.title.length).toBeGreaterThan(3);
      expect(r.description.length).toBeGreaterThan(10);
      if (id !== "SCAN_ERROR") expect(r.references.length, id).toBeGreaterThan(0);
    }
  });

  it("reference URLs are absolute https", () => {
    for (const u of REFERENCE_URLS) {
      expect(u.startsWith("https://"), u).toBe(true);
    }
  });
});

describe("verdict and policy helpers", () => {
  it("verdictOf", () => {
    expect(verdictOf([], false)).toBe("clean");
    expect(verdictOf([{ severity: "info" } as never], false)).toBe("clean");
    expect(verdictOf([{ severity: "low" } as never], false)).toBe("suspicious");
    expect(verdictOf([{ severity: "high" } as never], false)).toBe("malicious-indicators");
    expect(verdictOf([], true)).toBe("error");
  });

  it("applyPolicy", () => {
    const f = [{ id: "A", severity: "low" as const, title: "", description: "", location: { path: [] }, references: [] }];
    expect(applyPolicy(f, { ignore: ["A"] })).toHaveLength(0);
    expect(applyPolicy(f, { minSeverity: "high" })).toHaveLength(0);
    expect(applyPolicy(f, { severity: { A: "critical" } })[0]?.severity).toBe("critical");
  });
});
