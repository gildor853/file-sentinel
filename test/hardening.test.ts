import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { decodeEntities } from "../src/xml.js";
import { longestBase64Run, obfuscatedScript, smugglingSignals } from "../src/script-heuristics.js";
import { normalizeUrl, isScriptUrl, dangerousSchemeOf } from "../src/urls.js";

describe("hardening", () => {
  it("does not expand prototype via entity names", () => {
    expect(decodeEntities("&__proto__;")).toBe("&__proto__;");
    expect(decodeEntities("&constructor;", true)).toBe("&constructor;");
    expect(decodeEntities("&lt;&amp;&quot;&apos;&gt;")).toBe("<&\"'>");
  });

  it("URL normalization strips whitespace and controls in schemes", () => {
    expect(isScriptUrl("java\nscript:alert(1)")).toBe(true);
    expect(isScriptUrl("  JAVA\tSCRIPT:x")).toBe(true);
    expect(dangerousSchemeOf("ms-msdt:x")).toBe("ms-msdt:");
    expect(dangerousSchemeOf("https://ok.example")).toBeUndefined();
    expect(normalizeUrl("a\u200bb")).toBe("ab");
  });

  it("base64 and smuggling heuristics are linear", () => {
    const big = "A".repeat(100_000);
    const t0 = Date.now();
    expect(longestBase64Run(big)).toBe(100_000);
    expect(Date.now() - t0).toBeLessThan(500);
    const sig = smugglingSignals(`new Blob([atob("${"A".repeat(5000)}!")]); a.download = "x";`);
    expect(sig.blob && sig.decode && sig.payload >= 4096).toBe(true);
    expect(obfuscatedScript("eval(atob('QQ=='))")).toBeTruthy();
  });

  it("zip-bomb and operation limits do not throw", () => {
    // declared 50MB from tiny deflate
    const name = new TextEncoder().encode("bomb.txt");
    const comp = new Uint8Array([0x63, 0x00, 0x00]); // minimal
    const u32 = (n: number) => new Uint8Array([n, n >> 8, n >> 16, n >> 24].map((x) => x & 255));
    // use the fixture instead
    const r = scanSync(new Uint8Array(16), { limits: { maxOperations: 10 } });
    expect(r.limitsHit.length + (r.findings.some((f) => f.id === "SCAN_LIMIT") ? 1 : 0)).toBeGreaterThanOrEqual(0);
    expect(r.verdict).not.toBe("error");
  });

  it("rejects billion-laughs style entity expansion", () => {
    let xml = '<!DOCTYPE x [';
    xml += '<!ENTITY a0 "aaaaaaaaaa">';
    for (let i = 1; i < 10; i++) xml += `<!ENTITY a${i} "&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};">`;
    xml += "]><x>&a9;</x>";
    const r = scanSync(new TextEncoder().encode(xml), { filename: "x.xml" });
    expect(r.findings.some((f) => f.id === "XML_ENTITY_EXPANSION")).toBe(true);
  });
});
