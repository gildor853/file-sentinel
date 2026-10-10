import { describe, expect, it, vi } from "vitest";
import { RULES, scanSync } from "../src/index.js";
import * as inflate from "../src/inflate.js";
import { hydrateRuleFixtures, RULE_FIXTURES } from "./helpers/rule-fixtures.js";

hydrateRuleFixtures();

describe("per-rule fixture matrix", () => {
  it("defines a positive and negative fixture for every rule", () => {
    const missing = Object.keys(RULES).filter((id) => !RULE_FIXTURES[id]);
    expect(missing, `missing fixtures: ${missing.join(", ")}`).toEqual([]);
    expect(Object.keys(RULE_FIXTURES).length).toBe(Object.keys(RULES).length);
  });

  for (const id of Object.keys(RULES).sort()) {
    describe(id, () => {
      it("positive fixture triggers the rule", () => {
        if (id === "SCAN_ERROR") {
          const spy = vi.spyOn(inflate, "inflateZlib").mockImplementationOnce(() => {
            throw new Error("injected failure for SCAN_ERROR");
          });
          // PDF with a FlateDecode stream so inflateZlib is called
          const bytes = new TextEncoder().encode(
            "%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n3 0 obj<< /Type /Page /Parent 2 0 R >>endobj\n4 0 obj<< /Type /EmbeddedFile /Filter /FlateDecode /Length 5 >>stream\nxxxxx\nendstream\nendobj\ntrailer<< /Root 1 0 R /Encrypt 1 0 R >>\n%%EOF\n",
          );
          // Without encrypt, decodeStream calls inflateZlib for EmbeddedFile
          const plain = new TextEncoder().encode(
            "%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(x) 4 0 R] >> >> >>endobj\n2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>endobj\n4 0 obj<< /Type /Filespec /F (x.bin) /EF << /F 5 0 R >> >>endobj\n5 0 obj<< /Type /EmbeddedFile /Filter /FlateDecode /Length 5 >>stream\nxxxxx\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n",
          );
          const r = scanSync(plain, { filename: "x.pdf" });
          spy.mockRestore();
          expect(r.findings.some((f) => f.id === "SCAN_ERROR") || r.verdict === "error").toBe(true);
          return;
        }
        const fix = RULE_FIXTURES[id]!.positive;
        const r = scanSync(fix.bytes, {
          filename: fix.name,
          ...(fix.mime ? { declaredMime: fix.mime } : {}),
          ...(fix.options?.limits ? { limits: fix.options.limits } : {}),
        });
        expect(r.findings.some((f) => f.id === id), `${id} not in [${r.findings.map((f) => f.id).join(", ")}] (${fix.name})`).toBe(true);
      });

      it("negative near-miss does not trigger the rule", () => {
        if (id === "SCAN_ERROR") {
          const r = scanSync(new TextEncoder().encode("hello"), { filename: "ok.txt" });
          expect(r.findings.some((f) => f.id === "SCAN_ERROR")).toBe(false);
          return;
        }
        const fix = RULE_FIXTURES[id]!.negative;
        const r = scanSync(fix.bytes, {
          filename: fix.name,
          ...(fix.mime ? { declaredMime: fix.mime } : {}),
          ...(fix.options?.limits ? { limits: fix.options.limits } : {}),
        });
        expect(r.findings.some((f) => f.id === id), `${id} unexpectedly in [${r.findings.map((f) => f.id).join(", ")}]`).toBe(false);
      });
    });
  }
});
