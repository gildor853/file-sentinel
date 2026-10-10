import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

describe("clean fixtures", () => {
  const dir = join(ROOT, "clean");
  for (const name of readdirSync(dir).sort()) {
    it(`${name} is clean`, () => {
      const r = scanSync(readFileSync(join(dir, name)), { filename: name });
      expect(r.verdict, `${name}: ${r.findings.map((f) => f.id).join(", ")}`).toBe("clean");
      expect(r.findings.every((f) => f.severity === "info")).toBe(true);
    });
  }
});

const EXPECTED: Record<string, string[]> = {
  "svg-script.svg": ["SVG_SCRIPT"],
  "svg-handler.svg": ["SVG_SCRIPT_URL", "SVG_EVENT_HANDLER"],
  "svg-xxe.svg": ["XML_EXTERNAL_ENTITY"],
  "html-smuggle.html": ["HTML_SMUGGLING"],
  "html-hta.html": ["HTML_HTA"],
  "pdf-js.pdf": ["PDF_JAVASCRIPT", "PDF_OPEN_ACTION"],
  "pdf-launch.pdf": ["PDF_LAUNCH"],
  "pdf-obfuscated.pdf": ["PDF_OBFUSCATED_NAME", "PDF_JAVASCRIPT"],
  "zip-slip.zip": ["ARCHIVE_PATH_TRAVERSAL"],
  "slip.tar": ["ARCHIVE_PATH_TRAVERSAL"],
  "macro.doc": ["OFFICE_VBA_MACROS", "VBA_AUTOEXEC"],
  "xlm.xls": ["XLM_MACRO_SHEET", "XLM_AUTO_OPEN"],
  "zip-bomb.zip": ["ARCHIVE_BOMB"],
  "zip-nested.zip": ["ARCHIVE_NESTED"],
  "eicar.com": ["EICAR_TEST_FILE"],
  "polyglot.jpg": ["POLYGLOT"],
  "png-script.png": ["IMAGE_EMBEDDED_CODE"],
  "dde.docx": ["OFFICE_DDE"],
  "remote-template.docx": ["OOXML_REMOTE_TEMPLATE"],
  "macro.docm": ["OFFICE_VBA_MACROS", "VBA_AUTOEXEC"],
  "rtf-equation.rtf": ["OLE_EQUATION_EDITOR", "RTF_OLE_OBJECT"],
  "rtf-template.rtf": ["RTF_REMOTE_TEMPLATE"],
  "evil.lnk": ["LNK_FILE", "LNK_SUSPICIOUS_COMMAND"],
  "tiny.exe": ["EXECUTABLE"],
  "script.ps1": ["SCRIPT_FILE"],
  "script.vbs": ["SCRIPT_FILE"],
  "encoded.jse": ["SCRIPT_ENCODED"],
  "invoice.pdf.exe": ["FILENAME_DOUBLE_EXTENSION", "EXECUTABLE"],
};

describe("gif fixture", () => {
  it("tiny.gif is clean gif", () => {
    const r = scanSync(readFileSync(join(ROOT, "constructs/tiny.gif")), { filename: "tiny.gif" });
    expect(r.detectedType.format).toBe("gif");
    expect(r.verdict).toBe("clean");
  });
});

describe("construct fixtures", () => {
  const dir = join(ROOT, "constructs");
  for (const [name, ids] of Object.entries(EXPECTED)) {
    it(`${name} reports ${ids.join(", ")}`, () => {
      const r = scanSync(readFileSync(join(dir, name)), { filename: name });
      const got = new Set(r.findings.map((f) => f.id));
      for (const id of ids) expect(got.has(id), `${name} missing ${id}; got ${[...got]}`).toBe(true);
    });
  }

  it("RTL override filename", () => {
    const name = "invoice\u202efdp.exe";
    const r = scanSync(readFileSync(join(dir, name)), { filename: name });
    expect(r.findings.some((f) => f.id === "FILENAME_BIDI_CONTROL")).toBe(true);
  });
});
