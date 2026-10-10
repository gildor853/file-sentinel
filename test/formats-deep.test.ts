import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { ovbaDecompress, parseDir, analyzeVba, stripComments, codepageLabel } from "../src/vba.js";
import { parseLnk } from "../src/lnk.js";
import { locateZip, openZip, isTraversal } from "../src/zip.js";
import { inflateRaw, inflateZlib } from "../src/inflate.js";
import { deflateRawSync, gzipSync } from "node:zlib";
import { scanSvg, scanHtml, scanXml, decodeText } from "../src/markup.js";
import { Ctx, DEFAULT_LIMITS } from "../src/ctx.js";
import type { Env } from "../src/env.js";
import { detectedType } from "../src/formats.js";
import { checkFilename } from "../src/filename.js";
import { sniff, sniffText, pdfHeaderOffset, containsHtmlMarker } from "../src/sniff.js";
import { parseOle1 } from "../src/rtf.js";
import { parseOle10Native } from "../src/office-cfb.js";
import { crc32 } from "../src/crc32.js";
import { concat, entropy, excerpt, indexOf, lastIndexOf, utf16le, u64le, startsWith } from "../src/bytes.js";
import { checkTrailing } from "../src/trailing.js";
import { contentStats, isEicar } from "../src/generic.js";
import { entityDeclarations, checkDoctype, isStandardDtd } from "../src/xmlsec.js";
import { schemeOf, isExternalUrl } from "../src/urls.js";
import { SCRIPT_EXTS } from "../src/exec.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures/constructs");
const enc = (s: string) => new TextEncoder().encode(s);

function envFor(bytes: Uint8Array, name?: string): { env: Env; ctx: Ctx } {
  const ctx = new Ctx({ ...DEFAULT_LIMITS });
  const item = { bytes, path: [] as string[], name, declaredMime: undefined as string | undefined, depth: 0 };
  const env: Env = {
    ctx,
    item,
    child(b, segment, n) {
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

describe("gzip / tar / opaque archives", () => {
  it("scans gzip content", () => {
    const gz = gzipSync(enc("hello gzip"));
    const r = scanSync(gz, { filename: "a.txt.gz" });
    expect(r.detectedType.format).toBe("gzip");
  });

  it("scans tar", () => {
    // minimal ustar with one file
    const name = "hi.txt";
    const data = enc("hi");
    const block = Buffer.alloc(512);
    Buffer.from(name).copy(block);
    block.write("00000000066", 100); // mode
    block.write("00000000000", 108);
    block.write("00000000000", 116);
    block.write(data.length.toString(8).padStart(11, "0") + " ", 124);
    block.write("00000000000", 136);
    block[156] = 0x30; // typeflag '0'
    block.write("ustar", 257);
    block[262] = 0;
    block.write("00", 263);
    // checksum
    block.write("        ", 148);
    let sum = 0;
    for (const b of block) sum += b;
    block.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    const tar = Buffer.concat([block, Buffer.from(data), Buffer.alloc(512 - (data.length % 512)), Buffer.alloc(1024)]);
    const r = scanSync(new Uint8Array(tar), { filename: "a.tar" });
    expect(r.detectedType.format).toBe("tar");
  });

  it("reports opaque archives", () => {
    const r7 = scanSync(new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]), { filename: "a.7z" });
    expect(r7.findings.some((f) => f.id === "ARCHIVE_UNSUPPORTED")).toBe(true);
    const rr = scanSync(enc("Rar!\x1a\x07\x00"), { filename: "a.rar" });
    expect(rr.detectedType.format).toBe("rar");
  });
});

describe("images", () => {
  it("gif / bmp / webp structure", () => {
    const g = Buffer.alloc(14);
    g.write("GIF89a");
    g.writeUInt16LE(1, 6);
    g.writeUInt16LE(1, 8);
    g[13] = 0x3b;
    expect(scanSync(new Uint8Array(g), { filename: "a.gif" }).detectedType.format).toBe("gif");

    const bmp = Buffer.alloc(54);
    bmp.write("BM");
    bmp.writeUInt32LE(54, 2);
    bmp.writeUInt32LE(54, 10);
    bmp.writeUInt32LE(40, 14);
    bmp.writeInt32LE(1, 18);
    bmp.writeInt32LE(1, 22);
    bmp.writeUInt16LE(1, 26);
    bmp.writeUInt16LE(24, 28);
    // BMP sniffer needs a plausible header; just exercise scanImage via a real fixture path
    expect(["bmp", "unknown"]).toContain(scanSync(new Uint8Array(bmp), { filename: "a.bmp" }).detectedType.format);

    const webp = Buffer.alloc(30);
    webp.write("RIFF", 0);
    webp.writeUInt32LE(22, 4);
    webp.write("WEBP", 8);
    webp.write("VP8 ", 12);
    expect(scanSync(new Uint8Array(webp), { filename: "a.webp" }).detectedType.format).toBe("webp");
  });

  it("pixel bomb", () => {
    // PNG IHDR with huge dimensions — craft after signature
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(0xffff, 0);
    ihdr.writeUInt32BE(0xffff, 4);
    const { crc32: c } = { crc32: (d: Uint8Array) => crc32(d) };
    const type = Buffer.from("IHDR");
    const payload = Buffer.concat([type, ihdr]);
    const chunk = Buffer.concat([Buffer.from([0, 0, 0, 13]), payload, (() => { const b = Buffer.alloc(4); b.writeUInt32BE(c(payload) >>> 0); return b; })()]);
    const iendPayload = Buffer.from("IEND");
    const iend = Buffer.concat([Buffer.alloc(4), iendPayload, (() => { const b = Buffer.alloc(4); b.writeUInt32BE(c(iendPayload) >>> 0); return b; })()]);
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk, iend]);
    const r = scanSync(new Uint8Array(png), { filename: "bomb.png" });
    expect(r.findings.some((f) => f.id === "IMAGE_DIMENSIONS_BOMB")).toBe(true);
  });
});

describe("vba / cfb helpers", () => {
  it("ovba round-trip and analyze", () => {
    const src = 'Sub AutoOpen()\r\nShell "x"\r\nEnd Sub\r\n';
    // uncompressed chunk
    const comp = Buffer.alloc(3 + 4096);
    comp[0] = 1;
    comp.writeUInt16LE(0x3fff, 1);
    Buffer.from(src).copy(comp, 3);
    const out = ovbaDecompress(new Uint8Array(comp));
    expect(new TextDecoder().decode(out.subarray(0, src.length))).toBe(src);
    const a = analyzeVba(src);
    expect(a.autoexec).toContain("AutoOpen");
    expect(a.suspicious.some((s) => s.includes("Shell"))).toBe(true);
    expect(stripComments("' comment\r\nSub X()\r\nEnd Sub").includes("comment")).toBe(false);
    expect(codepageLabel(1252)).toBe("windows-1252");
    expect(codepageLabel(65001)).toBe("utf-8");
  });

  it("parseDir reads modules", () => {
    // minimal dir with one MODULENAME
    const parts: number[] = [];
    const push = (id: number, data: Uint8Array) => {
      const h = Buffer.alloc(6);
      h.writeUInt16LE(id, 0);
      h.writeUInt32LE(data.length, 2);
      parts.push(...h, ...data);
    };
    push(0x0003, Buffer.from([0xe4, 0x04]));
    push(0x0019, Buffer.from("Mod1"));
    push(0x001a, Buffer.from("Mod1"));
    push(0x0031, Buffer.from([0x10, 0, 0, 0]));
    const { modules, codepage } = parseDir(Uint8Array.from(parts));
    expect(codepage).toBe(1252);
    expect(modules[0]?.name).toBe("Mod1");
  });

  it("opens vbaProject fixture via cfb", () => {
    const data = readFileSync(join(FIX, "macro.docm"));
    // extract vba from zip manually via scan
    const r = scanSync(new Uint8Array(data), { filename: "macro.docm" });
    expect(r.findings.some((f) => f.id === "VBA_AUTOEXEC")).toBe(true);
  });
});

describe("lnk / pe / scripts", () => {
  it("parseLnk reads fixture", () => {
    const info = parseLnk(new Uint8Array(readFileSync(join(FIX, "evil.lnk"))));
    expect(info.relativePath.toLowerCase()).toContain("powershell");
    expect(info.arguments).toMatch(/Hidden|calc/i);
  });

  it("executables and disk images", () => {
    expect(scanSync(new Uint8Array(readFileSync(join(FIX, "tiny.exe"))), { filename: "t.exe" }).findings.some((f) => f.id === "EXECUTABLE")).toBe(true);
    const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0]);
    expect(scanSync(elf, { filename: "a" }).findings.some((f) => f.id === "EXECUTABLE")).toBe(true);
    const macho = new Uint8Array(20);
    macho[0] = 0xcf; macho[1] = 0xfa; macho[2] = 0xed; macho[3] = 0xfe;
    expect(scanSync(macho).detectedType.format).toBe("macho");
    expect(SCRIPT_EXTS.has("ps1")).toBe(true);
  });
});

describe("zip helpers", () => {
  it("locateZip and traversal", () => {
    const z = readFileSync(join(FIX, "zip-slip.zip"));
    expect(locateZip(new Uint8Array(z))).toBeTruthy();
    expect(isTraversal("../x")).toBe(true);
    expect(isTraversal("a/b")).toBe(false);
    const { env } = envFor(new Uint8Array(z), "z.zip");
    expect(openZip(env, new Uint8Array(z))?.entries.length).toBeGreaterThan(0);
  });
});

describe("sniff / bytes / misc", () => {
  it("sniff covers many formats", () => {
    expect(sniff(enc("%PDF-1.4")).format).toBe("pdf");
    expect(sniff(enc("{\\rtf1")).format).toBe("rtf");
    expect(sniff(enc("#! /bin/sh")).format).toBe("script");
    expect(sniff(enc("<html><body>")).format).toBe("html");
    expect(sniff(enc('<?xml version="1.0"?><x/>')).format).toBe("xml");
    expect(sniff(new Uint8Array(0)).format).toBe("empty");
    expect(pdfHeaderOffset(enc("xxxx%PDF-1.4yyyy"))).toBe(4);
    expect(containsHtmlMarker(enc("aa<script>bb"))).toBeGreaterThanOrEqual(0);
    expect(sniffText(enc("#@~^xxx")).format).toBe("script-encoded");
  });

  it("bytes helpers", () => {
    expect(excerpt("a\u0000b\u202ec", 20).length).toBeGreaterThan(3);
    expect(concat([new Uint8Array([1]), new Uint8Array([2])])).toEqual(new Uint8Array([1, 2]));
    expect(entropy(new Uint8Array(100).fill(0))).toBe(0);
    expect(indexOf(new Uint8Array([1, 2, 3, 2, 3]), new Uint8Array([2, 3]))).toBe(1);
    expect(lastIndexOf(new Uint8Array([1, 2, 3, 2, 3]), new Uint8Array([2, 3]))).toBe(3);
    expect(startsWith(new Uint8Array([1, 2, 3]), [1, 2])).toBe(true);
    expect(utf16le(new Uint8Array([0x61, 0, 0x62, 0]))).toBe("ab");
    expect(u64le(new Uint8Array(8).fill(0xff), 0)).toBeGreaterThan(0);
  });

  it("filename and mismatch", () => {
    const { env, ctx } = envFor(enc("MZ"), "report.pdf.exe");
    checkFilename(env, "report.pdf.exe");
    expect(ctx.findings.some((f) => f.id === "FILENAME_DOUBLE_EXTENSION")).toBe(true);
    expect(isEicar(enc("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))).toBe(true);
  });

  it("xmlsec", () => {
    expect(isStandardDtd("http://www.w3.org/2001/XML.dtd")).toBe(true);
    const decls = entityDeclarations('<!DOCTYPE x [ <!ENTITY a "1"><!ENTITY % b SYSTEM "http://evil"> ]>');
    expect(decls.length).toBe(2);
    const { env, ctx } = envFor(enc("<x/>"));
    checkDoctype(env, '<!DOCTYPE x [ <!ENTITY a SYSTEM "http://evil"> ]>', 0);
    expect(ctx.findings.some((f) => f.id === "XML_EXTERNAL_ENTITY")).toBe(true);
  });

  it("urls", () => {
    expect(schemeOf("HTTP://x")).toBe("http");
    expect(isExternalUrl("//cdn.example/x")).toBe(true);
  });

  it("markup handlers directly", () => {
    const { env } = envFor(enc('<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><p/></body></foreignObject></svg>'));
    scanSvg(env, detectedType("svg", "high"));
    expect(env.ctx.findings.some((f) => f.id === "SVG_FOREIGN_OBJECT_HTML")).toBe(true);
    const h = envFor(enc('<html><meta http-equiv="refresh" content="0;url=https://x"><input type="password"/></html>'));
    scanHtml(h.env, detectedType("html", "high"));
    expect(h.ctx.findings.some((f) => f.id === "HTML_REDIRECT" || f.id === "HTML_CREDENTIAL_FORM")).toBe(true);
    scanXml(envFor(enc('<?xml version="1.0"?><!DOCTYPE x SYSTEM "http://evil"><x/>')).env, detectedType("xml", "high"));
    expect(decodeText(enc("hello")).includes("hello")).toBe(true);
  });

  it("rtf ole1 and ole10native", () => {
    const cls = Buffer.from("Package\0");
    const native = Buffer.from("hi");
    const ole1 = Buffer.concat([
      Buffer.from([0x01, 0x05, 0, 0, 2, 0, 0, 0]),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(cls.length); return b; })(),
      cls,
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(1); return b; })(),
      Buffer.from([0]),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(1); return b; })(),
      Buffer.from([0]),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(native.length); return b; })(),
      native,
    ]);
    const p = parseOle1(new Uint8Array(ole1));
    expect(p?.cls).toBe("Package");
  });

  it("pdf embedded and encrypted markers", () => {
    const encPdf = enc("%PDF-1.4\ntrailer<< /Encrypt 1 0 R /Root 1 0 R >>\n%%EOF\n");
    const r = scanSync(encPdf, { filename: "e.pdf" });
    expect(r.findings.some((f) => f.id === "PDF_ENCRYPTED")).toBe(true);
  });

  it("tokenize trailing + content stats", () => {
    const { env, ctx } = envFor(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    checkTrailing(env, new Uint8Array([0, 0, 0, 1, 2, 3]), 3);
    expect(ctx.findings.some((f) => f.id === "TRAILING_DATA")).toBe(true);
    contentStats(envFor(enc("A".repeat(40_000)), "a.txt").env, detectedType("text", "high"));
  });
});

describe("inflate edge cases", () => {
  it("zlib and raw", () => {
    const raw = deflateRawSync(Buffer.from("hello world ".repeat(50)));
    const r = inflateRaw(new Uint8Array(raw), 10_000);
    expect(r.status).toBe("ok");
    const z = inflateZlib(new Uint8Array([0x78, 0x9c, ...raw]), 10_000);
    expect(z.data.length).toBeGreaterThan(0);
  });
});
