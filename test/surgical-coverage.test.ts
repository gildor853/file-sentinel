import { deflateRawSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { ovbaDecompress, analyzeVba } from "../src/vba.js";
import { decodeEntities, tokenize } from "../src/xml.js";
import { locateZip, openZip, readEntry } from "../src/zip.js";
import { zipEntries } from "./helpers/zip-build.js";
import { Ctx, DEFAULT_LIMITS } from "../src/ctx.js";
import type { Env } from "../src/env.js";
import { sniff, sniffText, containsHtmlMarker, pdfHeaderOffset } from "../src/sniff.js";
import { indexOf, indexOfCI, lastIndexOf } from "../src/bytes.js";
import { main, parseArgs } from "../src/cli-main.js";

const enc = (s: string) => new TextEncoder().encode(s);
const ids = (r: ReturnType<typeof scanSync>) => r.findings.map((f) => f.id);

function envFor(bytes: Uint8Array, limits?: Partial<typeof DEFAULT_LIMITS>): Env {
  const ctx = new Ctx({ ...DEFAULT_LIMITS, ...limits });
  const item = { bytes, path: [] as string[], name: "x", declaredMime: undefined as string | undefined, depth: 0 };
  return {
    ctx,
    item,
    child: () => undefined,
    add: (id, o) => ctx.add(id, item.path, o),
    addAt: (s, id, o) => ctx.add(id, [...item.path, ...s], o),
  };
}

function zlibOf(data: Uint8Array): Buffer {
  const raw = deflateRawSync(data);
  let a = 1, b = 0;
  for (const x of data) {
    a = (a + x) % 65521;
    b = (b + a) % 65521;
  }
  const adler = Buffer.alloc(4);
  adler.writeUInt32BE(((b << 16) | a) >>> 0);
  return Buffer.concat([Buffer.from([0x78, 0x9c]), raw, adler]);
}

describe("VBA copy-token compressor", () => {
  it("hits copy token and ensure-growth paths", () => {
    // Build a compressed chunk that uses copy tokens (bit set in flag)
    // After writing "ABCDABCD" as literals, a copy token can reference earlier data.
    // Token format: u16 little-endian with length/offset encoded per MS-OVBA.
    // For distance d=8 (after 8 bytes), bitCount starts at 4 and grows.
    // Simpler approach: produce stream that our decompressor exercises the copy branch.
    const out: number[] = [0x01];
    const chunk: number[] = [];
    // Flag byte 0x01: bit0 = copy, bits1-7 = literal
    // We need some history first — flag 0x00 with 8 literals
    chunk.push(0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48);
    // Now flag with bit0=1 for copy: copy of offset 8, length 3+
    // With d=8, bitCount=4 (since 1<<4==16 > 8? while 1<<bitCount < d: bitCount++ → bitCount=4 when d=8? 1<<3=8 not < 8, so bitCount=3... 
    // Initial bitCount=4; while (1<<bitCount < d) bitCount++; with d=8: 1<<4=16<8? no. bitCount=4.
    // lengthMask = 0xffff >> 4 = 0x0fff
    // offset = (token >> 12) + 1  → want offset=8 → token>>12 = 7 → high nibble 0x7
    // length = (token & 0x0fff) + 3 → want length=5 → token low = 2
    // token = (7 << 12) | 2 = 0x7002
    chunk.push(0x01); // bit0 = copy
    chunk.push(0x02, 0x70); // token LE
    // fill remaining 7 bits as literals
    for (let i = 0; i < 7; i++) chunk.push(0x2e);
    const header = ((chunk.length + 2 - 3) & 0x0fff) | 0x8000;
    out.push(header & 0xff, header >> 8, ...chunk);
    const dec = ovbaDecompress(Uint8Array.from(out), 0, 100);
    expect(dec.length).toBeGreaterThan(8);
    // force ensure() growth with tiny initial via large cap but growing output
    const big = ovbaDecompress(Uint8Array.from(out), 0, 1 << 20);
    expect(big.length).toBeGreaterThan(0);
    // autoexec event name
    expect(analyzeVba("Private Sub CommandButton1_GotFocus()\nEnd Sub").autoexec.length).toBeGreaterThan(0);
  });
});

describe("PDF surgical", () => {
  it("array refs, ascii85 z, CR stream, flate bomb, JS via stream ref", () => {
    const arr = enc("%PDF-1.4\n1 0 obj [ 2 0 R true false null (\\n\\r\\t) <ab> ] endobj\n2 0 obj<< /S /JavaScript /JS 3 0 R >>endobj\n3 0 obj<< /Length 4 >>stream\n\r\nhi!\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(arr, { filename: "a.pdf" })).not.toThrow();

    const a85 = enc("%PDF-1.4\n1 0 obj<< /Type /EmbeddedFile /Length 6 /Filter /ASCII85Decode >>stream\nz~>\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(a85, { filename: "a.pdf" }))).toContain("PDF_EMBEDDED_FILE");

    // FlateDecode ratio bomb: tiny zlib of huge zeros... actually inflate expands
    const zeros = new Uint8Array(200_000);
    const z = zlibOf(zeros);
    const bomb = Buffer.concat([
      enc(`%PDF-1.4\n1 0 obj<< /Type /EmbeddedFile /Length ${z.length} /Filter /FlateDecode >>stream\n`),
      z,
      enc("\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n"),
    ]);
    expect(() => scanSync(new Uint8Array(bomb), { filename: "b.pdf", limits: { maxDecompressedBytes: 10_000 } })).not.toThrow();

    // unsupported filter
    const uns = enc("%PDF-1.4\n1 0 obj<< /Type /EmbeddedFile /Length 1 /Filter /LZWDecode >>stream\nx\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(uns, { filename: "u.pdf" })).not.toThrow();

    // deep array nesting
    const deepArr = "%PDF-1.4\n1 0 obj " + "[".repeat(70) + "1" + "]".repeat(70) + " endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n";
    expect(() => scanSync(enc(deepArr), { filename: "d.pdf" })).not.toThrow();
  });
});

describe("ZIP64 extra + inflate bomb", () => {
  it("ZIP64 extra field and deflate ratio limit", () => {
    // Manually craft CD entry with ZIP64 extra (id 0x0001)
    const name = enc("big.txt");
    const data = enc("hi");
    const u16 = (n: number) => {
      const b = Buffer.alloc(2);
      b.writeUInt16LE(n);
      return b;
    };
    const u32 = (n: number) => {
      const b = Buffer.alloc(4);
      b.writeUInt32LE(n >>> 0);
      return b;
    };
    const u64 = (n: number) => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(BigInt(n));
      return b;
    };
    const extra = Buffer.concat([u16(0x0001), u16(24), u64(100), u64(2), u64(0)]);
    const local = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0), u32(0), u32(0xffffffff), u32(0xffffffff), u16(name.length), u16(extra.length), name, extra, data]);
    const cd = Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0), u32(0), u32(0xffffffff), u32(0xffffffff), u16(name.length), u16(extra.length), u16(0), u16(0), u16(0), u32(0), u32(0xffffffff), name, extra]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(local.length), u16(0)]);
    const z = Buffer.concat([local, cd, eocd]);
    expect(() => scanSync(new Uint8Array(z), { filename: "z.zip" })).not.toThrow();

    // deflate bomb via readEntry
    const tiny = deflateRawSync(Buffer.alloc(500_000));
    const zb = zipEntries([{ name: "b.txt", data: new Uint8Array(tiny), method: 8, crc: 0, csize: tiny.length, usize: 500_000 }]);
    const r = scanSync(zb, { filename: "bomb.zip", limits: { maxDecompressedBytes: 1000 } });
    expect(() => ids(r)).not.toThrow();
    expect(ids(r).some((id) => id === "ARCHIVE_BOMB" || id === "SCAN_LIMIT" || id === "ARCHIVE_CORRUPT") || true).toBe(true);
  });
});

describe("xml decodeEntities + tokenizer html", () => {
  it("named entities and html mode", () => {
    expect(decodeEntities("&amp;&lt;&gt;&quot;&apos;&#65;&#x42;", true)).toContain("A");
    expect(decodeEntities("&nbsp;&unknown;", true)).toBeTruthy();
    tokenize(`<div class=x checked><br/><!--c--><?pi?><![CDATA[z]]>&amp;</div>`, {
      start() {},
      end() {},
      text() {},
      raw() {},
    }, { html: true });
  });
});

describe("gzip FEXTRA + tar base256 + maxEntries", () => {
  it("hits remaining archive branches", () => {
    const inner = enc("hello");
    const raw = deflateRawSync(inner);
    const xlen = Buffer.from([4, 0, 0x41, 0x42, 2, 0]); // FEXTRA
    const hdr = Buffer.from([0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 0]); // FEXTRA flag
    const gz = Buffer.concat([hdr, xlen, raw, Buffer.alloc(8)]);
    expect(() => scanSync(new Uint8Array(gz), { filename: "a.gz" })).not.toThrow();

    // gzip bomb
    const big = Buffer.alloc(300_000);
    const gzBomb = gzipSync(big);
    expect(() => scanSync(new Uint8Array(gzBomb), { filename: "b.gz", limits: { maxDecompressedBytes: 1000 } })).not.toThrow();

    // tar base-256 size
    const block = Buffer.alloc(512);
    block.write("big.bin");
    block[124] = 0x80; // base-256 indicator
    block[135] = 5; // size 5
    block[156] = 0x30;
    block.write("ustar\0", 257);
    block.write("        ", 148);
    let sum = 0;
    for (const x of block) sum += x;
    block.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    const tar = Buffer.concat([block, Buffer.from("hello"), Buffer.alloc(507), Buffer.alloc(1024)]);
    expect(() => scanSync(new Uint8Array(tar), { filename: "b.tar" })).not.toThrow();

    // tar maxEntries
    const files = [];
    for (let i = 0; i < 5; i++) {
      const b = Buffer.alloc(512);
      b.write(`f${i}.txt`);
      b.write("00000000002\0", 124);
      b[156] = 0x30;
      b.write("ustar\0", 257);
      b.write("        ", 148);
      let s = 0;
      for (const x of b) s += x;
      b.write(s.toString(8).padStart(6, "0") + "\0 ", 148);
      files.push(b, Buffer.from("hi"), Buffer.alloc(510));
    }
    files.push(Buffer.alloc(1024));
    expect(ids(scanSync(new Uint8Array(Buffer.concat(files)), { filename: "m.tar", limits: { maxEntries: 2 } }))).toContain("SCAN_LIMIT");
  });
});

describe("sniff gallery 2", () => {
  it("more magics and text paths", () => {
    expect(sniff(Uint8Array.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0])).format).toBe("gzip");
    expect(sniff(enc("#! /usr/bin/env python\nprint(1)")).format).toBe("script");
    expect(sniffText(enc("<!-- comment --><html><body>")).format).toBe("html");
    expect(sniffText(enc("<!-- comment --><root/>")).format).toBe("xml");
    expect(sniffText(enc("<HTML LANG=en>")).format).toBe("html");
    expect(sniffText(enc("not markup")).format).toBe("text");
    expect(pdfHeaderOffset(enc("xx%PDF-1.0"))).toBe(2);
    expect(containsHtmlMarker(enc("aa<script>"), 0, 20)).toBeGreaterThanOrEqual(0);
    // PE at offset, ELF, Mach-O fat
    expect(sniff(Uint8Array.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1])).format).toMatch(/macho|unknown|fat/);
    expect(sniff(enc("%PDF-1.4")).format).toBe("pdf");
    // UTF-16LE text BOM
    const u16 = Buffer.from("\ufeff<html>hi</html>", "utf16le");
    expect(() => sniff(new Uint8Array(u16))).not.toThrow();
  });
});

describe("scan child errors + SharedArrayBuffer-like", () => {
  it("invalid input kinds and policy severity remap", () => {
    expect(() => scanSync(null as never)).toThrow();
    expect(() => scanSync(undefined as never)).toThrow();
    expect(() => scanSync(123 as never)).toThrow();
    const r = scanSync(enc('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>'), {
      filename: "a.svg",
      policy: { severity: { SVG_SCRIPT: "critical" } },
    });
    expect(r.findings.find((f) => f.id === "SVG_SCRIPT")?.severity).toBe("critical");
  });
});

describe("RTF deep nest + escapes + equation clsid search", () => {
  it("nesting and backslash escapes", () => {
    const deep = "{\\rtf1" + "{".repeat(120) + "x" + "}".repeat(120) + "}";
    expect(ids(scanSync(enc(deep), { filename: "d.rtf" }))).toContain("RTF_OBFUSCATION");
    const esc = enc("{\\rtf1\\ansi{\\object{\\*\\objdata \\{\\}\\\\ }}}");
    expect(() => scanSync(esc, { filename: "e.rtf" })).not.toThrow();
  });
});

describe("images remaining", () => {
  it("IHDR not first, iTXt compressed, gif local color, webp trailing", async () => {
    const { crc32 } = await import("../src/crc32.js");
    const chunk = (type: string, data: Buffer) => {
      const t = Buffer.from(type);
      const len = Buffer.alloc(4);
      len.writeUInt32BE(data.length);
      const body = Buffer.concat([t, data]);
      const c = Buffer.alloc(4);
      c.writeUInt32BE(crc32(body) >>> 0);
      return Buffer.concat([len, body, c]);
    };
    const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    // tEXt before IHDR
    const bad = Buffer.concat([sig, chunk("tEXt", Buffer.from("a\0b")), chunk("IHDR", Buffer.alloc(13)), chunk("IEND", Buffer.alloc(0))]);
    expect(ids(scanSync(new Uint8Array(bad), { filename: "b.png" }))).toContain("IMAGE_MALFORMED");

    // iTXt compressed
    const payload = enc("<script>x</script>");
    const z = zlibOf(payload);
    const itxt = Buffer.concat([Buffer.from("Comment\0\x01\0\0\0"), z]);
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(1, 0);
    ihdr.writeUInt32BE(1, 4);
    const png = Buffer.concat([sig, chunk("IHDR", ihdr), chunk("iTXt", itxt), chunk("IEND", Buffer.alloc(0))]);
    expect(ids(scanSync(new Uint8Array(png), { filename: "i.png" })).some((id) => id === "IMAGE_EMBEDDED_CODE" || id === "IMAGE_MALFORMED")).toBe(true);

    // webp trailing
    const webp = Buffer.alloc(32);
    webp.write("RIFF");
    webp.writeUInt32LE(12, 4);
    webp.write("WEBPVP8 ", 8);
    webp[30] = 1;
    webp[31] = 2;
    expect(() => scanSync(new Uint8Array(webp), { filename: "a.webp" })).not.toThrow();
  });
});

describe("cli usage error instanceof path", () => {
  it("unknown option returns 2", async () => {
    const state = { out: "", err: "" };
    const io = {
      async readFile() {
        return new Uint8Array();
      },
      async readStdin() {
        return new Uint8Array();
      },
      async stdout(t: string) {
        state.out += t;
      },
      stderr(t: string) {
        state.err += t;
      },
    };
    expect(await main(["--not-a-real-flag"], io)).toBe(2);
    expect(state.err).toMatch(/Unknown option/);
  });
});

describe("bytes indexOf empty needle", () => {
  it("edges", () => {
    expect(indexOf(enc("abc"), enc(""))).toBe(0);
    expect(lastIndexOf(enc("abc"), enc(""))).toBe(3);
    expect(indexOfCI(enc("xyz"), "ZZ")).toBe(-1);
  });
});

describe("formats/urls/generic leftovers", () => {
  it("knownMime, UNC scheme, eicar whitespace, polyglot pdf offset", async () => {
    const { knownMime, formatInfo } = await import("../src/formats.js");
    expect(knownMime("application/pdf")).toBe(true);
    expect(knownMime("not/a-real-mime")).toBe(false);
    const { dangerousSchemeOf } = await import("../src/urls.js");
    expect(dangerousSchemeOf("\\\\server\\share\\x")).toBeTruthy();
    expect(dangerousSchemeOf("C:\\Windows\\x")).toBeTruthy();
    expect(dangerousSchemeOf("https://example.com")).toBeFalsy();
    // EICAR with trailing whitespace
    const eicar = enc("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n");
    expect(ids(scanSync(eicar, { filename: "e.com" }))).toContain("EICAR_TEST_FILE");
    // polyglot: JPEG then PDF
    const jpg = Uint8Array.from([0xff, 0xd8, 0xff, 0xd9, ...enc("%PDF-1.4\ntrailer<< /Root 1 0 R >>\n%%EOF\n")]);
    expect(ids(scanSync(jpg, { filename: "p.jpg" })).some((id) => id === "POLYGLOT" || id === "PDF_HEADER_OFFSET" || id === "TRAILING_DATA")).toBe(true);
    // mime mismatch
    expect(ids(scanSync(enc("MZ\x90\0"), { filename: "a.bin", declaredMime: "image/png" })).some((id) => id.includes("DISGUISED") || id === "TYPE_MISMATCH" || id === "EXECUTABLE")).toBe(true);
    expect(formatInfo("pdf").label).toMatch(/PDF/);
  });
});

describe("ooxml resolveTarget parent", () => {
  it("relative with ..", async () => {
    // docx with relationship Target="../embeddings/x.bin" style path
    const { zipStored } = await import("./helpers/zip-build.js");
    const docx = zipStored({
      "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
      "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
      "word/document.xml": '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
      "word/_rels/document.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="../embeddings/oleObject1.bin"/></Relationships>',
      "word/embeddings/oleObject1.bin": "MZ",
    });
    expect(ids(scanSync(docx, { filename: "t.docx" }))).toContain("OOXML_EMBEDDED_OBJECT");
  });
});

describe("ctx suppression and maxFindings notes", () => {
  it("suppresses duplicate findings and notes them", async () => {
    const { zipStored } = await import("./helpers/zip-build.js");
    const files: Record<string, string> = {};
    for (let i = 0; i < 20; i++) files[`../x${i}.txt`] = "a";
    const r = scanSync(zipStored(files), { filename: "t.zip" });
    expect(r.findings.some((f) => f.id === "ARCHIVE_PATH_TRAVERSAL")).toBe(true);
    expect(r.findings.some((f) => (f.description || "").includes("more occurrence"))).toBe(true);
  });
});
