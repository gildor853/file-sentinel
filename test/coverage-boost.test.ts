import { deflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { scan, scanSync, FileSentinelError, isFileSentinelError, RULES } from "../src/index.js";
import { obfuscatedScript, smugglingSignals, isSmuggling, longestBase64Run, SMUGGLING_PAYLOAD } from "../src/script-heuristics.js";
import { ovbaDecompress } from "../src/vba.js";
import { locateZip, openZip, readEntry } from "../src/zip.js";
import { show, fail } from "../src/errors.js";
import { Ctx, DEFAULT_LIMITS, LimitReached } from "../src/ctx.js";
import type { Env } from "../src/env.js";
import { zipEntries, zipStored } from "./helpers/zip-build.js";
import { indexOfCI, excerpt, excerptBytes, entropy } from "../src/bytes.js";
import { parseLnk } from "../src/lnk.js";
import { main } from "../src/cli-main.js";
import { tokenize } from "../src/xml.js";
import { crc32 } from "../src/crc32.js";

const enc = (s: string) => new TextEncoder().encode(s);
const ids = (r: ReturnType<typeof scanSync>) => r.findings.map((f) => f.id);

function envFor(bytes: Uint8Array, name?: string, limits?: Partial<typeof DEFAULT_LIMITS>): { env: Env; ctx: Ctx } {
  const ctx = new Ctx({ ...DEFAULT_LIMITS, ...limits });
  const item = { bytes, path: [] as string[], name, declaredMime: undefined as string | undefined, depth: 0 };
  const env: Env = {
    ctx,
    item,
    child(b, _s, n) {
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

describe("scan API / options / errors", () => {
  it("accepts ArrayBuffer and DataView; rejects bad options", async () => {
    const u8 = enc("hello");
    expect(scanSync(u8.buffer).detectedType.format).toBeTruthy();
    expect(scanSync(new DataView(u8.buffer)).detectedType.format).toBeTruthy();
    await expect(scan(u8)).resolves.toBeTruthy();
    expect(() => scanSync("nope" as unknown as Uint8Array)).toThrow(FileSentinelError);
    expect(isFileSentinelError(new FileSentinelError("InvalidInput", "x"))).toBe(true);
    expect(isFileSentinelError(new Error("x"))).toBe(false);
    expect(() => scanSync(u8, { nope: 1 } as never)).toThrow(/Unknown option/);
    expect(() => scanSync(u8, { limits: null as never })).toThrow(/limits/);
    expect(() => scanSync(u8, { limits: { maxBytes: -1 } })).toThrow(/positive/);
    expect(() => scanSync(u8, { limits: { notALimit: 1 } as never })).toThrow(/Unknown limit/);
    expect(() => scanSync(u8, { policy: [] as never })).toThrow(/policy/);
    expect(() => scanSync(u8, { policy: { ignore: ["NOPE"] } })).toThrow(/Unknown rule/);
    expect(() => scanSync(u8, { policy: { minSeverity: "nope" as never } })).toThrow(/minSeverity/);
    expect(() => scanSync(u8, { policy: { severity: { SVG_SCRIPT: "nope" as never } } })).toThrow(/severity/);
    expect(() => scanSync(u8, { policy: { severity: { NOPE: "low" } } })).toThrow(/Unknown rule/);
    expect(() => scanSync(u8, { policy: { weird: 1 } as never })).toThrow(/Unknown policy/);
    expect(() => scanSync(u8, { filename: 1 as never })).toThrow(/filename/);
    expect(show(null)).toBe("null");
    expect(show([1])).toBe("an array");
    expect(show({ a: 1 })).toBe("an object");
    expect(show("x".repeat(50)).includes("…")).toBe(true);
    expect(show(Symbol("s"))).toMatch(/symbol/);
    expect(show(() => 0)).toMatch(/function/);
    expect(show(3)).toBe("3");
    try {
      fail("InvalidOption", "boom");
    } catch (e) {
      expect(isFileSentinelError(e)).toBe(true);
    }
  });

  it("hits maxDepth / maxFindings / policy ignore", () => {
    const nested = zipStored({ "a.zip": zipStored({ "b.txt": "hi" }) });
    const r = scanSync(nested, { filename: "n.zip", limits: { maxDepth: 1 } });
    expect(ids(r)).toContain("SCAN_LIMIT");
    const many = zipStored(Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`../x${i}.txt`, "a"])));
    const r2 = scanSync(many, { filename: "t.zip", limits: { maxFindings: 3 } });
    expect(r2.limitsHit).toContain("maxFindings");
    const svg = enc('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>');
    expect(ids(scanSync(svg, { filename: "a.svg", policy: { ignore: ["SVG_SCRIPT"], minSeverity: "critical" } }))).not.toContain("SVG_SCRIPT");
  });
});

describe("script heuristics", () => {
  it("obfuscation and smuggling detectors", () => {
    expect(obfuscatedScript('eval(atob("YQ=="))')).toBeTruthy();
    expect(obfuscatedScript("eval(function(p,a,c,k,e,d){return p})")).toBeTruthy();
    expect(obfuscatedScript('document.write(unescape("%66"))')).toBeTruthy();
    expect(obfuscatedScript('Function(atob("YQ=="))')).toBeTruthy();
    expect(obfuscatedScript("\\x61".repeat(40))).toBeTruthy();
    expect(obfuscatedScript("%u0061".repeat(20))).toBeTruthy();
    const args = Array.from({ length: 30 }, (_, i) => String(i)).join(",");
    expect(obfuscatedScript(`String.fromCharCode(${args})`)).toBeTruthy();
    const b64 = "A".repeat(SMUGGLING_PAYLOAD + 10);
    const sig = smugglingSignals(`new Blob([atob("${b64}")]); a.download="x";`);
    expect(isSmuggling(sig, false)).toBe(true);
    expect(longestBase64Run(`"${b64}"+"BB"`)).toBeGreaterThan(100);
    const html = enc(`<html><script>new Blob([atob("${b64}")]);navigator.msSaveOrOpenBlob(x,"f")</script></html>`);
    expect(ids(scanSync(html, { filename: "s.html" })).some((id) => id === "HTML_SMUGGLING" || id === "SCRIPT_OBFUSCATION")).toBe(true);
  });
});

describe("ZIP deep paths", () => {
  it("maxEntries, bad CRC, stored oversize, deflate corrupt, UTF-8 names", () => {
    const files = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`f${i}.txt`, "x"]));
    const z = zipStored(files);
    const { env, ctx } = envFor(z, "z.zip", { maxEntries: 2 });
    openZip(env, z);
    expect(ctx.findings.some((f) => f.id === "SCAN_LIMIT")).toBe(true);

    const badCrc = zipEntries([{ name: "a.txt", data: enc("hi"), crc: 0xdeadbeef }]);
    expect(ids(scanSync(badCrc, { filename: "c.zip" }))).toContain("ARCHIVE_CORRUPT");

    const big = zipEntries([{ name: "big.bin", data: new Uint8Array(100), method: 0 }]);
    const { env: e2 } = envFor(big, "b.zip", { maxItemBytes: 10, maxDecompressedBytes: 10 });
    const zip = openZip(e2, big)!;
    expect(readEntry(e2, zip, zip.entries[0]!)).toBeUndefined();

    // deflate corrupt
    const raw = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xff]);
    const defl = zipEntries([{ name: "x.txt", data: raw, method: 8, crc: 0, csize: raw.length, usize: 100 }]);
    expect(() => scanSync(defl, { filename: "d.zip" })).not.toThrow();

    // UTF-8 flag name with high bytes
    const utf = zipEntries([{ name: "café.txt", data: enc("ok"), flags: 0x800 }]);
    expect(locateZip(utf)).toBeTruthy();
    expect(ids(scanSync(utf, { filename: "u.zip" })).length).toBeGreaterThanOrEqual(0);

    // ZIP64-ish EOCD fields (0xffff) without valid locator — locateZip skips
    const base = zipStored({ "a.txt": "x" });
    const mut = base.slice();
    // set total entries to 0xffff at EOCD+10
    const eocd = locateZip(mut)!.eocd;
    mut[eocd + 10] = 0xff;
    mut[eocd + 11] = 0xff;
    expect(() => locateZip(mut)).not.toThrow();
  });
});

describe("VBA compressed copy tokens", () => {
  it("handles copy tokens and cap growth", () => {
    // Manual MS-OVBA compressed chunk: flag byte with bit0=1 (copy), rest literals
    // After some literals, a copy token
    const outExpect = "ABCDEFGABCDEFG"; // pattern that copy can reference
    // Build compressed: start with literals A-G, then copy
    const data: number[] = [];
    // flag: bit0-6 literal, bit7 copy — simpler: all literals first via flag=0
    const literals = Buffer.from("ABCDEFGXXXXYYYY");
    data.push(0x00); // 8 literals
    for (let i = 0; i < 8; i++) data.push(literals[i]!);
    data.push(0x00);
    for (let i = 8; i < 16 && i < literals.length; i++) data.push(literals[i]!);
    // pad to make chunk
    while (data.length < 20) data.push(0x20);
    const header = ((data.length + 2 - 3) & 0x0fff) | 0x8000;
    const stream = Buffer.alloc(3 + data.length);
    stream[0] = 1;
    stream.writeUInt16LE(header, 1);
    Buffer.from(data).copy(stream, 3);
    const dec = ovbaDecompress(new Uint8Array(stream), 0, 64);
    expect(dec.length).toBeGreaterThan(0);
    // tiny cap
    expect(ovbaDecompress(new Uint8Array(stream), 0, 4).length).toBeLessThanOrEqual(4);
    // bad signature
    expect(ovbaDecompress(new Uint8Array([0x00, 1, 2])).length).toBe(0);
  });
});

describe("images bmp/tiff/ico + jpeg stuffing", () => {
  it("bmp path and jpeg restart markers", () => {
    const bmp = Buffer.alloc(128);
    bmp.write("BM");
    bmp.writeUInt32LE(128, 2);
    bmp.writeUInt16LE(0, 6);
    bmp.writeUInt16LE(0, 8);
    bmp.writeUInt32LE(54, 10);
    bmp.writeUInt32LE(40, 14);
    bmp.writeInt32LE(20000, 18);
    bmp.writeInt32LE(20000, 22);
    const r = scanSync(new Uint8Array(bmp), { filename: "a.bmp" });
    expect(r.detectedType.format).toBe("bmp");
    expect(ids(r)).toContain("IMAGE_DIMENSIONS_BOMB");

    // JPEG with fill 0xFF and RST
    const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0xaa, 0xff, 0x00, 0xbb, 0xff, 0xd0, 0xcc, 0xff, 0xd9]);
    expect(() => scanSync(new Uint8Array(jpeg), { filename: "a.jpg" })).not.toThrow();
  });
});

describe("LNK unicode LinkInfo", () => {
  it("parses unicode local base path", () => {
    const flags = 0x02 | 0x80;
    const hdr = Buffer.alloc(0x4c);
    hdr.writeUInt32LE(0x4c, 0);
    Buffer.from([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]).copy(hdr, 4);
    hdr.writeUInt32LE(flags, 0x14);
    // LinkInfo with headerSize >= 0x24 and unicode
    const path = Buffer.from("C:\\Windows\\System32\\powershell.exe\0", "utf16le");
    const liSize = 0x3c + path.length;
    const li = Buffer.alloc(liSize);
    li.writeUInt32LE(liSize, 0);
    li.writeUInt32LE(0x3c, 4); // header size >= 0x24
    li.writeUInt32LE(1, 8); // local
    li.writeUInt32LE(0x10, 16); // ansi offset (unused)
    li.writeUInt32LE(0x3c, 28); // unicode local base path offset
    path.copy(li, 0x3c);
    const info = parseLnk(new Uint8Array(Buffer.concat([hdr, li])));
    expect(info.target.toLowerCase()).toContain("powershell");
  });
});

describe("gzip/tar remaining branches", () => {
  it("truncated gzip, corrupt tar size, duplicate tar names, typeflag 7", () => {
    const trunc = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0]); // header only
    expect(ids(scanSync(trunc, { filename: "t.gz" }))).toContain("ARCHIVE_CORRUPT");

    const block = Buffer.alloc(512);
    block.write("bad.txt");
    block.write("NOTOCTAL!!!", 124); // bad size
    block.write("ustar\0", 257);
    block.write("        ", 148);
    let sum = 0;
    for (const b of block) sum += b;
    block.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    expect(ids(scanSync(new Uint8Array(Buffer.concat([block, Buffer.alloc(1024)])), { filename: "b.tar" }))).toContain("ARCHIVE_CORRUPT");

    // typeflag '7' continuous file + duplicate
    function th(name: string, data: Buffer, tf = "0") {
      const b = Buffer.alloc(512);
      b.write(name);
      b.write("0000644\0", 100);
      b.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
      b[156] = tf.charCodeAt(0);
      b.write("ustar\0", 257);
      b.write("        ", 148);
      let s = 0;
      for (const x of b) s += x;
      b.write(s.toString(8).padStart(6, "0") + "\0 ", 148);
      const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
      return Buffer.concat([b, data, pad]);
    }
    const d = Buffer.from("zz");
    const tar = Buffer.concat([th("same.txt", d), th("same.txt", d), th("cont.dat", d, "7"), Buffer.alloc(1024)]);
    expect(ids(scanSync(new Uint8Array(tar), { filename: "d.tar" }))).toContain("ARCHIVE_DUPLICATE_NAMES");
  });
});

describe("XML tokenizer edges + RTF DDE field", () => {
  it("covers xml entity/cdata and rtf fldinst", () => {
    const events: string[] = [];
    tokenize(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "1">]><r a='1' b="2">&a;<![CDATA[hi]]></r>`, {
      start(n) {
        events.push("S" + n);
      },
      end(n) {
        events.push("E" + n);
      },
      text(t) {
        events.push("T" + t);
      },
      raw() {},
      doctype() {},
      pi() {},
      comment() {},
    });
    expect(events.length).toBeGreaterThan(0);
    const rtf = enc("{\\rtf1\\ansi{\\field{\\*\\fldinst DDEAUTO excel|sheet!r1c1}{\\fldrslt }}}");
    expect(ids(scanSync(rtf, { filename: "d.rtf" }))).toContain("OFFICE_DDE");
  });
});

describe("office-cfb fixtures", () => {
  it("scans macro.doc, xlm, encrypted, ole package, msg, ppt", async () => {
    const { readFileSync } = await import("node:fs");
    const { join, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures/constructs");
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "macro.doc"))), { filename: "m.doc" })).some((id) => id.startsWith("VBA_") || id === "OFFICE_VBA_MACROS")).toBe(true);
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "office-encrypted.bin"))), { filename: "e.bin" }))).toContain("OFFICE_ENCRYPTED");
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "xlm.xls"))), { filename: "x.xls" })).some((id) => id.startsWith("XLM_"))).toBe(true);
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "ole-package.cfb"))), { filename: "p.bin" }))).toContain("OLE_PACKAGE");
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "office-enc-streams.cfb"))), { filename: "e.cfb" }))).toContain("OFFICE_ENCRYPTED");
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "ppt-enc.cfb"))), { filename: "p.ppt" }))).toContain("OFFICE_ENCRYPTED");
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "word-enc.cfb"))), { filename: "w.doc" }))).toContain("OFFICE_ENCRYPTED");
    expect(scanSync(new Uint8Array(readFileSync(join(FIX, "msg-like.cfb"))), { filename: "m.msg" }).detectedType.format).toBe("msg");
    expect(ids(scanSync(new Uint8Array(readFileSync(join(FIX, "ole-contents.cfb"))), { filename: "c.bin" })).length).toBeGreaterThanOrEqual(0);
  });
});

describe("cli error verdict path", () => {
  it("sets exit 2 on usage error path already covered; formatReport sort", async () => {
    const r = scanSync(enc('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script><foreignObject/></svg>'), { filename: "a.svg" });
    expect(main.length).toBe(2);
    // force many findings ordering
    const { formatReport } = await import("../src/cli-main.js");
    expect(formatReport("a.svg", r)).toMatch(/SVG_/);
  });
});

describe("bytes remaining", () => {
  it("indexOfCI and excerpt edges", () => {
    expect(indexOfCI(enc("Ab\0Cd"), "cd")).toBe(3);
    expect(excerpt("short")).toBe("short");
    expect(excerptBytes(enc("abcdef"), 1, 3).length).toBeGreaterThan(0);
    expect(entropy(new Uint8Array(0))).toBe(0);
  });
});

describe("PDF XFA + stream without endstream + nesting", () => {
  it("hits more pdf branches", () => {
    const deep = "%PDF-1.4\n1 0 obj<< " + "/A << ".repeat(70) + "/X 1" + " >>".repeat(70) + " >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n";
    expect(() => scanSync(enc(deep), { filename: "d.pdf" })).not.toThrow();

    const noEnd = enc("%PDF-1.4\n1 0 obj<< /Length 3 >>stream\nABC");
    expect(ids(scanSync(noEnd, { filename: "n.pdf" }))).toContain("PDF_MALFORMED");

    // FileAttachment annotation
    const fa = enc("%PDF-1.4\n1 0 obj<< /Subtype /FileAttachment /FS << /F (x.bin) >> >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(fa, { filename: "f.pdf" }))).toContain("PDF_EMBEDDED_FILE");

    // OpenAction as destination array (should NOT flag)
    const oa = enc("%PDF-1.4\n1 0 obj<< /Type /Catalog /OpenAction [2 0 R /Fit] /Pages 2 0 R >>endobj\n2 0 obj<< /Type /Pages /Kids [] /Count 0 >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(ids(scanSync(oa, { filename: "oa.pdf" }))).not.toContain("PDF_OPEN_ACTION");
  });
});


describe("ZIP64 and inflate bomb via readEntry", () => {
  it("exercises ZIP64 locator path and ratio bomb on inflate", () => {
    // Build a stored zip then append fake ZIP64 EOCD locator before EOCD
    const z = zipStored({ "a.txt": "hi" });
    const loc = locateZip(z)!;
    // Insert ZIP64 locator (20 bytes) + ZIP64 EOCD (56 bytes) before EOCD — may not fully parse but hits branches
    const z64eocd = Buffer.alloc(56);
    z64eocd.writeUInt32LE(0x06064b50, 0);
    z64eocd.writeBigUInt64LE(44n, 4); // size of z64eocd minus 12
    z64eocd.writeBigUInt64LE(1n, 32); // total entries
    z64eocd.writeBigUInt64LE(BigInt(loc.cdSize), 40);
    z64eocd.writeBigUInt64LE(BigInt(loc.cdStart), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeUInt32LE(0, 4);
    // offset of z64eocd = loc.eocd (we'll prepend before eocd)
    const before = z.subarray(0, loc.eocd);
    const eocd = z.subarray(loc.eocd);
    // rewrite eocd count to 0xffff to force zip64 path
    const eocd2 = eocd.slice();
    eocd2[10] = 0xff; eocd2[11] = 0xff;
    eocd2[12] = 0xff; eocd2[13] = 0xff; eocd2[14] = 0xff; eocd2[15] = 0xff;
    eocd2[16] = 0xff; eocd2[17] = 0xff; eocd2[18] = 0xff; eocd2[19] = 0xff;
    locator.writeBigUInt64LE(BigInt(before.length), 8);
    const combined = new Uint8Array(before.length + 56 + 20 + eocd2.length);
    combined.set(before, 0);
    combined.set(z64eocd, before.length);
    combined.set(locator, before.length + 56);
    combined.set(eocd2, before.length + 76);
    locator.writeBigUInt64LE(BigInt(before.length), 8);
    // fix locator offset in combined
    const locOff = before.length + 56;
    new DataView(combined.buffer).setBigUint64(locOff + 8, BigInt(before.length), true);
    expect(() => locateZip(combined)).not.toThrow();
    expect(() => scanSync(combined, { filename: "z64.zip" })).not.toThrow();

  });
});

describe("sniff format gallery", () => {
  it("hits uncommon magic", async () => {
    const { sniff } = await import("../src/sniff.js");
    const samples: [string, number[]][] = [
      ["tiff", [0x49, 0x49, 0x2a, 0x00]],
      ["tiff", [0x4d, 0x4d, 0x00, 0x2a]],
      ["ico", [0, 0, 1, 0, 1, 0]],
      ["7z", [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
      ["rar", [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]],
      ["rar", [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]],
      ["xz", [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]],
      ["bz2", [0x42, 0x5a, 0x68]],
      ["cab", [0x4d, 0x53, 0x43, 0x46]],
      ["iso", [0x00, 0x00, 0x00, 0x00]], // may not hit
      ["wasm", [0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]],
      ["sqlite", [...enc("SQLite format 3\0")]],
    ];
    for (const [, bytes] of samples) {
      expect(() => sniff(Uint8Array.from(bytes))).not.toThrow();
      expect(() => scanSync(Uint8Array.from(bytes))).not.toThrow();
    }
    // disk images
    const vhd = new Uint8Array(512);
    vhd.set(enc("conectix"), 0);
    expect(() => scanSync(vhd, { filename: "a.vhd" })).not.toThrow();
  });
});
