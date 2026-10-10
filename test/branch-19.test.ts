import { describe, expect, it } from "vitest";
import { decodeEntities, tokenize } from "../src/xml.js";
import { scanSync } from "../src/index.js";
import { decodeText } from "../src/markup.js";
import { gzipSync } from "node:zlib";
import { parseLnk } from "../src/lnk.js";

const enc = (s: string) => new TextEncoder().encode(s);

describe("nineteen branches", () => {
  it("decodeEntities remaining", () => {
    expect(decodeEntities("a&amp;b", false)).toBe("a&b");
    expect(decodeEntities("&#0;", true)).toBe("\uFFFD");
    expect(decodeEntities("&#x110000;", true)).toBe("\uFFFD");
    expect(decodeEntities("&#x41", true)).toContain("A"); // no semicolon HTML
    expect(decodeEntities("&#65", true)).toContain("A");
    expect(decodeEntities("&AMP;", true)).toContain("&"); // case fold html
    expect(decodeEntities("&NotAnEntity;", true)).toContain("&");
    expect(decodeEntities("&#xZZ;", true)).toContain("&");
    // CDATA unclosed
    tokenize("<![CDATA[unterminated", { raw() {} });
    tokenize("<!--unterminated", { comment() {} });
    tokenize("<!DOCTYPE x [ <!ELEMENT x ANY>", { doctype() {} });
  });

  it("decodeText encodings", () => {
    expect(decodeText(enc('<?xml version="1.0" encoding="ISO-8859-1"?><x/>')).length).toBeGreaterThan(0);
    expect(decodeText(enc('<html><meta charset="utf-8"><body>hi</body></html>')).includes("hi")).toBe(true);
    const u16 = Buffer.from("\ufeff<svg xmlns='http://www.w3.org/2000/svg'/>", "utf16le");
    expect(decodeText(new Uint8Array(u16)).toLowerCase()).toContain("svg");
  });

  it("type mismatch branches", () => {
    // png named .jpg → low severity mismatch
    const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44]);
    expect(scanSync(png, { filename: "a.jpg" }).findings.some((f) => f.id === "TYPE_MISMATCH")).toBe(true);
    // svg as text/plain is textual OK
    const svg = enc('<svg xmlns="http://www.w3.org/2000/svg"/>');
    expect(scanSync(svg, { filename: "a.svg", declaredMime: "text/plain" }).findings.every((f) => f.id !== "TYPE_MISMATCH" || f.location.element !== "mime")).toBe(true);
    // svg declared as application/xml OK
    scanSync(svg, { filename: "a.svg", declaredMime: "application/xml" });
    // zip declared as application/zip OK
  });

  it("gzip tgz name + markup css", async () => {
    const { zipStored } = await import("./helpers/zip-build.js");
    const z = zipStored({ "a.txt": "hi" });
    scanSync(z, { filename: "a.zip", declaredMime: "application/zip" });
    // executable disguised by mime
    scanSync(enc("MZ\x90\0\0\0\0\0"), { filename: "x.bin", declaredMime: "text/plain" });
    // active disguised
    scanSync(enc('<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'), { filename: "a.svg", declaredMime: "image/png" });
    // gzip .tgz → tar name strip
    const gz = gzipSync(enc("ustar content"));
    scanSync(new Uint8Array(gz), { filename: "archive.tgz" });
    // CSS expression / external url
    scanSync(enc('<svg xmlns="http://www.w3.org/2000/svg"><style>x{behavior:url(#default#warning)}</style></svg>'), { filename: "a.svg" });
    scanSync(enc('<svg xmlns="http://www.w3.org/2000/svg"><style>@import url("https://evil.example/x.css"); x{background:url(https://evil.example/a.png)}</style></svg>'), { filename: "b.svg" });
    scanSync(enc('<html><style>body{expression(alert(1))}</style></html>'), { filename: "a.html" });
  });

  it("lnk network path branch", () => {
    // LinkInfo with NetworkShareInfo (liFlags & 2), headerSize < 0x24
    const flags = 0x02;
    const hdr = Buffer.alloc(0x4c);
    hdr.writeUInt32LE(0x4c, 0);
    Buffer.from([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]).copy(hdr, 4);
    hdr.writeUInt32LE(flags, 0x14);
    const share = Buffer.from("\\\\server\\share\0");
    const li = Buffer.alloc(0x30 + share.length);
    li.writeUInt32LE(li.length, 0);
    li.writeUInt32LE(0x1c, 4); // header < 0x24
    li.writeUInt32LE(2, 8); // CommonNetworkRelativeLinkAndPathSuffix
    li.writeUInt32LE(0x1c, 20); // net offset
    // at net: size, flags, netname offset
    li.writeUInt32LE(share.length + 20, 0x1c);
    li.writeUInt32LE(0, 0x20);
    li.writeUInt32LE(20, 0x24); // net name offset relative to net structure → 0x1c+20
    share.copy(li, 0x1c + 20);
    const info = parseLnk(new Uint8Array(Buffer.concat([hdr, li])));
    expect(typeof info.target).toBe("string");
  });
});
