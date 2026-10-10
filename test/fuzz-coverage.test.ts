import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { tokenize } from "../src/xml.js";
import { openCfb } from "../src/cfb.js";
import { ovbaDecompress } from "../src/vba.js";
import { inflateRaw, inflateZlib } from "../src/inflate.js";
import { parseLnk } from "../src/lnk.js";
import { locateZip, readEntry, openZip } from "../src/zip.js";
import { Ctx, DEFAULT_LIMITS } from "../src/ctx.js";
import type { Env } from "../src/env.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const enc = (s: string) => new TextEncoder().encode(s);

describe("coverage fuzz", () => {
  it("scans every fixture truncated and mutated", () => {
    for (const dir of ["clean", "constructs"]) {
      for (const name of readdirSync(join(FIX, dir))) {
        const full = new Uint8Array(readFileSync(join(FIX, dir, name)));
        for (const n of [0, 1, 8, 32, 64, 128, 256, Math.floor(full.length / 2), full.length]) {
          const slice = full.subarray(0, Math.min(n, full.length));
          expect(() => scanSync(slice, { filename: name, limits: { maxOperations: 5_000_000 } })).not.toThrow();
        }
        // bit flips
        if (full.length > 16) {
          const mut = full.slice();
          mut[0] = (mut[0] as number) ^ 0xff;
          const mid = Math.floor(full.length / 2);
          mut[mid] = (mut[mid] as number) ^ 0xaa;
          mut[full.length - 1] = (mut[full.length - 1] as number) ^ 0x55;
          expect(() => scanSync(mut, { filename: name })).not.toThrow();
        }
      }
    }
  });

  it("random binary blobs", () => {
    for (let seed = 1; seed <= 40; seed++) {
      const b = new Uint8Array(256 + (seed * 17) % 2000);
      for (let i = 0; i < b.length; i++) b[i] = (i * seed * 31 + 17) & 0xff;
      // plant some signatures
      if (seed % 5 === 0) {
        b[0] = 0x50; b[1] = 0x4b; b[2] = 3; b[3] = 4;
      }
      if (seed % 5 === 1) {
        b.set(enc("%PDF-1.7"), 0);
      }
      if (seed % 5 === 2) {
        b.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 0);
      }
      if (seed % 5 === 3) {
        b.set(enc("{\\rtf1"), 0);
      }
      expect(() => scanSync(b, { filename: `f${seed}.bin`, limits: { maxOperations: 2_000_000 } })).not.toThrow();
    }
  });

  it("xml tokenizer edge cases", () => {
    const samples = [
      "<!-- comment --><root a='1' b=\"2\"/>",
      "<![CDATA[x]]> <a></a>",
      "<?xml-stylesheet href='http://x'?>",
      "<script>alert(1)</script>",
      "<div style=\"expression(alert(1))\">",
      "<svg><animate attributeName='href' to='javascript:1'/></svg>",
      "<html><iframe src='javascript:1'></iframe><object data='x'></object></html>",
      "<a href='data:text/html,hi'>",
      "<meta http-equiv=refresh content=\"0;url=javascript:1\">",
      "<style>@import url('http://x'); body{behavior:url(#x)}</style>",
    ];
    for (const s of samples) {
      expect(() =>
        tokenize(s, {
          start() {},
          end() {},
          text() {},
          raw() {},
          doctype() {},
          pi() {},
          comment() {},
        }, { html: s.includes("<html") || s.includes("<div") || s.includes("<meta") || s.includes("<style") || s.includes("<a ") || s.includes("<iframe") }),
      ).not.toThrow();
      expect(() => scanSync(enc(s), { filename: s.includes("svg") ? "a.svg" : s.includes("html") || s.includes("div") || s.includes("meta") ? "a.html" : "a.xml" })).not.toThrow();
    }
  });

  it("inflate / ovba / lnk / zip helpers on junk", () => {
    for (let i = 0; i < 20; i++) {
      const b = new Uint8Array(100 + i * 10);
      for (let j = 0; j < b.length; j++) b[j] = (j * i) & 0xff;
      inflateRaw(b, 1000);
      inflateZlib(b, 1000);
      ovbaDecompress(b);
      parseLnk(b);
      locateZip(b);
    }
    // real zip readEntry
    const z = new Uint8Array(readFileSync(join(FIX, "clean/clean.zip")));
    const ctx = new Ctx({ ...DEFAULT_LIMITS });
    const item = { bytes: z, path: [] as string[], name: "z.zip", declaredMime: undefined, depth: 0 };
    const env: Env = { ctx, item, child: () => undefined, add: (id, o) => ctx.add(id, item.path, o), addAt: (s, id, o) => ctx.add(id, s as string[], o) };
    const zip = openZip(env, z);
    if (zip) for (const e of zip.entries) readEntry(env, zip, e);
  });

  it("cfb on junk and real vba", () => {
    for (let i = 0; i < 10; i++) {
      const b = new Uint8Array(4096);
      b.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
      for (let j = 8; j < b.length; j++) b[j] = (j * i) & 0xff;
      try {
        openCfb(b, () => {}, 100);
      } catch {
        /* expected */
      }
    }
  });

  it("markup svg/html variants", () => {
    const svgs = [
      `<svg xmlns="http://www.w3.org/2000/svg"><script href="x.js"/></svg>`,
      `<svg><use href="http://evil/x#a"/></svg>`,
      `<svg><image href="http://evil/x.png"/></svg>`,
      `<svg><iframe/></svg>`,
      `<svg><style>url(javascript:1)</style></svg>`,
      `<svg><set attributeName="xlink:href" to="javascript:1"/></svg>`,
      `<svg><a href="vbscript:1"/></svg>`,
    ];
    for (const s of svgs) scanSync(enc(s), { filename: "a.svg" });
    const htmls = [
      `<html><script src="x.js"></script><a download href="data:application/octet-stream;base64,${"A".repeat(5000)}">x</a></html>`,
      `<html><body onload="x()"><a href="javascript:1"></a></body></html>`,
      `<html><?php echo 1?><script>eval(unescape('%61'))</script></html>`,
    ];
    for (const s of htmls) scanSync(enc(s), { filename: "a.html" });
  });

  it("pdf keyword soup", () => {
    const body = `%PDF-1.5
1 0 obj<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /Win << /F (calc.exe) /P (/c whoami) >> >> /AcroForm << /XFA [(x) 3 0 R] >> >>endobj
2 0 obj<< /Type /Pages /Kids [4 0 R] /Count 1 >>endobj
3 0 obj<< /Length 40 /Filter [/ASCIIHexDecode /FlateDecode] >>stream
3c7363726970743e616c6572742831293c2f7363726970743e>
endstream endobj
4 0 obj<< /Type /Page /Parent 2 0 R /Annots [5 0 R 6 0 R] >>endobj
5 0 obj<< /Subtype /FileAttachment /FS << /F (x.bin) /EF << /F 7 0 R >> >> >>endobj
6 0 obj<< /A << /S /GoToE /F (other.pdf) >> >>endobj
7 0 obj<< /Type /EmbeddedFile /Length 3 >>stream
MZ!
endstream endobj
8 0 obj<< /S /JavaScript /JS <FEFF00410042> >>endobj
9 0 obj<< /Filter /JBIG2Decode /Length 1 >>stream
!
endstream endobj
trailer<< /Root 1 0 R /Encrypt << /Filter /Standard >> >>
startxref
0
%%EOF
`;
    scanSync(enc(body), { filename: "soup.pdf" });
  });
});
