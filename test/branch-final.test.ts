import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { tokenize } from "../src/xml.js";
import { inflateRaw, inflateZlib } from "../src/inflate.js";
import { deflateRawSync } from "node:zlib";
import { openCfb, CfbError } from "../src/cfb.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { zipEntries, zipStored } from "./helpers/zip-build.js";
import { main } from "../src/cli-main.js";

const enc = (s: string) => new TextEncoder().encode(s);
const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures/constructs");

describe("final branch pushes", () => {
  it("xml html tokenizer quirks", () => {
    const samples = [
      `<br>`,
      `<BR/>`,
      `<input disabled checked type=text value=x>`,
      `<p class='a' id="b" data-x=1>`,
      `</p></div>`,
      `<script>a<b</script>`,
      `<style>a{color:red}</style>`,
      `<textarea>a</textarea>`,
      `&lt;&gt;&#xZZ;&#999999;`,
      `<![CDATA[]]>`,
      `<?xml version='1.0' encoding="utf-8"?>`,
      `<a href="x" href='y'>`,
    ];
    for (const s of samples) {
      expect(() =>
        tokenize(s, { start() {}, end() {}, text() {}, raw() {} }, { html: true }),
      ).not.toThrow();
    }
  });

  it("inflate error paths", () => {
    expect(inflateRaw(new Uint8Array([0xff, 0xff, 0xff]), 100).status).not.toBe("ok");
    expect(inflateZlib(new Uint8Array([0x78, 0x01, 0xff]), 100).status).not.toBe("ok");
    const raw = deflateRawSync(Buffer.alloc(1000));
    expect(inflateRaw(new Uint8Array(raw), 10).status).toBe("limit");
  });

  it("cfb errors and real fixtures", () => {
    expect(() => openCfb(new Uint8Array(100), () => {}, 10)).toThrow(CfbError);
    const bad = new Uint8Array(1024);
    bad.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    bad[0x1e] = 10; // bad sector shift
    expect(() => openCfb(bad, () => {}, 10)).toThrow();
    for (const name of ["macro.doc", "macro.docm", "xlm.xls", "office-encrypted.bin", "ole-package.cfb", "msg-like.cfb", "ppt-enc.cfb", "word-enc.cfb", "ole-contents.cfb"]) {
      expect(() => scanSync(new Uint8Array(readFileSync(join(FIX, name))), { filename: name })).not.toThrow();
    }
  });

  it("zip directory entries and missing local", () => {
    const z = zipEntries([
      { name: "dir/", data: new Uint8Array(0) },
      { name: "gone.txt", data: enc("x"), skipData: true, localOffset: 99999 },
    ]);
    expect(() => scanSync(z, { filename: "a.zip" })).not.toThrow();
  });

  it("cli -h -v and version string", async () => {
    const state = { out: "", err: "" };
    const io = {
      async readFile() { return enc("hi"); },
      async readStdin() { return enc("hi"); },
      async stdout(t: string) { state.out += t; },
      stderr(t: string) { state.err += t; },
    };
    expect(await main(["-h"], io)).toBe(0);
    expect(await main(["-v"], io)).toBe(0);
    expect(await main(["--json", "a.txt"], io)).toBe(0);
  });

  it("pdf oddballs", () => {
    // stream keyword right after dict without newline, hex string odd nibble already done
    const p = enc("%PDF-1.4\n1 0 obj<< /Length 0 >>stream\nendstream\nendobj\n2 0 obj<< /S /JavaScript /JS (\\376\\377\\000A) >>endobj\ntrailer<< /Root 1 0 R /Size 2 >>\n%%EOF\n");
    expect(() => scanSync(p, { filename: "a.pdf" })).not.toThrow();
    // empty name, deep refs
    const p2 = enc("%PDF-1.4\n1 0 obj<< / /X 1 0 R /Y 99 0 R >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");
    expect(() => scanSync(p2, { filename: "b.pdf" })).not.toThrow();
  });

  it("jar without manifest", () => {
    const jar = zipStored({ "com/Foo.class": "\xca\xfe\xba\xbe\x00\x00\x00\x37" });
    expect(scanSync(jar, { filename: "a.jar" }).detectedType.format).toBe("jar");
  });
});
