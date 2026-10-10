import { describe, expect, it } from "vitest";
import { scanSync } from "../src/index.js";
import { sniff } from "../src/sniff.js";

const enc = (s: string) => new TextEncoder().encode(s);

function pe(opts: { machine?: number; chars?: number; magic?: number; subsystem?: number; clr?: boolean } = {}): Uint8Array {
  const b = Buffer.alloc(0x200);
  b.write("MZ");
  b.writeUInt32LE(0x80, 0x3c);
  b.write("PE\0\0", 0x80);
  b.writeUInt16LE(opts.machine ?? 0x8664, 0x84);
  b.writeUInt16LE(opts.chars ?? 0, 0x80 + 22);
  const opt = 0x80 + 24;
  b.writeUInt16LE(opts.magic ?? 0x20b, opt);
  b.writeUInt16LE(opts.subsystem ?? 3, opt + 68);
  if (opts.clr) b.writeUInt32LE(1, opt + 112 + 14 * 8);
  return new Uint8Array(b);
}

describe("sniff + exec gallery for branch coverage", () => {
  it("hits uncommon magics and PE/ELF/Mach-O variants", () => {
    const samples: [string, Uint8Array][] = [
      ["a.tiff", Uint8Array.from([0x49, 0x49, 0x2a, 0x00, 0, 0, 0, 0])],
      ["b.tiff", Uint8Array.from([0x4d, 0x4d, 0x00, 0x2a, 0, 0, 0, 0])],
      ["a.ico", (() => {
        const b = Buffer.alloc(32);
        b.writeUInt16LE(0, 0);
        b.writeUInt16LE(1, 2);
        b.writeUInt16LE(1, 4);
        b[9] = 0;
        b.writeUInt32LE(22, 18);
        return new Uint8Array(b);
      })()],
      ["a.bz2", Uint8Array.from([0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26])],
      ["a.xz", Uint8Array.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 0])],
      ["a.zst", Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0])],
      ["a.cab", (() => { const b = Buffer.alloc(16); b.write("MSCF"); b.writeUInt32LE(0, 4); return new Uint8Array(b); })()],
      ["a.chm", enc("ITSF\0\0\0\0")],
      ["a.dex", Uint8Array.from([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00])],
      ["a.wasm", Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])],
      ["a.vhdx", enc("vhdxfile" + "\0".repeat(8))],
      ["a.vhd", (() => { const b = Buffer.alloc(1024); b.write("conectix", 1024 - 512); return new Uint8Array(b); })()],
      ["b.vhd", enc("conectix" + "\0".repeat(20))],
      ["a.iso", (() => { const b = Buffer.alloc(0x8001 + 6); b.write("CD001", 0x8001); return new Uint8Array(b); })()],
      ["b.iso", (() => { const b = Buffer.alloc(0x8001 + 6); b.write("BEA01", 0x8001); return new Uint8Array(b); })()],
      ["a.class", (() => { const b = Buffer.alloc(16); b[0]=0xca;b[1]=0xfe;b[2]=0xba;b[3]=0xbe; b.writeUInt32BE(45, 4); return new Uint8Array(b); })()],
      ["fat.macho", (() => { const b = Buffer.alloc(16); b[0]=0xca;b[1]=0xfe;b[2]=0xba;b[3]=0xbe; b.writeUInt32BE(2, 4); return new Uint8Array(b); })()],
      ["m32.macho", Uint8Array.from([0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0])],
      ["m64.macho", Uint8Array.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0])],
      ["m32le.macho", Uint8Array.from([0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0])],
      ["m64le.macho", Uint8Array.from([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0])],
      ["utf8.txt", Uint8Array.from([0xef, 0xbb, 0xbf, ...enc("hello")])],
      ["utf16le.txt", Buffer.from("\ufeffhello", "utf16le")],
      ["utf16be.txt", Uint8Array.from([0xfe, 0xff, 0x00, 0x68, 0x00, 0x69])],
      ["a.jse", enc("#@~^AAAA")],
      ["empty.bin", new Uint8Array(0)],
      ["zipempty.zip", Uint8Array.from([0x50, 0x4b, 0x05, 0x06, ...Array(18).fill(0)])],
      ["zipspan.zip", Uint8Array.from([0x50, 0x4b, 0x07, 0x08, 0, 0, 0, 0])],
    ];
    for (const [name, bytes] of samples) {
      expect(() => sniff(bytes)).not.toThrow();
      expect(() => scanSync(bytes, { filename: name })).not.toThrow();
    }

    // PE variants
    for (const opts of [
      { machine: 0x14c, magic: 0x10b, subsystem: 2 },
      { machine: 0xaa64, magic: 0x20b, subsystem: 1 },
      { machine: 0x8664, chars: 0x2000, subsystem: 3 },
      { machine: 0x8664, magic: 0x20b, subsystem: 3, clr: true },
      { machine: 0x9999, subsystem: 9 },
    ]) {
      expect(() => scanSync(pe(opts), { filename: "a.exe" })).not.toThrow();
    }

    // ELF variants: 32/64, types
    for (const [cls, type] of [[1, 1], [1, 2], [2, 3], [2, 4], [1, 0]] as const) {
      const elf = new Uint8Array(32);
      elf.set([0x7f, 0x45, 0x4c, 0x46, cls, 1, 1], 0);
      elf[16] = type; elf[17] = 0;
      expect(() => scanSync(elf, { filename: "a.elf" })).not.toThrow();
    }
    // big-endian ELF
    const elfbe = new Uint8Array(32);
    elfbe.set([0x7f, 0x45, 0x4c, 0x46, 1, 2, 1], 0);
    elfbe[16] = 0; elfbe[17] = 2;
    expect(() => scanSync(elfbe, { filename: "a.elf" })).not.toThrow();

    // scripts by extension
    for (const ext of ["ps1", "bat", "cmd", "vbs", "js", "hta", "sh"]) {
      expect(scanSync(enc("echo hi\n"), { filename: `x.${ext}` }).findings.some((f) => f.id === "SCRIPT_FILE")).toBe(true);
    }
  });
});
