import { deflateRawSync, deflateSync, constants } from "node:zlib";
import { describe, expect, it } from "vitest";
import { inflateRaw, inflateZlib } from "../src/inflate.js";

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x297a2d39) >>> 0;
    return s / 2 ** 32;
  };
}

function sample(n: number, r: () => number, alphabet: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(r() * alphabet);
  // add repeats so that back-references occur
  for (let i = 64; i < n; i += 97) b.copyWithin(i, i - 50, i - 10);
  return b;
}

describe("inflate", () => {
  it("round-trips node:zlib output for many sizes, levels and strategies", () => {
    const r = rng(7);
    for (const n of [0, 1, 2, 10, 100, 1000, 65_535, 65_536, 200_000]) {
      for (const alphabet of [2, 16, 256]) {
        const data = sample(n, r, alphabet);
        for (const opts of [{ level: 0 }, { level: 1 }, { level: 9 }, { level: 6, strategy: constants.Z_FIXED }, { level: 6, strategy: constants.Z_HUFFMAN_ONLY }, { level: 6, strategy: constants.Z_RLE }]) {
          const raw = deflateRawSync(data, opts);
          const out = inflateRaw(raw, n + 10);
          expect(out.status, `${n}/${alphabet}/${JSON.stringify(opts)}`).toBe("ok");
          expect(out.consumed).toBe(raw.length);
          expect(Buffer.from(out.data).equals(Buffer.from(data))).toBe(true);
        }
        const z = inflateZlib(deflateSync(data), n + 10);
        expect(z.status).toBe("ok");
        expect(Buffer.from(z.data).equals(Buffer.from(data))).toBe(true);
      }
    }
  });

  it("stops at the output cap without allocating more", () => {
    const big = deflateRawSync(new Uint8Array(10_000_000));
    const r = inflateRaw(big, 1000);
    expect(r.status).toBe("limit");
    expect(r.data.length).toBe(1000);
    expect(inflateRaw(deflateRawSync(new Uint8Array(5000), { level: 0 }), 100).status).toBe("limit");
  });

  it("reports truncated and corrupt input instead of throwing", () => {
    const raw = deflateRawSync(sample(10_000, rng(3), 256));
    expect(inflateRaw(raw.subarray(0, raw.length >> 1), 1e6).status).toBe("truncated");
    expect(inflateRaw(new Uint8Array([0xff, 0xff, 0xff]), 100).status).toBe("corrupt"); // block type 3
    expect(inflateRaw(new Uint8Array([0x01, 0x05, 0x00, 0x00, 0x00]), 100).status).toBe("corrupt"); // stored, bad NLEN
    expect(inflateRaw(new Uint8Array([]), 100).status).toBe("truncated");
    const r = rng(11);
    for (let k = 0; k < 2000; k++) {
      const junk = sample(1 + Math.floor(r() * 300), r, 256);
      const res = inflateRaw(junk, 10_000);
      expect(["ok", "limit", "truncated", "corrupt"]).toContain(res.status);
      expect(res.data.length).toBeLessThanOrEqual(10_000);
    }
  });

  it("propagates a budget exception from the step callback", () => {
    const big = deflateRawSync(new Uint8Array(1_000_000));
    expect(() => inflateRaw(big, 2_000_000, () => { throw new Error("budget"); })).toThrow("budget");
  });

  it("accepts raw deflate when the zlib header is missing", () => {
    const data = new TextEncoder().encode("hello hello hello");
    expect(inflateZlib(deflateRawSync(data), 100).data).toEqual(data);
  });
});
