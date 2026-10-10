/**
 * DEFLATE (RFC 1951) and zlib (RFC 1950) decoder with a hard output cap.
 * Written for scanning hostile input: it never allocates more than the cap,
 * never throws, and reports corrupt or oversized streams in its result.
 */

export interface InflateResult {
  /** Decompressed bytes (possibly partial). */
  data: Uint8Array;
  /** `ok`: stream ended normally; `limit`: output reached the cap; `truncated`: input ended early; `corrupt`: invalid data. */
  status: "ok" | "limit" | "truncated" | "corrupt";
  /** Input bytes consumed (up to the end of the final block when `ok`). */
  consumed: number;
}

const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

class Corrupt extends Error {}
class Truncated extends Error {}
class Full extends Error {}

/** Decoding table: entry = symbol << 4 | length, indexed by the next `bits` input bits (LSB first). */
interface Table {
  readonly t: Uint16Array;
  readonly bits: number;
}

function buildTable(lengths: ArrayLike<number>, n: number): Table {
  const count = new Uint16Array(16);
  let max = 0;
  for (let i = 0; i < n; i++) {
    const l = lengths[i] as number;
    count[l]!++;
    if (l > max) max = l;
  }
  count[0] = 0;
  // over-subscribed or incomplete codes: over-subscription is invalid; incomplete is allowed (single-code trees)
  let left = 1;
  for (let l = 1; l <= 15; l++) {
    left = (left << 1) - (count[l] as number);
    if (left < 0) throw new Corrupt();
  }
  const bits = Math.max(1, max);
  const t = new Uint16Array(1 << bits);
  let c = 0;
  const first = new Uint16Array(17);
  for (let l = 1; l <= 15; l++) {
    c = (c + (count[l - 1] as number)) << 1;
    first[l] = c;
  }
  for (let sym = 0; sym < n; sym++) {
    const l = lengths[sym] as number;
    if (l === 0) continue;
    const cv = first[l]!++;
    let r = 0;
    for (let k = 0; k < l; k++) r |= ((cv >> k) & 1) << (l - 1 - k);
    const entry = (sym << 4) | l;
    for (let k = r; k < t.length; k += 1 << l) t[k] = entry;
  }
  return { t, bits };
}

let FIXED_LIT: Table | undefined;
let FIXED_DIST: Table | undefined;

function fixedTables(): [Table, Table] {
  if (!FIXED_LIT || !FIXED_DIST) {
    const l = new Uint8Array(288);
    l.fill(8, 0, 144);
    l.fill(9, 144, 256);
    l.fill(7, 256, 280);
    l.fill(8, 280, 288);
    FIXED_LIT = buildTable(l, 288);
    FIXED_DIST = buildTable(new Uint8Array(30).fill(5), 30);
  }
  return [FIXED_LIT, FIXED_DIST];
}

class Inflater {
  pos: number;
  bitbuf = 0;
  bitcnt = 0;
  out: Uint8Array;
  outLen = 0;
  constructor(
    readonly src: Uint8Array,
    start: number,
    readonly cap: number,
    readonly step: (n: number) => void,
  ) {
    this.pos = start;
    this.out = new Uint8Array(Math.min(cap, Math.max(1024, src.length * 4)));
  }

  need(n: number): void {
    while (this.bitcnt < n) {
      if (this.pos >= this.src.length) throw new Truncated();
      this.bitbuf |= (this.src[this.pos++] as number) << this.bitcnt;
      this.bitcnt += 8;
    }
  }

  bits(n: number): number {
    if (n === 0) return 0;
    this.need(n);
    const v = this.bitbuf & ((1 << n) - 1);
    this.bitbuf >>>= n;
    this.bitcnt -= n;
    return v;
  }

  decode(tab: Table): number {
    // fill up to tab.bits; near the end of input, allow fewer bits if the code is short enough
    while (this.bitcnt < tab.bits && this.pos < this.src.length) {
      this.bitbuf |= (this.src[this.pos++] as number) << this.bitcnt;
      this.bitcnt += 8;
    }
    const e = tab.t[this.bitbuf & ((1 << tab.bits) - 1)] as number;
    const l = e & 15;
    if (l === 0) throw new Corrupt();
    if (l > this.bitcnt) throw new Truncated();
    this.bitbuf >>>= l;
    this.bitcnt -= l;
    return e >> 4;
  }

  ensure(extra: number): void {
    const need = this.outLen + extra;
    if (need > this.cap) throw new Full();
    if (need > this.out.length) {
      const grown = new Uint8Array(Math.min(this.cap, Math.max(need, this.out.length * 2)));
      grown.set(this.out.subarray(0, this.outLen));
      this.out = grown;
    }
  }

  run(): void {
    let last = 0;
    while (!last) {
      last = this.bits(1);
      const type = this.bits(2);
      this.step(64);
      if (type === 0) this.stored();
      else if (type === 1) {
        const [l, d] = fixedTables();
        this.codes(l, d);
      } else if (type === 2) this.dynamic();
      else throw new Corrupt();
    }
  }

  stored(): void {
    this.bitbuf = 0;
    this.bitcnt = 0;
    if (this.pos + 4 > this.src.length) throw new Truncated();
    const len = (this.src[this.pos] as number) | ((this.src[this.pos + 1] as number) << 8);
    const nlen = (this.src[this.pos + 2] as number) | ((this.src[this.pos + 3] as number) << 8);
    this.pos += 4;
    if ((len ^ 0xffff) !== nlen) throw new Corrupt();
    const avail = Math.min(len, this.src.length - this.pos);
    const room = Math.min(avail, this.cap - this.outLen);
    this.ensure(room);
    this.out.set(this.src.subarray(this.pos, this.pos + room), this.outLen);
    this.outLen += room;
    this.pos += room;
    this.step(room >>> 4);
    if (room < avail) throw new Full();
    if (avail < len) throw new Truncated();
  }

  dynamic(): void {
    const hlit = this.bits(5) + 257;
    const hdist = this.bits(5) + 1;
    const hclen = this.bits(4) + 4;
    if (hlit > 286 || hdist > 30) throw new Corrupt();
    const cl = new Uint8Array(19);
    for (let i = 0; i < hclen; i++) cl[CL_ORDER[i] as number] = this.bits(3);
    const clTab = buildTable(cl, 19);
    const lens = new Uint8Array(hlit + hdist);
    let i = 0;
    while (i < hlit + hdist) {
      const sym = this.decode(clTab);
      if (sym < 16) lens[i++] = sym;
      else {
        let rep: number;
        let val = 0;
        if (sym === 16) {
          if (i === 0) throw new Corrupt();
          val = lens[i - 1] as number;
          rep = 3 + this.bits(2);
        } else if (sym === 17) rep = 3 + this.bits(3);
        else rep = 11 + this.bits(7);
        if (i + rep > hlit + hdist) throw new Corrupt();
        lens.fill(val, i, i + rep);
        i += rep;
      }
    }
    if (lens[256] === 0) throw new Corrupt();
    this.codes(buildTable(lens.subarray(0, hlit), hlit), buildTable(lens.subarray(hlit), hdist));
  }

  codes(lit: Table, dist: Table): void {
    let n = 0;
    for (;;) {
      const sym = this.decode(lit);
      if (sym < 256) {
        if (this.outLen >= this.out.length) this.ensure(1);
        this.out[this.outLen++] = sym;
      } else if (sym === 256) return;
      else {
        const li = sym - 257;
        if (li >= 29) throw new Corrupt();
        const len = (LEN_BASE[li] as number) + this.bits(LEN_EXTRA[li] as number);
        const di = this.decode(dist);
        if (di >= 30) throw new Corrupt();
        const d = (DIST_BASE[di] as number) + this.bits(DIST_EXTRA[di] as number);
        if (d > this.outLen) throw new Corrupt();
        const room = Math.min(len, this.cap - this.outLen);
        this.ensure(room);
        const o = this.out;
        let p = this.outLen;
        for (let k = 0; k < room; k++, p++) o[p] = o[p - d] as number;
        this.outLen = p;
        if (room < len) throw new Full();
      }
      if (++n === 4096) {
        n = 0;
        this.step(256);
      }
    }
  }
}

/** @internal Raw DEFLATE. `step` is charged with work units (may throw to abort). */
export function inflateRaw(src: Uint8Array, cap: number, step: (n: number) => void = () => {}, start = 0): InflateResult {
  const f = new Inflater(src, start, Math.max(0, cap), step);
  let status: InflateResult["status"] = "ok";
  try {
    f.run();
  } catch (e) {
    if (e instanceof Full) status = "limit";
    else if (e instanceof Truncated) status = "truncated";
    else if (e instanceof Corrupt || e instanceof RangeError) status = "corrupt";
    else throw e;
  }
  return { data: f.out.subarray(0, f.outLen), status, consumed: f.pos - start };
}

/** @internal zlib-wrapped DEFLATE (PDF FlateDecode, PNG). A missing or invalid header falls back to raw DEFLATE. */
export function inflateZlib(src: Uint8Array, cap: number, step?: (n: number) => void): InflateResult {
  const cmf = src[0] ?? 0;
  const flg = src[1] ?? 0;
  const zlibHeader = src.length >= 2 && (cmf & 0x0f) === 8 && (cmf >> 4) <= 7 && ((cmf << 8) | flg) % 31 === 0 && (flg & 0x20) === 0;
  const r = inflateRaw(src, cap, step, zlibHeader ? 2 : 0);
  return { ...r, consumed: r.consumed + (zlibHeader ? 2 : 0) };
}
