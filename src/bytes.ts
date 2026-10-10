/** Byte helpers. All functions are bounds-checked and never throw on short input. */

interface TextDecoderLike {
  decode(bytes: Uint8Array): string;
}
type TextDecoderCtor = new (label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean }) => TextDecoderLike;
const TD = (globalThis as { TextDecoder?: TextDecoderCtor }).TextDecoder;

const decoders = new Map<string, TextDecoderLike | null>();

/** @internal Decodes with a WHATWG encoding label; falls back to Latin-1 when unavailable. */
export function decode(bytes: Uint8Array, label = "utf-8"): string {
  let d = decoders.get(label);
  if (d === undefined) {
    try {
      d = TD ? new TD(label, { ignoreBOM: false }) : null;
    } catch {
      d = null;
    }
    decoders.set(label, d);
  }
  return d ? d.decode(bytes) : latin1(bytes);
}

/** @internal One char per byte (ISO-8859-1). */
export function latin1(bytes: Uint8Array, start = 0, end = bytes.length): string {
  let s = "";
  const e = Math.min(end, bytes.length);
  for (let i = Math.max(0, start); i < e; i += 8192) {
    s += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, Math.min(i + 8192, e))));
  }
  return s;
}

/** @internal UTF-16LE without a BOM. */
export function utf16le(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] as number) | ((bytes[i + 1] as number) << 8));
  return s;
}

/** @internal ASCII bytes of a string (code points above 0xFF are truncated). */
export function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export const u8 = (b: Uint8Array, o: number): number => (o >= 0 && o < b.length ? (b[o] as number) : 0);
export const u16le = (b: Uint8Array, o: number): number => u8(b, o) | (u8(b, o + 1) << 8);
export const u16be = (b: Uint8Array, o: number): number => (u8(b, o) << 8) | u8(b, o + 1);
export const u32le = (b: Uint8Array, o: number): number => (u16le(b, o) | (u16le(b, o + 2) << 16)) >>> 0;
export const u32be = (b: Uint8Array, o: number): number => ((u16be(b, o) << 16) | u16be(b, o + 2)) >>> 0;
/** 64-bit little-endian as a number (exact up to 2^53). */
export const u64le = (b: Uint8Array, o: number): number => u32le(b, o) + u32le(b, o + 4) * 0x100000000;

/** @internal True when `b` contains `sig` at offset `o`. */
export function startsWith(b: Uint8Array, sig: readonly number[] | Uint8Array, o = 0): boolean {
  if (o < 0 || o + sig.length > b.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[o + i] !== sig[i]) return false;
  return true;
}

/** @internal First index of `needle` at or after `from` (and before `to`), or -1. Linear for the short needles used here. */
export function indexOf(b: Uint8Array, needle: Uint8Array, from = 0, to = b.length): number {
  const n = needle.length;
  if (n === 0) return from;
  const first = needle[0] as number;
  const end = Math.min(to, b.length) - n;
  let i = Math.max(0, from);
  while (i <= end) {
    const k = b.indexOf(first, i);
    if (k < 0 || k > end) return -1;
    let j = 1;
    while (j < n && b[k + j] === needle[j]) j++;
    if (j === n) return k;
    i = k + 1;
  }
  return -1;
}

/** @internal Last index of `needle` starting before `before`, or -1. */
export function lastIndexOf(b: Uint8Array, needle: Uint8Array, before = b.length): number {
  const n = needle.length;
  for (let k = Math.min(before, b.length) - n; k >= 0; k--) {
    let j = 0;
    while (j < n && b[k + j] === needle[j]) j++;
    if (j === n) return k;
  }
  return -1;
}

/** @internal Case-insensitive ASCII search (needle must be lowercase). */
export function indexOfCI(b: Uint8Array, needle: string, from = 0, to = b.length): number {
  const n = needle.length;
  const end = Math.min(to, b.length) - n;
  const c0 = needle.charCodeAt(0);
  const c0u = c0 >= 97 && c0 <= 122 ? c0 - 32 : c0;
  for (let i = Math.max(0, from); i <= end; i++) {
    const x = b[i] as number;
    if (x !== c0 && x !== c0u) continue;
    let j = 1;
    for (; j < n; j++) {
      let y = b[i + j] as number;
      if (y >= 65 && y <= 90) y += 32;
      if (y !== needle.charCodeAt(j)) break;
    }
    if (j === n) return i;
  }
  return -1;
}

/** @internal Concatenates byte arrays. */
export function concat(parts: readonly Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * @internal Short, safe excerpt for `evidence`: control and non-ASCII-printable characters
 * are escaped, whitespace runs collapsed, length capped.
 */
export function excerpt(s: string, max = 200): string {
  let out = "";
  let space = false;
  let i = 0;
  for (; i < s.length && out.length < max; i++) {
    const c = s.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13) {
      if (!space && out.length > 0) out += " ";
      space = true;
      continue;
    }
    space = false;
    if (c < 32 || c === 127 || (c >= 0x80 && c < 0xa0)) out += `\\x${c.toString(16).padStart(2, "0")}`;
    else if ((c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c === 0xfeff || c === 0x061c) {
      out += `\\u${c.toString(16).toUpperCase().padStart(4, "0")}`;
    } else if (c >= 0xd800 && c <= 0xdfff) out += "\uFFFD";
    else out += s[i];
  }
  out = out.slice(0, max).trimEnd();
  return i < s.length && s.slice(i).trim() !== "" ? `${out}…` : out;
}

/** @internal Excerpt of bytes interpreted as Latin-1. */
export function excerptBytes(b: Uint8Array, start: number, length = 120): string {
  return excerpt(latin1(b, start, start + length), length);
}

/** @internal Shannon entropy (bits per byte) of a byte range. */
export function entropy(b: Uint8Array, start = 0, end = b.length): number {
  const counts = new Uint32Array(256);
  const e = Math.min(end, b.length);
  for (let i = start; i < e; i++) counts[b[i] as number]!++;
  const n = e - start;
  if (n <= 0) return 0;
  let h = 0;
  for (let k = 0; k < 256; k++) {
    const c = counts[k] as number;
    if (c) {
      const p = c / n;
      h -= p * Math.log2(p);
    }
  }
  return h;
}
