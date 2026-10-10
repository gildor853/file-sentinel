/** Content-based format identification (magic numbers and text sniffing). */
import { indexOf, latin1, startsWith, u16le, u32be, u32le } from "./bytes.js";

export interface Sniffed {
  format: string;
  confidence: "high" | "medium" | "low";
}

const CFB = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const LNK = [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const A = (s: string) => Array.from(s, (c) => c.charCodeAt(0));

/** @internal Identifies the format of `b` from its first bytes (and a few structural checks). */
export function sniff(b: Uint8Array): Sniffed {
  if (b.length === 0) return { format: "empty", confidence: "high" };
  const s = (sig: number[], o = 0) => startsWith(b, sig, o);
  if (s(A("%PDF-"))) return { format: "pdf", confidence: "high" };
  if (s([0x50, 0x4b, 0x03, 0x04]) || s([0x50, 0x4b, 0x05, 0x06]) || s([0x50, 0x4b, 0x07, 0x08])) return { format: "zip", confidence: "medium" };
  if (s(CFB)) return { format: "cfb", confidence: "medium" };
  if (s(A("{\\rt"))) return { format: "rtf", confidence: "high" };
  if (s(PNG)) return { format: "png", confidence: "high" };
  if (s([0xff, 0xd8, 0xff])) return { format: "jpeg", confidence: "high" };
  if (s(A("GIF87a")) || s(A("GIF89a"))) return { format: "gif", confidence: "high" };
  if (s(A("RIFF")) && s(A("WEBP"), 8)) return { format: "webp", confidence: "high" };
  if (s(A("BM")) && b.length >= 26 && u16le(b, 6) === 0 && u16le(b, 8) === 0 && u32le(b, 10) >= 26 && u32le(b, 10) < Math.max(b.length, 27) && [12, 40, 52, 56, 64, 108, 124].includes(u32le(b, 14))) {
    return { format: "bmp", confidence: "high" };
  }
  if (s([0x49, 0x49, 0x2a, 0x00]) || s([0x4d, 0x4d, 0x00, 0x2a])) return { format: "tiff", confidence: "high" };
  if (s([0, 0, 1, 0]) && b.length >= 22 && u16le(b, 4) > 0 && u16le(b, 4) <= 256 && (b[9] === 0 || b[9] === 255) && u32le(b, 18) >= 6 + 16 * u16le(b, 4)) {
    return { format: "ico", confidence: "medium" };
  }
  if (s([0x1f, 0x8b, 0x08])) return { format: "gzip", confidence: "high" };
  if (s(A("BZh")) && (b[3] ?? 0) >= 0x31 && (b[3] ?? 0) <= 0x39) return { format: "bzip2", confidence: "high" };
  if (s([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return { format: "xz", confidence: "high" };
  if (s([0x28, 0xb5, 0x2f, 0xfd])) return { format: "zstd", confidence: "high" };
  if (s([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { format: "7z", confidence: "high" };
  if (s(A("Rar!\x1a\x07"))) return { format: "rar", confidence: "high" };
  if (s(A("MSCF")) && u32le(b, 4) === 0) return { format: "cab", confidence: "high" };
  if (s(A("ITSF"))) return { format: "chm", confidence: "high" };
  if (s(A("MZ"))) {
    const pe = u32le(b, 0x3c);
    if (pe >= 0x40 && pe < b.length - 4 && s(A("PE\0\0"), pe)) return { format: "pe", confidence: "high" };
    return { format: "pe", confidence: "medium" };
  }
  if (s([0x7f, 0x45, 0x4c, 0x46])) return { format: "elf", confidence: "high" };
  if (s([0xfe, 0xed, 0xfa, 0xce]) || s([0xfe, 0xed, 0xfa, 0xcf]) || s([0xce, 0xfa, 0xed, 0xfe]) || s([0xcf, 0xfa, 0xed, 0xfe])) return { format: "macho", confidence: "high" };
  if (s([0xca, 0xfe, 0xba, 0xbe]) && b.length >= 8) {
    const n = u32be(b, 4);
    if (n >= 1 && n <= 30) return { format: "macho", confidence: "high" }; // fat binary; class files have major version >= 45 here
    return { format: "class", confidence: "high" };
  }
  if (s(A("dex\n")) && b[7] === 0) return { format: "dex", confidence: "high" };
  if (s(LNK)) return { format: "lnk", confidence: "high" };
  if (s([0x00, 0x61, 0x73, 0x6d])) return { format: "wasm", confidence: "high" };
  if (s(A("vhdxfile"))) return { format: "vhd", confidence: "high" };
  if (b.length >= 512 && startsWith(b, A("conectix"), b.length - 512)) return { format: "vhd", confidence: "high" };
  if (s(A("conectix"))) return { format: "vhd", confidence: "medium" };
  if (s(A("ustar"), 257)) return { format: "tar", confidence: "high" };
  for (const o of [0x8001, 0x8801, 0x9001]) if (s(A("CD001"), o)) return { format: "iso", confidence: "high" };
  if (s(A("BEA01"), 0x8001)) return { format: "iso", confidence: "medium" };
  return sniffText(b);
}

/** BOM and encoding of a text file, or undefined when the bytes do not look like text. */
export function textEncoding(b: Uint8Array): { label: string; offset: number } | undefined {
  if (startsWith(b, [0xef, 0xbb, 0xbf])) return { label: "utf-8", offset: 3 };
  if (startsWith(b, [0xff, 0xfe])) return { label: "utf-16le", offset: 2 };
  if (startsWith(b, [0xfe, 0xff])) return { label: "utf-16be", offset: 2 };
  const n = Math.min(b.length, 8192);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i] as number;
    if (c === 0) return undefined;
    if (c < 0x20 && c !== 9 && c !== 10 && c !== 13 && c !== 12 && c !== 27 && c !== 8) bad++;
  }
  if (bad > n / 100 + 1) return undefined;
  // must be valid UTF-8 or mostly ASCII (legacy single-byte text)
  let i = 0;
  let high = 0;
  let invalid = 0;
  while (i < n) {
    const c = b[i] as number;
    if (c < 0x80) {
      i++;
      continue;
    }
    high++;
    const len = c >= 0xf0 && c <= 0xf4 ? 4 : c >= 0xe0 ? 3 : c >= 0xc2 && c <= 0xdf ? 2 : 0;
    if (len === 0) {
      invalid++;
      i++;
      continue;
    }
    let ok = true;
    for (let k = 1; k < len; k++) if (i + k < n && ((b[i + k] as number) & 0xc0) !== 0x80) ok = false;
    if (!ok) invalid++;
    i += ok ? len : 1;
  }
  if (invalid > 0 && invalid > high / 4 + 4) return undefined;
  return { label: invalid > 0 ? "windows-1252" : "utf-8", offset: 0 };
}

/** WHATWG MIME Sniffing "identify an unknown type": HTML patterns (§7.1). */
const HTML_TAGS = ["!doctype html", "html", "head", "script", "iframe", "h1", "div", "font", "table", "a", "style", "title", "b", "body", "br", "p"];

/** @internal Text formats: HTML, SVG, XML, RTF, scripts, plain text. */
export function sniffText(b: Uint8Array): Sniffed {
  if (startsWith(b, A("#@~^"))) return { format: "script-encoded", confidence: "high" };
  const enc = textEncoding(b);
  if (!enc) return { format: "unknown", confidence: "low" };
  // inspect the head as Latin-1/ASCII (UTF-16 is converted crudely by dropping NULs)
  let head = latin1(b, enc.offset, enc.offset + 4096);
  if (enc.label.startsWith("utf-16")) head = head.replace(/\u0000/g, "");
  const t = head.replace(/^[\t\n\f\r ]+/, "");
  const lower = t.slice(0, 1024).toLowerCase();
  if (lower.startsWith("{\\rt")) return { format: "rtf", confidence: "high" };
  if (lower.startsWith("#!")) return { format: "script", confidence: "medium" };
  if (lower.startsWith("<")) {
    const root = firstElement(t);
    if (root !== undefined) {
      const local = root.slice(root.indexOf(":") + 1).toLowerCase();
      if (local === "svg") return { format: "svg", confidence: "high" };
      if (local === "html") return { format: "html", confidence: "high" };
      if (local.startsWith("hta:")) return { format: "html", confidence: "medium" };
    }
    for (const tag of HTML_TAGS) {
      if (lower.startsWith(`<${tag}`)) {
        const next = lower.charCodeAt(tag.length + 1);
        if (next === 0x20 || next === 0x3e || next === 0x09 || next === 0x0a || next === 0x0c || next === 0x0d) return { format: "html", confidence: "medium" };
      }
    }
    if (lower.startsWith("<!--")) {
      // comment first: HTML if an HTML tag follows, else XML when it looks like XML
      if (root !== undefined) return { format: "xml", confidence: "medium" };
      return { format: "html", confidence: "low" };
    }
    if (lower.startsWith("<?xml") || root !== undefined) return { format: "xml", confidence: lower.startsWith("<?xml") ? "high" : "low" };
  }
  return { format: "text", confidence: "low" };
}

/**
 * Name of the first element after the prolog (XML declaration, processing
 * instructions, comments, DOCTYPE), or undefined. Scans at most the given head.
 */
function firstElement(t: string): string | undefined {
  let i = 0;
  for (let guard = 0; guard < 64 && i < t.length; guard++) {
    while (i < t.length && " \t\r\n".includes(t[i] as string)) i++;
    if (t.startsWith("<?", i)) {
      const e = t.indexOf("?>", i);
      if (e < 0) return undefined;
      i = e + 2;
    } else if (t.startsWith("<!--", i)) {
      const e = t.indexOf("-->", i + 4);
      if (e < 0) return undefined;
      i = e + 3;
    } else if (t.slice(i, i + 9).toUpperCase() === "<!DOCTYPE") {
      // skip to the matching '>' (internal subset in brackets)
      const lb = t.indexOf("[", i);
      const gt = t.indexOf(">", i);
      if (lb >= 0 && (gt < 0 || lb < gt)) {
        const rb = t.indexOf("]", lb);
        if (rb < 0) return undefined;
        const e = t.indexOf(">", rb);
        if (e < 0) return undefined;
        i = e + 1;
      } else {
        if (gt < 0) return undefined;
        i = gt + 1;
      }
    } else if (t[i] === "<") {
      const m = /^<([A-Za-z_][\w.:-]{0,80})/.exec(t.slice(i, i + 90));
      return m ? m[1] : undefined;
    } else return undefined;
  }
  return undefined;
}

/** @internal True when an HTML document signature appears anywhere in the first `limit` bytes (for polyglot checks). */
export function containsHtmlMarker(b: Uint8Array, from = 0, to = b.length): number {
  for (const m of ["<script", "<html", "<iframe", "<svg", "<?php", "<body", "javascript:"]) {
    const k = indexOfLower(b, m, from, to);
    if (k >= 0) return k;
  }
  return -1;
}

function indexOfLower(b: Uint8Array, needle: string, from: number, to: number): number {
  // fast path: search for '<' / 'j' then compare case-insensitively
  const first = needle.charCodeAt(0);
  const upper = first >= 97 && first <= 122 ? first - 32 : first;
  for (let i = Math.max(0, from); i < Math.min(to, b.length) - needle.length + 1; i++) {
    const c = b[i] as number;
    if (c !== first && c !== upper) continue;
    let j = 1;
    for (; j < needle.length; j++) {
      let x = b[i + j] as number;
      if (x >= 65 && x <= 90) x += 32;
      if (x !== needle.charCodeAt(j)) break;
    }
    if (j === needle.length) return i;
  }
  return -1;
}

/** @internal Offset of `%PDF-` within the first 1024 bytes (where readers accept it), or -1. */
export function pdfHeaderOffset(b: Uint8Array): number {
  return indexOf(b, new Uint8Array(A("%PDF-")), 0, Math.min(b.length, 1024 + 5));
}
