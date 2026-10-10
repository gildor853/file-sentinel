/**
 * Defensive ZIP reader. It tolerates damaged archives, records structural
 * anomalies (path traversal, overlapping entries, header mismatches, bombs)
 * and decompresses entries only within the scan's limits.
 */
import { decode, excerpt, latin1, u16le, u32le, u64le } from "./bytes.js";
import { crc32 } from "./crc32.js";
import type { Env } from "./env.js";
import { inflateRaw } from "./inflate.js";

/** @internal One central-directory entry. */
export interface ZipEntry {
  readonly name: string;
  readonly method: number;
  readonly flags: number;
  readonly crc: number;
  readonly csize: number;
  readonly usize: number;
  readonly localOffset: number;
  /** Start of the entry data (after the local header); -1 when the local header is missing. */
  readonly dataStart: number;
  readonly isDir: boolean;
  readonly encrypted: boolean;
  readonly symlink: boolean;
}

/** @internal An opened archive. */
export interface Zip {
  readonly bytes: Uint8Array;
  readonly entries: readonly ZipEntry[];
  /** Offset of the end-of-central-directory record. */
  readonly eocd: number;
  /** Bytes before the first local header that the offsets do not account for (prepended data). */
  readonly prefix: number;
  /** Offset just past the archive (end of the EOCD record and its comment). */
  readonly end: number;
}

const RATIO_MIN_SIZE = 1 << 20;
const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

/**
 * @internal Locates a ZIP archive whose end-of-central-directory record lies in `b`
 * (searching backwards from `to`) and whose central directory is valid.
 */
export function locateZip(b: Uint8Array, to = b.length): { eocd: number; cdStart: number; cdSize: number; count: number; prefix: number; end: number } | undefined {
  const lowest = Math.max(0, to - 22 - 0xffff);
  for (let i = to - 22; i >= lowest; i--) {
    if (b[i] !== 0x50 || u32le(b, i) !== SIG_EOCD) continue;
    let count = u16le(b, i + 10);
    let cdSize = u32le(b, i + 12);
    let cdOffset = u32le(b, i + 16);
    const commentLen = u16le(b, i + 20);
    // ZIP64 end of central directory locator just before the EOCD
    if ((count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) && i >= 20 && u32le(b, i - 20) === 0x07064b50) {
      const rec = u64le(b, i - 12);
      if (rec + 56 <= b.length && u32le(b, rec) === 0x06064b50) {
        count = Math.min(u64le(b, rec + 32), Number.MAX_SAFE_INTEGER);
        cdSize = u64le(b, rec + 40);
        cdOffset = u64le(b, rec + 48);
      }
    }
    const cdEnd = cdOffset + cdSize;
    // prepended data shifts everything: the central directory really ends where the EOCD (or ZIP64 record) begins
    let realEnd = i;
    if (i >= 20 && u32le(b, i - 20) === 0x07064b50) {
      const rec = u64le(b, i - 12);
      if (rec < i && u32le(b, rec) === 0x06064b50) realEnd = rec;
      else {
        // search the ZIP64 record backwards (prefixed archive)
        const z = i - 20 - 56;
        if (z >= 0 && u32le(b, z) === 0x06064b50) realEnd = z;
      }
    }
    const prefix = realEnd - cdEnd;
    if (prefix < 0 || cdSize > realEnd) continue;
    const cdStart = cdOffset + prefix;
    if (count > 0 && u32le(b, cdStart) !== SIG_CENTRAL) continue;
    return { eocd: i, cdStart, cdSize, count, prefix, end: Math.min(b.length, i + 22 + commentLen) };
  }
  return undefined;
}

function entryName(raw: Uint8Array, utf8: boolean): string {
  if (utf8) return decode(raw, "utf-8");
  // CP437 is not available in TextDecoder; ASCII names are the norm, otherwise try UTF-8 then Latin-1
  for (const c of raw) if (c >= 0x80) {
    const s = decode(raw, "utf-8");
    return s.includes("\uFFFD") ? latin1(raw) : s;
  }
  return latin1(raw);
}

/** @internal True for names that escape the extraction directory. */
export function isTraversal(name: string): boolean {
  const n = name.replace(/\\/g, "/");
  if (n.startsWith("/") || /^[A-Za-z]:/.test(n)) return true;
  return n.split("/").some((s) => s === "..");
}

/**
 * @internal Parses the archive and reports structural findings on `env`. Returns
 * undefined (after reporting ARCHIVE_CORRUPT) when no central directory is found.
 */
export function openZip(env: Env, b: Uint8Array): Zip | undefined {
  const loc = locateZip(b);
  if (!loc) {
    env.add("ARCHIVE_CORRUPT", { detail: "No valid end-of-central-directory record was found." });
    return undefined;
  }
  const ctx = env.ctx;
  const entries: ZipEntry[] = [];
  let p = loc.cdStart;
  const max = ctx.limits.maxEntries;
  for (let k = 0; k < loc.count; k++) {
    ctx.step(4);
    if (k >= max) {
      ctx.hit("maxEntries");
      env.add("SCAN_LIMIT", { detail: `Only the first ${max} of ${loc.count} entries were inspected (maxEntries).` });
      break;
    }
    if (p + 46 > b.length || u32le(b, p) !== SIG_CENTRAL) {
      env.add("ARCHIVE_CORRUPT", { offset: p, detail: "The central directory is truncated or damaged." });
      break;
    }
    const madeBy = u16le(b, p + 4);
    const flags = u16le(b, p + 8);
    const method = u16le(b, p + 10);
    const crc = u32le(b, p + 16);
    let csize = u32le(b, p + 20);
    let usize = u32le(b, p + 24);
    const nameLen = u16le(b, p + 28);
    const extraLen = u16le(b, p + 30);
    const commentLen = u16le(b, p + 32);
    const extAttr = u32le(b, p + 38);
    let localOffset = u32le(b, p + 42);
    const name = entryName(b.subarray(p + 46, p + 46 + nameLen), (flags & 0x800) !== 0);
    // ZIP64 extended information extra field
    let e = p + 46 + nameLen;
    const extraEnd = Math.min(b.length, e + extraLen);
    while (e + 4 <= extraEnd) {
      const id = u16le(b, e);
      const size = u16le(b, e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (usize === 0xffffffff) (usize = u64le(b, q)), (q += 8);
        if (csize === 0xffffffff) (csize = u64le(b, q)), (q += 8);
        if (localOffset === 0xffffffff) localOffset = u64le(b, q);
      }
      e += 4 + size;
    }
    p += 46 + nameLen + extraLen + commentLen;
    const lo = localOffset + loc.prefix;
    let dataStart = -1;
    if (lo + 30 <= b.length && u32le(b, lo) === SIG_LOCAL) {
      const ln = u16le(b, lo + 26);
      dataStart = lo + 30 + ln + u16le(b, lo + 28);
      const localName = entryName(b.subarray(lo + 30, lo + 30 + ln), (u16le(b, lo + 6) & 0x800) !== 0);
      if (localName !== name || u16le(b, lo + 8) !== method) {
        env.add("ARCHIVE_HEADER_MISMATCH", { element: name, evidence: excerpt(localName === name ? `method ${u16le(b, lo + 8)} vs ${method}` : `local "${localName}" vs central "${name}"`) });
      }
    }
    const host = madeBy >> 8;
    const symlink = (host === 3 || host === 19) && ((extAttr >>> 16) & 0xf000) === 0xa000;
    entries.push({ name, method, flags, crc, csize, usize, localOffset: lo, dataStart, isDir: name.endsWith("/") || name.endsWith("\\"), encrypted: (flags & 1) !== 0 || method === 99, symlink });
  }
  const zip: Zip = { bytes: b, entries, eocd: loc.eocd, prefix: loc.prefix, end: loc.end };
  structuralChecks(env, zip);
  return zip;
}

function structuralChecks(env: Env, zip: Zip): void {
  const seen = new Set<string>();
  let encrypted = 0;
  let unsupported = 0;
  for (const e of zip.entries) {
    if (isTraversal(e.name)) env.add("ARCHIVE_PATH_TRAVERSAL", { element: e.name, evidence: excerpt(e.name) });
    if (e.symlink) env.add("ARCHIVE_SYMLINK", { element: e.name, evidence: excerpt(e.name) });
    const key = e.name.replace(/\\/g, "/");
    if (seen.has(key)) env.add("ARCHIVE_DUPLICATE_NAMES", { element: e.name, evidence: excerpt(e.name) });
    seen.add(key);
    if (e.isDir) continue;
    if (e.encrypted) encrypted++;
    else if (e.method !== 0 && e.method !== 8) unsupported++;
    if (e.usize > RATIO_MIN_SIZE && e.usize / Math.max(1, e.csize) > env.ctx.limits.maxCompressionRatio) {
      env.add("ARCHIVE_BOMB", { element: e.name, evidence: `declared ${e.usize} bytes from ${e.csize} compressed (ratio ${Math.round(e.usize / Math.max(1, e.csize))}:1)` });
    }
    if (e.dataStart < 0) env.add("ARCHIVE_CORRUPT", { element: e.name, detail: "An entry's local header is missing." });
    else if (e.dataStart + e.csize > zip.bytes.length) env.add("ARCHIVE_CORRUPT", { element: e.name, detail: "An entry extends past the end of the file." });
  }
  if (encrypted) env.add("ARCHIVE_ENCRYPTED", { evidence: `${encrypted} encrypted entr${encrypted === 1 ? "y" : "ies"}` });
  if (unsupported) env.add("ARCHIVE_UNSUPPORTED", { evidence: `${unsupported} entr${unsupported === 1 ? "y uses" : "ies use"} an unsupported compression method` });
  // Overlapping entries (Fifield's non-recursive zip bomb, parser confusion)
  const ranges = zip.entries
    .filter((e) => e.dataStart >= 0)
    .map((e) => ({ start: e.localOffset, end: e.dataStart + e.csize, name: e.name }))
    .sort((a, c) => a.start - c.start || a.end - c.end);
  for (let i = 1; i < ranges.length; i++) {
    const prev = ranges[i - 1]!;
    const cur = ranges[i]!;
    if (cur.start < prev.end) {
      env.add("ARCHIVE_OVERLAPPING_ENTRIES", { evidence: excerpt(`"${cur.name}" starts inside "${prev.name}"`) });
      break;
    }
  }
}

/**
 * @internal Decompresses an entry within the limits. Returns undefined when the entry
 * cannot or must not be decompressed (findings explain why).
 */
export function readEntry(env: Env, zip: Zip, e: ZipEntry): Uint8Array | undefined {
  if (e.isDir || e.encrypted || e.dataStart < 0 || (e.method !== 0 && e.method !== 8)) return undefined;
  const ctx = env.ctx;
  const end = Math.min(zip.bytes.length, e.dataStart + e.csize);
  const raw = zip.bytes.subarray(e.dataStart, end);
  const allowance = ctx.allowance();
  let data: Uint8Array;
  if (e.method === 0) {
    data = raw;
    if (raw.length > allowance) {
      limitHit(env, e, allowance);
      return undefined;
    }
  } else {
    // never decompress more than the ratio limit allows (declared sizes can lie)
    const ratioCap = Math.max(RATIO_MIN_SIZE, raw.length * ctx.limits.maxCompressionRatio);
    const cap = Math.min(allowance, ratioCap);
    const r = inflateRaw(raw, cap, (n) => ctx.step(n));
    ctx.inflated(r.data.length);
    if (r.status === "limit") {
      if (cap === ratioCap) env.add("ARCHIVE_BOMB", { element: e.name, evidence: `decompresses beyond ${ctx.limits.maxCompressionRatio}:1 (${raw.length} compressed bytes)` });
      else limitHit(env, e, allowance);
      return undefined;
    }
    if (r.status !== "ok") {
      env.add("ARCHIVE_CORRUPT", { element: e.name, detail: `The compressed data of an entry is ${r.status}.` });
      return r.data.length > 0 ? r.data : undefined;
    }
    data = r.data;
  }
  if (data.length !== e.usize && (e.flags & 8) === 0) {
    env.add("ARCHIVE_HEADER_MISMATCH", { element: e.name, evidence: `declared size ${e.usize}, actual ${data.length}` });
  } else if (e.crc !== 0 && data.length <= 64 << 20 && crc32(data) !== e.crc) {
    env.add("ARCHIVE_CORRUPT", { element: e.name, detail: "An entry fails its CRC-32 check." });
  }
  return data;
}

function limitHit(env: Env, e: ZipEntry, allowance: number): void {
  const name = allowance < env.ctx.limits.maxItemBytes ? "maxDecompressedBytes" : "maxItemBytes";
  env.ctx.hit(name);
  env.add("SCAN_LIMIT", { element: e.name, detail: `An entry was not inspected because it exceeds ${name}.` });
}
