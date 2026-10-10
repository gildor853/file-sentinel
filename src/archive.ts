/** Archive handlers: ZIP (and ZIP-based formats), GZIP, TAR, and formats that are only identified. */
import { decode, excerpt, latin1, u16le } from "./bytes.js";
import type { Env } from "./env.js";
import { detectedType, formatInfo } from "./formats.js";
import { inflateRaw } from "./inflate.js";
import { analyzeOdf, analyzeOoxml, PartReader } from "./ooxml.js";
import type { DetectedType } from "./types.js";
import { isTraversal, openZip } from "./zip.js";

const RATIO_MIN_SIZE = 1 << 20;

function nested(env: Env, child: DetectedType | undefined, name: string): void {
  if (child && formatInfo(child.format).kind === "archive") env.add("ARCHIVE_NESTED", { element: name, evidence: excerpt(`${name} (${child.format})`) });
}

/** @internal ZIP handler; also identifies and analyzes OOXML, OpenDocument, EPUB, JAR and APK. */
export function scanZip(env: Env, detected: DetectedType): DetectedType {
  const zip = openZip(env, env.item.bytes);
  if (!zip) return detected;
  const parts = new PartReader(env, zip);
  let type = detected;
  const ct = parts.entry("[Content_Types].xml");
  const first = zip.entries[0];
  const mimetype = first && first.name === "mimetype" ? parts.text("mimetype") : undefined;
  if (ct) {
    const xml = parts.text(ct.name);
    if (xml !== undefined) type = analyzeOoxml(env, parts, xml);
  } else if (mimetype?.startsWith("application/vnd.oasis.opendocument.")) {
    type = analyzeOdf(env, parts, mimetype);
  } else if (mimetype?.trim() === "application/epub+zip") {
    type = detectedType("epub", "high");
  } else if (parts.entry("AndroidManifest.xml") && parts.entry("classes.dex")) {
    type = detectedType("apk", "high");
  } else if (parts.entry("META-INF/MANIFEST.MF") || zip.entries.some((e) => e.name.endsWith(".class"))) {
    type = detectedType("jar", parts.entry("META-INF/MANIFEST.MF") ? "high" : "medium");
  } else type = detectedType("zip", "high");
  const container = type.format === "zip";
  for (const e of zip.entries) {
    if (e.isDir || e.encrypted || e.symlink) continue;
    const data = parts.take(e);
    if (data === undefined) continue;
    const child = env.child(data, e.name, e.name);
    if (container) nested(env, child, e.name);
  }
  return type;
}

/** @internal GZIP handler (first member). */
export function scanGzip(env: Env, detected: DetectedType): DetectedType {
  const b = env.item.bytes;
  const flags = b[3] ?? 0;
  let p = 10;
  if (flags & 4) p += 2 + u16le(b, p);
  let name: string | undefined;
  const cstr = () => {
    let e = p;
    while (e < b.length && b[e] !== 0) e++;
    const s = latin1(b, p, Math.min(e, p + 1024));
    p = e + 1;
    return s;
  };
  if (flags & 8) name = cstr();
  if (flags & 16) cstr();
  if (flags & 2) p += 2;
  if (p >= b.length) {
    env.add("ARCHIVE_CORRUPT", { detail: "The GZIP header is truncated." });
    return detected;
  }
  const ctx = env.ctx;
  const compressed = b.length - p;
  const ratioCap = Math.max(RATIO_MIN_SIZE, compressed * ctx.limits.maxCompressionRatio);
  const allowance = ctx.allowance();
  const cap = Math.min(allowance, ratioCap);
  const r = inflateRaw(b, cap, (n) => ctx.step(n), p);
  ctx.inflated(r.data.length);
  if (r.status === "limit") {
    if (cap === ratioCap) env.add("ARCHIVE_BOMB", { evidence: `decompresses beyond ${ctx.limits.maxCompressionRatio}:1 (${compressed} compressed bytes)` });
    else {
      const limit = allowance < ctx.limits.maxItemBytes ? "maxDecompressedBytes" : "maxItemBytes";
      ctx.hit(limit);
      env.add("SCAN_LIMIT", { detail: `Only the first ${r.data.length} decompressed bytes were inspected (${limit}).` });
    }
  } else if (r.status !== "ok") env.add("ARCHIVE_CORRUPT", { detail: `The compressed stream is ${r.status}.` });
  const inner = name ?? (env.item.name ? env.item.name.replace(/\.(?:gz|tgz)$/i, (m) => (m.toLowerCase() === ".tgz" ? ".tar" : "")) : undefined);
  if (r.data.length > 0) nested(env, env.child(r.data, inner ?? "(gzip content)", inner), inner ?? "(gzip content)");
  return detected;
}

function octal(b: Uint8Array, o: number, n: number): number {
  if (((b[o] ?? 0) & 0x80) !== 0) {
    // GNU base-256
    let v = 0;
    for (let i = 1; i < n; i++) v = v * 256 + (b[o + i] ?? 0);
    return v;
  }
  const s = latin1(b, o, o + n).replace(/[\0 ]+$/, "").trim();
  return /^[0-7]{1,22}$/.test(s) ? parseInt(s, 8) : NaN;
}

const cstrAt = (b: Uint8Array, o: number, n: number) => {
  const s = b.subarray(o, o + n);
  const z = s.indexOf(0);
  return decode(z >= 0 ? s.subarray(0, z) : s, "utf-8");
};

/** @internal TAR handler (ustar, GNU long names, pax path). */
export function scanTar(env: Env, detected: DetectedType): DetectedType {
  const b = env.item.bytes;
  let p = 0;
  let longName: string | undefined;
  let count = 0;
  const seen = new Set<string>();
  while (p + 512 <= b.length) {
    env.ctx.step(8);
    if (b[p] === 0 && b.subarray(p, p + 512).every((x) => x === 0)) break;
    const size = octal(b, p + 124, 12);
    if (Number.isNaN(size)) {
      env.add("ARCHIVE_CORRUPT", { offset: p, detail: "A TAR header is damaged." });
      break;
    }
    if (++count > env.ctx.limits.maxEntries) {
      env.ctx.hit("maxEntries");
      env.add("SCAN_LIMIT", { detail: `Only the first ${env.ctx.limits.maxEntries} entries were inspected (maxEntries).` });
      break;
    }
    const h = p;
    const typeflag = String.fromCharCode(b[p + 156] ?? 0);
    const prefix = latin1(b, p + 257, p + 263) === "ustar\0" || latin1(b, p + 257, p + 262) === "ustar" ? cstrAt(b, p + 345, 155) : "";
    let name = longName ?? (prefix ? `${prefix}/${cstrAt(b, p, 100)}` : cstrAt(b, p, 100));
    longName = undefined;
    const dataStart = p + 512;
    const dataEnd = Math.min(b.length, dataStart + size);
    p = dataStart + Math.ceil(size / 512) * 512;
    if (typeflag === "L") {
      longName = cstrAt(b, dataStart, Math.min(size, 4096));
      continue;
    }
    if (typeflag === "x") {
      const pax = decode(b.subarray(dataStart, Math.min(dataEnd, dataStart + 65536)), "utf-8");
      const m = /(?:^|\n)\d{1,10} path=([^\n]{1,4096})/.exec(pax);
      if (m) longName = m[1];
      continue;
    }
    if (typeflag === "g") continue;
    name = name.replace(/^\.\//, "");
    if (isTraversal(name)) env.add("ARCHIVE_PATH_TRAVERSAL", { element: name, evidence: excerpt(name) });
    if (seen.has(name)) env.add("ARCHIVE_DUPLICATE_NAMES", { element: name, evidence: excerpt(name) });
    seen.add(name);
    if (typeflag === "1" || typeflag === "2") {
      const target = cstrAt(b, h + 157, 100);
      env.add("ARCHIVE_SYMLINK", { element: name, evidence: excerpt(`${name} -> ${target}`) });
      continue;
    }
    if (typeflag !== "0" && typeflag !== "\0" && typeflag !== "7") continue;
    if (dataStart + size > b.length) env.add("ARCHIVE_CORRUPT", { element: name, detail: "An entry extends past the end of the file." });
    if (dataEnd > dataStart) nested(env, env.child(b.subarray(dataStart, dataEnd), name, name), name);
  }
  return detected;
}

/** @internal Archive and disk-image formats that are identified but not unpacked. */
export function scanOpaqueArchive(env: Env, detected: DetectedType): DetectedType {
  env.add("ARCHIVE_UNSUPPORTED", { evidence: `${formatInfo(detected.format).label} contents are not unpacked` });
  return detected;
}
