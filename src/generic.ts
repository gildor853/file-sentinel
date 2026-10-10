/** Format-independent checks: EICAR, base64 blobs, entropy, polyglots, type mismatches. */
import { ascii, entropy, excerpt, indexOf, latin1, startsWith } from "./bytes.js";
import type { Env } from "./env.js";
import { extensionOf, FORMATS, formatInfo, KNOWN_EXTS, normalizeMime, knownMime } from "./formats.js";
import { longestBase64Run } from "./script-heuristics.js";
import { pdfHeaderOffset } from "./sniff.js";
import type { DetectedType } from "./types.js";
import { locateZip } from "./zip.js";

/** The 68-byte EICAR test string. */
const EICAR = ascii("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

/** @internal EICAR: the file starts with the test string, optionally followed by whitespace (up to 128 bytes in total). */
export function isEicar(b: Uint8Array): boolean {
  if (b.length > 128 || !startsWith(b, EICAR)) return false;
  for (let i = EICAR.length; i < b.length; i++) if (!" \t\r\n\x1a".includes(String.fromCharCode(b[i] as number))) return false;
  return true;
}

const TEXTUAL = new Set(["text", "html", "svg", "xml", "script", "rtf"]);
/** Base64 runs at least this long are reported (info). */
export const BASE64_REPORT = 32 * 1024;

/** @internal Info-level content observations for text and unknown data. */
export function contentStats(env: Env, detected: DetectedType): void {
  const b = env.item.bytes;
  if (TEXTUAL.has(detected.format) && detected.format !== "rtf") {
    const text = latin1(b, 0, Math.min(b.length, 64 << 20));
    env.ctx.step(text.length >>> 4);
    const run = longestBase64Run(text, 1 << 30);
    if (run >= BASE64_REPORT) env.add("BASE64_BLOB", { evidence: `${run} base64 characters` });
  } else if (detected.format === "unknown" && b.length >= 1024) {
    const n = Math.min(b.length, 1 << 20);
    env.ctx.step(n >>> 4);
    const h = entropy(b, 0, n);
    if (h >= 7.9) env.add("HIGH_ENTROPY", { evidence: `${h.toFixed(2)} bits/byte over ${n} bytes` });
  }
}

const NO_POLYGLOT_CHECK = new Set(["cfb", "doc", "xls", "ppt", "msg", "msi", "office-encrypted", "pe", "elf", "macho", "iso", "vhd", "zip", "jar", "apk", "epub", "tar", "gzip"]);

/** @internal Second formats hidden in the same bytes (ZIP directory, PDF header behind other data). */
export function polyglotChecks(env: Env, detected: DetectedType): void {
  const b = env.item.bytes;
  const f = detected.format;
  const already = () => env.ctx.findings.some((x) => x.id === "POLYGLOT" && x.location.path.join("\u0000") === env.item.path.join("\u0000"));
  const ooxmlish = formatInfo(f).mimes.includes("application/zip") || FORMATS[f]?.mime.includes("openxmlformats") === true || f.startsWith("od");
  if (f !== "pdf") {
    const k = pdfHeaderOffset(b);
    if (k > 0 && (indexOf(b, ascii("endobj")) >= 0 || indexOf(b, ascii("%%EOF")) >= 0)) {
      env.add("PDF_HEADER_OFFSET", { offset: k, evidence: `%PDF- at offset ${k}` });
      const unremarkable = f === "unknown" || f === "text" || f === "empty";
      if (!unremarkable && !already()) env.add("POLYGLOT", { offset: k, evidence: `${f} file with a PDF header at offset ${k}` });
      env.child(b.subarray(k), `pdf@${k}`);
    }
  }
  if (!NO_POLYGLOT_CHECK.has(f) && !ooxmlish && b.length >= 22) {
    const loc = locateZip(b);
    if (loc && loc.count > 0 && !already()) {
      const start = loc.prefix;
      env.add("POLYGLOT", { offset: start, evidence: `${f} file that is also a ZIP archive (${loc.count} entries)` });
      env.child(b.subarray(start, loc.end), `zip@${start}`);
    }
  }
}

const IMAGE = (f: string) => formatInfo(f).kind === "image";
const ZIP_BASED = new Set(["zip", "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb", "pptx", "pptm", "ppsx", "ppsm", "potx", "potm", "ooxml", "odt", "ods", "odp", "odg", "epub", "jar", "apk"]);
/** Extensions whose content cannot be reliably sniffed (no signature), so unknown content is not a mismatch. */
const WEAK_EXTS = new Set(["img", "bin", "dat", "tar", "ico", "iso", "db", "class", "txt", "csv", "tsv", "log", "md", "json", "ndjson", "css", "ini", "cfg", "conf", "yaml", "yml", "toml"]);

/** @internal Extension / MIME versus content. Returns true when a mismatch was reported. */
export function mismatchChecks(env: Env, detected: DetectedType): boolean {
  const f = detected.format;
  if (f === "empty") return false;
  const info = formatInfo(f);
  const executable = (info.kind === "executable" || info.kind === "script") && f !== "script";
  const active = f === "html" || f === "svg";
  let reported = false;
  const name = env.item.name;
  const ext = name ? extensionOf(name) : "";
  if (ext && KNOWN_EXTS.has(ext) && !info.exts.includes(ext)) {
    const extFormats = Object.entries(FORMATS).filter(([, v]) => v.exts.includes(ext)).map(([id]) => id);
    const extExecutable = extFormats.some((id) => ["executable", "script"].includes(formatInfo(id).kind)) || /^(?:js|jse|vbs|vbe|wsf|ps1|bat|cmd|sh|py)$/.test(ext);
    const extActive = ["html", "htm", "xhtml", "svg", "hta", "mht", "mhtml", "xml", "shtml", "xht"].includes(ext);
    const benign =
      (ext === "zip" && ZIP_BASED.has(f)) ||
      (f === "xml" && extActive) ||
      ((f === "text" || f === "unknown" || f === "script") && WEAK_EXTS.has(ext)) ||
      (f === "unknown" && extFormats.every((id) => formatInfo(id).kind === "text"));
    if (benign) {
      // a valid ZIP named .zip, text named .txt, ...
    } else if (executable && !extExecutable) {
      env.add("EXECUTABLE_DISGUISED", { element: "filename", evidence: excerpt(`${info.label} named .${ext}`) });
      reported = true;
    } else if (active && !extActive && ext !== "txt") {
      env.add("ACTIVE_CONTENT_DISGUISED", { element: "filename", evidence: excerpt(`${info.label} named .${ext}`) });
      reported = true;
    } else {
      const lowSeverity = IMAGE(f) && extFormats.some(IMAGE);
      env.add("TYPE_MISMATCH", { element: "filename", evidence: excerpt(`${info.label} named .${ext}`), severity: lowSeverity ? "low" : undefined });
      reported = true;
    }
  }
  const declared = env.item.declaredMime ? normalizeMime(env.item.declaredMime) : "";
  if (declared && declared !== "application/octet-stream" && knownMime(declared) && info.mime !== declared && !info.mimes.includes(declared)) {
    const textual = declared === "text/plain" && (TEXTUAL.has(f) && !active);
    const xml = (declared === "application/xml" || declared === "text/xml") && (f === "svg" || f === "xml");
    const zip = (declared === "application/zip" || declared === "application/x-zip-compressed") && ZIP_BASED.has(f);
    if (!textual && !xml && !zip) {
      const mimeExecutable = Object.values(FORMATS).some((v) => (v.mime === declared || v.mimes.includes(declared)) && (v.kind === "executable" || v.kind === "script"));
      const mimeActive = /html|svg|xml|javascript/.test(declared);
      if (executable && !mimeExecutable) env.add("EXECUTABLE_DISGUISED", { element: "mime", evidence: excerpt(`${info.label} declared as ${declared}`) });
      else if (active && !mimeActive) env.add("ACTIVE_CONTENT_DISGUISED", { element: "mime", evidence: excerpt(`${info.label} declared as ${declared}`) });
      else env.add("TYPE_MISMATCH", { element: "mime", evidence: excerpt(`${info.label} declared as ${declared}`), severity: IMAGE(f) && declared.startsWith("image/") ? "low" : undefined });
      reported = true;
    }
  }
  return reported;
}
