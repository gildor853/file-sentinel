/** Legacy Office / OLE compound files: VBA, XLM macro sheets, encryption, OLE packages, Equation Editor, Outlook attachments. */
import { decode, excerpt, latin1, u16le, u32le } from "./bytes.js";
import { type Cfb, type CfbEntry, CfbError, openCfb } from "./cfb.js";
import type { Env } from "./env.js";
import { detectedType } from "./formats.js";
import type { DetectedType } from "./types.js";
import { analyzeVba, CHR_OBFUSCATION_THRESHOLD, codepageLabel, ovbaDecompress, parseDir } from "./vba.js";

const MSI_CLSIDS = new Set(["{000C1084-0000-0000-C000-000000000046}", "{000C1086-0000-0000-C000-000000000046}", "{000C108A-0000-0000-C000-000000000046}"]);
/** Equation Editor 3.0 (Equation.3) class id. */
export const EQUATION_CLSID = "{0002CE02-0000-0000-C000-000000000046}";

const lc = (s: string) => s.toLowerCase();

/** @internal Reads a stream, returning undefined (and noting the problem) on damage. */
function readSafe(env: Env, cfb: Cfb, e: CfbEntry): Uint8Array | undefined {
  try {
    const data = cfb.read(e);
    env.ctx.step(data.length >>> 6);
    return data;
  } catch (err) {
    if (err instanceof CfbError) {
      env.addAt([e.path.join("/")], "ARCHIVE_CORRUPT", { detail: `A compound-file stream could not be read (${err.message}).` });
      return undefined;
    }
    throw err;
  }
}

/** @internal Extracts and analyzes the VBA projects found in a compound file. Returns the number of modules. */
export function scanVbaProjects(env: Env, cfb: Cfb, segment: readonly string[] = []): number {
  let total = 0;
  const byParent = new Map<string, CfbEntry[]>();
  for (const e of cfb.entries) {
    const key = e.path.slice(0, -1).map(lc).join("/");
    const list = byParent.get(key);
    if (list) list.push(e);
    else byParent.set(key, [e]);
  }
  for (const [parent, children] of byParent) {
    const dirEntry = children.find((c) => c.type === 2 && lc(c.name) === "dir");
    if (!dirEntry) continue;
    const parentPath = parent.split("/");
    const grand = parentPath.slice(0, -1).join("/");
    const hasProject = (byParent.get(grand) ?? []).some((c) => lc(c.name) === "_vba_project") || children.some((c) => lc(c.name) === "_vba_project");
    if (!hasProject) continue;
    const dirBytes = readSafe(env, cfb, dirEntry);
    if (!dirBytes) continue;
    const dir = ovbaDecompress(dirBytes, 0, 4 << 20);
    env.ctx.inflated(dir.length);
    const { codepage, modules } = parseDir(dir);
    const label = codepageLabel(codepage);
    const where = [...segment, dirEntry.path.slice(0, -1).join("/")];
    env.addAt(where, "OFFICE_VBA_MACROS", { evidence: excerpt(`${modules.length} module(s): ${modules.map((m) => m.name).join(", ")}`) });
    for (const m of modules) {
      const se = children.find((c) => c.type === 2 && lc(c.name) === lc(m.stream || m.name));
      if (!se) continue;
      const raw = readSafe(env, cfb, se);
      if (!raw) continue;
      const src = ovbaDecompress(raw, m.offset, env.ctx.allowance());
      env.ctx.inflated(src.length);
      total++;
      analyzeSource(env, [...where, m.name], decode(src, label));
    }
  }
  return total;
}

/** @internal Reports VBA_AUTOEXEC / VBA_SUSPICIOUS for one module's source. */
export function analyzeSource(env: Env, where: readonly string[], source: string): void {
  env.ctx.step(source.length >>> 4);
  const a = analyzeVba(source);
  if (a.autoexec.length) env.addAt(where, "VBA_AUTOEXEC", { evidence: excerpt(a.autoexec.join(", ")) });
  const susp = [...a.suspicious];
  if (a.chrCalls >= CHR_OBFUSCATION_THRESHOLD) susp.push(`Chr() string building (${a.chrCalls} calls)`);
  if (susp.length) env.addAt(where, "VBA_SUSPICIOUS", { evidence: excerpt(susp.join(", ")) });
}

/** BIFF8 workbook globals: macro sheets, Auto_Open names and encryption. */
function scanWorkbook(env: Env, wb: Uint8Array, where: readonly string[]): boolean {
  let p = 0;
  let encrypted = false;
  let guard = 0;
  while (p + 4 <= wb.length && guard++ < 200_000) {
    const id = u16le(wb, p);
    const len = u16le(wb, p + 2);
    const d = wb.subarray(p + 4, p + 4 + len);
    p += 4 + len;
    if (id === 0x000a) break; // EOF of the globals substream
    if (id === 0x002f) {
      encrypted = true;
      break; // the remaining records are encrypted
    }
    if (id === 0x0085 && d.length >= 8) {
      const hs = (d[4] as number) & 3;
      const dt = d[5] as number;
      const cch = d[6] as number;
      const wide = ((d[7] as number) & 1) === 1;
      const name = wide ? decode(d.subarray(8, 8 + cch * 2), "utf-16le") : latin1(d, 8, 8 + cch);
      if (dt === 1) {
        env.addAt(where, "XLM_MACRO_SHEET", { element: name, evidence: excerpt(`${name} (${hs === 2 ? "very hidden" : hs === 1 ? "hidden" : "visible"})`) });
      }
    }
    if (id === 0x0018 && d.length >= 15) {
      const builtin = (u16le(d, 0) & 0x20) !== 0;
      const flags = d[14] as number;
      const code = d[15];
      if (builtin && (flags & 1) === 0 && code === 0x01) env.addAt(where, "XLM_AUTO_OPEN", { evidence: "built-in name Auto_Open" });
      if (builtin && (flags & 1) === 1 && u16le(d, 15) === 0x01) env.addAt(where, "XLM_AUTO_OPEN", { evidence: "built-in name Auto_Open" });
    }
  }
  return encrypted;
}

/** @internal Parses an OLE1 Ole10Native stream: returns label and embedded file bytes. */
export function parseOle10Native(b: Uint8Array, start = 6): { label: string; path: string; data: Uint8Array } | undefined {
  // [u32 total size], u16 flags, label\0, source path\0, u32 reserved, u32 temp-path length, temp path\0, u32 data size, data
  let p = start;
  const cstr = () => {
    let e = p;
    while (e < b.length && b[e] !== 0 && e - p < 1024) e++;
    const s = decode(b.subarray(p, e), "windows-1252");
    p = e + 1;
    return s;
  };
  if (b.length < 12) return undefined;
  const label = cstr();
  const path = cstr();
  p += 4;
  const tmpLen = u32le(b, p);
  p += 4 + Math.min(tmpLen, 4096);
  const size = u32le(b, p);
  p += 4;
  if (p > b.length) return undefined;
  return { label, path, data: b.subarray(p, Math.min(b.length, p + size)) };
}

/** @internal Handler for compound files (doc, xls, ppt, msi, msg, vbaProject.bin, OLE objects). */
export function scanCfb(env: Env, detected: DetectedType): DetectedType {
  let cfb: Cfb;
  try {
    cfb = openCfb(env.item.bytes, (n) => env.ctx.step(n), env.ctx.limits.maxEntries);
  } catch (err) {
    if (err instanceof CfbError) {
      env.add("ARCHIVE_CORRUPT", { detail: `The compound file could not be parsed (${err.message}).` });
      return detected;
    }
    throw err;
  }
  const top = (n: string) => cfb.entries.find((e) => e.path.length === 1 && lc(e.name) === lc(n));
  let type = detected;
  if (MSI_CLSIDS.has(cfb.root.clsid)) type = detectedType("msi", "high");
  else if (top("EncryptionInfo") && top("EncryptedPackage")) {
    type = detectedType("office-encrypted", "high");
    env.add("OFFICE_ENCRYPTED", { evidence: "EncryptionInfo + EncryptedPackage streams" });
  } else if (top("WordDocument")) type = detectedType("doc", "high");
  else if (top("Workbook") || top("Book")) type = detectedType("xls", "high");
  else if (top("PowerPoint Document")) type = detectedType("ppt", "high");
  else if (top("__properties_version1.0")) type = detectedType("msg", "high");
  if (type.format === "msi") return type; // installer databases are reported as executables by the caller

  // Word: FIB fEncrypted
  const word = top("WordDocument");
  if (word) {
    const fib = readSafe(env, cfb, word);
    if (fib && u16le(fib, 0) === 0xa5ec && (u16le(fib, 0x0a) & 0x0100) !== 0) env.add("OFFICE_ENCRYPTED", { evidence: "Word FIB fEncrypted flag" });
  }
  const wbEntry = top("Workbook") ?? top("Book");
  if (wbEntry) {
    const wb = readSafe(env, cfb, wbEntry);
    if (wb && scanWorkbook(env, wb, [wbEntry.name])) env.add("OFFICE_ENCRYPTED", { evidence: "Excel FILEPASS record" });
  }
  if (top("PowerPoint Document") && top("EncryptedSummary")) env.add("OFFICE_ENCRYPTED", { evidence: "PowerPoint EncryptedSummary stream" });

  scanVbaProjects(env, cfb);

  if (cfb.root.clsid === EQUATION_CLSID || cfb.entries.some((e) => e.clsid === EQUATION_CLSID)) env.add("OLE_EQUATION_EDITOR", { evidence: `CLSID ${EQUATION_CLSID}` });
  let children = 0;
  for (const e of cfb.entries) {
    if (e.type !== 2) continue;
    const name = lc(e.name);
    const where = e.path.join("/");
    if (name === "equation native") env.addAt([where], "OLE_EQUATION_EDITOR", { evidence: "Equation Native stream" });
    if (name === "\u0001ole10native") {
      const data = readSafe(env, cfb, e);
      const pkg = data && parseOle10Native(data);
      if (pkg) {
        env.addAt([where], "OLE_PACKAGE", { evidence: excerpt(`${pkg.label} (${pkg.path})`) });
        if (pkg.data.length > 0) env.child(pkg.data, where, pkg.label || pkg.path);
      }
    } else if (name === "package" || name === "contents" && e.size > 0 && cfb.entries.length < 8) {
      // embedded OOXML package or raw embedded file of an OLE object
      const data = readSafe(env, cfb, e);
      if (data && data.length > 0) env.child(data, where);
    } else if (type.format === "msg" && /^__substg1\.0_37010102$/i.test(e.name) && children < env.ctx.limits.maxEntries) {
      // Outlook attachment data; the long file name is in a sibling stream
      const sib = cfb.entries.find((s) => s.path.length === e.path.length && s.path.slice(0, -1).join("/") === e.path.slice(0, -1).join("/") && /^__substg1\.0_3707001F$/i.test(s.name));
      const nameBytes = sib && readSafe(env, cfb, sib);
      const data = readSafe(env, cfb, e);
      children++;
      if (data && data.length > 0) env.child(data, e.path.slice(0, -1).join("/"), nameBytes ? decode(nameBytes, "utf-16le").replace(/\0+$/, "") : undefined);
    }
  }
  return type;
}
