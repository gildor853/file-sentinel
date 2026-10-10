/** Windows shortcut (MS-SHLLINK) parsing: target path and command-line arguments. */
import { decode, excerpt, latin1, u16le, u32le } from "./bytes.js";
import type { Env } from "./env.js";
import type { DetectedType } from "./types.js";

/** @internal Parsed shortcut fields. */
export interface LnkInfo {
  target: string;
  arguments: string;
  workingDir: string;
  relativePath: string;
  icon: string;
  name: string;
}

/** @internal Parses the fields of a shell link; never throws. */
export function parseLnk(b: Uint8Array): LnkInfo {
  const flags = u32le(b, 0x14);
  const unicode = (flags & 0x80) !== 0;
  let p = 0x4c;
  const idNames: string[] = [];
  if (flags & 0x01) {
    const size = u16le(b, p);
    const end = Math.min(b.length, p + 2 + size);
    let q = p + 2;
    while (q + 2 <= end) {
      const isz = u16le(b, q);
      if (isz < 2) break;
      const item = b.subarray(q, Math.min(end, q + isz));
      const type = item[2] ?? 0;
      if (type === 0x2f) idNames.push(latin1(item, 3, Math.max(3, item.indexOf(0, 3)))); // drive "C:\"
      else if ((type & 0x70) === 0x30) {
        const z = item.indexOf(0, 14);
        idNames.push(latin1(item, 14, z < 0 ? item.length : z)); // file entry short name
      }
      q += isz;
    }
    p = end;
  }
  let target = "";
  if (flags & 0x02) {
    const size = u32le(b, p);
    const li = b.subarray(p, Math.min(b.length, p + size));
    const liFlags = u32le(li, 8);
    const headerSize = u32le(li, 4);
    const cstr = (o: number) => {
      if (o <= 0 || o >= li.length) return "";
      const z = li.indexOf(0, o);
      return decode(li.subarray(o, z < 0 ? li.length : z), "windows-1252");
    };
    const wstr = (o: number) => {
      if (o <= 0 || o >= li.length) return "";
      let e = o;
      while (e + 1 < li.length && (li[e] !== 0 || li[e + 1] !== 0)) e += 2;
      return decode(li.subarray(o, e), "utf-16le");
    };
    let base = "";
    if (liFlags & 1) base = headerSize >= 0x24 ? wstr(u32le(li, 28)) || cstr(u32le(li, 16)) : cstr(u32le(li, 16));
    if (liFlags & 2 && !base) {
      const net = u32le(li, 20);
      if (net > 0 && net < li.length) base = cstr(net + u32le(li, net + 8));
    }
    const suffix = headerSize >= 0x24 ? wstr(u32le(li, 32)) || cstr(u32le(li, 24)) : cstr(u32le(li, 24));
    target = base + (suffix && !base.endsWith("\\") ? `\\${suffix}` : suffix);
    p += Math.max(4, size);
  }
  const str = () => {
    const count = u16le(b, p);
    const bytes = unicode ? count * 2 : count;
    const s = unicode ? decode(b.subarray(p + 2, p + 2 + bytes), "utf-16le") : decode(b.subarray(p + 2, p + 2 + bytes), "windows-1252");
    p += 2 + bytes;
    return s;
  };
  const name = flags & 0x04 ? str() : "";
  const relativePath = flags & 0x08 ? str() : "";
  const workingDir = flags & 0x10 ? str() : "";
  const args = flags & 0x20 ? str() : "";
  const icon = flags & 0x40 ? str() : "";
  if (!target) target = idNames.join("\\").replace(/\\\\+/g, "\\") || relativePath;
  return { target, arguments: args, workingDir, relativePath, icon, name };
}

/** Interpreters and LOLBins commonly started from malicious shortcuts (MITRE ATT&CK T1218, T1059). */
const LOLBINS = /(?:^|[\\/\s"'])(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|msiexec|conhost|forfiles|wmic|schtasks|msbuild|installutil|regasm|regsvcs|odbcconf|cmstp|hh|explorer|bash|wsl|ftp|finger|scriptrunner|pcalua|msdt)(?:\.exe)?(?=$|[\s"',;&|])/i;

/** @internal LNK handler. */
export function scanLnk(env: Env, detected: DetectedType): DetectedType {
  const info = parseLnk(env.item.bytes);
  const cmd = `${info.target} ${info.arguments}`.trim();
  env.add("LNK_FILE", { evidence: excerpt(cmd || info.relativePath || "(no target)") });
  const reasons: string[] = [];
  if (LOLBINS.test(info.target) || LOLBINS.test(info.relativePath) || LOLBINS.test(` ${info.arguments}`)) reasons.push("interpreter or LOLBin");
  if (info.arguments.length > 260) reasons.push(`${info.arguments.length}-character arguments`);
  if (/\s{50}/.test(info.arguments)) reasons.push("whitespace-padded arguments");
  if (/https?:\/\/|\\\\[\w.-]+\\/i.test(info.arguments)) reasons.push("remote location in arguments");
  if (reasons.length) env.add("LNK_SUSPICIOUS_COMMAND", { evidence: excerpt(`${reasons.join(", ")}: ${cmd}`) });
  return detected;
}
