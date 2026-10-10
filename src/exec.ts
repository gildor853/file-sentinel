/** Executables, scripts and disk images: identification details. */
import { excerpt, latin1, u16le, u32be, u32le } from "./bytes.js";
import type { Env } from "./env.js";
import { extensionOf, formatInfo } from "./formats.js";
import type { DetectedType } from "./types.js";

/** Script extensions run by a Windows script host or shell on double click. */
export const SCRIPT_EXTS: ReadonlySet<string> = new Set(["js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "sct", "ps1", "psm1", "bat", "cmd", "hta", "reg", "url", "scf", "iqy", "slk", "settingcontent-ms", "sh", "command"]);

function peInfo(b: Uint8Array): string {
  const pe = u32le(b, 0x3c);
  if (latin1(b, pe, pe + 4) !== "PE\0\0") return "MS-DOS executable";
  const machine = u16le(b, pe + 4);
  const chars = u16le(b, pe + 22);
  const opt = pe + 24;
  const magic = u16le(b, opt);
  const subsystem = u16le(b, opt + 68);
  const dirs = opt + (magic === 0x20b ? 112 : 96);
  const clr = u32le(b, dirs + 14 * 8) !== 0;
  const arch = machine === 0x8664 ? "x64" : machine === 0x14c ? "x86" : machine === 0xaa64 ? "ARM64" : `machine 0x${machine.toString(16)}`;
  const kind = chars & 0x2000 ? "DLL" : subsystem === 2 ? "GUI executable" : subsystem === 3 ? "console executable" : subsystem === 1 ? "driver" : "executable";
  return `PE${magic === 0x20b ? "32+" : "32"} ${arch} ${kind}${clr ? " (.NET)" : ""}`;
}

function elfInfo(b: Uint8Array): string {
  const cls = b[4] === 2 ? "64-bit" : "32-bit";
  const le = b[5] !== 2;
  const type = le ? u16le(b, 16) : (b[16]! << 8) | b[17]!;
  return `ELF ${cls} ${type === 2 ? "executable" : type === 3 ? "shared object" : type === 1 ? "relocatable" : type === 4 ? "core dump" : "file"}`;
}

function machoInfo(b: Uint8Array): string {
  const m = u32be(b, 0);
  if (m === 0xcafebabe) return `Mach-O universal binary (${u32be(b, 4)} architectures)`;
  return `Mach-O ${m === 0xfeedfacf || m === 0xcffaedfe ? "64-bit" : "32-bit"}`;
}

/** @internal Reports executables, scripts and disk images. */
export function scanExecutable(env: Env, detected: DetectedType): DetectedType {
  const b = env.item.bytes;
  switch (detected.format) {
    case "pe":
      env.add("EXECUTABLE", { evidence: peInfo(b) });
      break;
    case "elf":
      env.add("EXECUTABLE", { evidence: elfInfo(b) });
      break;
    case "macho":
      env.add("EXECUTABLE", { evidence: machoInfo(b) });
      break;
    case "iso":
    case "vhd":
      env.add("DISK_IMAGE", { evidence: formatInfo(detected.format).label });
      break;
    case "script-encoded":
      env.add("SCRIPT_ENCODED", { evidence: excerpt(latin1(b, 0, 60)) });
      break;
    default:
      env.add(formatInfo(detected.format).kind === "script" ? "SCRIPT_FILE" : "EXECUTABLE", { evidence: formatInfo(detected.format).label });
  }
  return detected;
}

/** @internal Text content that a Windows script host or shell would run, judged by its name or a shebang. */
export function scriptByName(env: Env, detected: DetectedType): void {
  if (detected.format !== "text" && detected.format !== "script") return;
  const ext = env.item.name ? extensionOf(env.item.name) : "";
  if (detected.format === "script" || SCRIPT_EXTS.has(ext)) env.add("SCRIPT_FILE", { evidence: ext ? `.${ext}` : "shebang script" });
}
