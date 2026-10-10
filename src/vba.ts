/** VBA project extraction (MS-OVBA) and keyword analysis in the spirit of olevba. */
import { decode, u16le, u32le } from "./bytes.js";

/** @internal MS-OVBA 2.4.1 decompression; returns what could be decompressed (never throws). */
export function ovbaDecompress(src: Uint8Array, start = 0, cap = 64 << 20): Uint8Array {
  if (src[start] !== 0x01) return new Uint8Array(0);
  let out = new Uint8Array(Math.min(cap, Math.max(4096, (src.length - start) * 3)));
  let len = 0;
  const ensure = (n: number) => {
    if (len + n <= out.length) return true;
    if (len + n > cap) return false;
    const next = new Uint8Array(Math.min(cap, Math.max(out.length * 2, len + n)));
    next.set(out.subarray(0, len));
    out = next;
    return true;
  };
  let p = start + 1;
  while (p + 2 <= src.length) {
    const header = u16le(src, p);
    const chunkSize = (header & 0x0fff) + 3;
    const compressed = (header & 0x8000) !== 0;
    const chunkEnd = Math.min(src.length, p + chunkSize);
    p += 2;
    const chunkStart = len;
    if (!compressed) {
      const n = Math.min(4096, src.length - p);
      if (!ensure(n)) break;
      out.set(src.subarray(p, p + n), len);
      len += n;
      p += 4096;
      continue;
    }
    while (p < chunkEnd) {
      const flags = src[p++] as number;
      for (let bit = 0; bit < 8 && p < chunkEnd; bit++) {
        if ((flags & (1 << bit)) === 0) {
          if (!ensure(1)) return out.subarray(0, len);
          out[len++] = src[p++] as number;
        } else {
          if (p + 2 > chunkEnd) {
            p = chunkEnd;
            break;
          }
          const token = u16le(src, p);
          p += 2;
          const d = len - chunkStart;
          let bitCount = 4;
          while (1 << bitCount < d) bitCount++;
          bitCount = Math.min(bitCount, 12);
          const lengthMask = 0xffff >>> bitCount;
          const offset = (token >>> (16 - bitCount)) + 1;
          const length = (token & lengthMask) + 3;
          if (offset > d) return out.subarray(0, len); // corrupt
          if (!ensure(length)) return out.subarray(0, len);
          for (let k = 0; k < length; k++, len++) out[len] = out[len - offset] as number;
        }
      }
    }
    p = chunkEnd;
  }
  return out.subarray(0, len);
}

/** @internal A module of a VBA project. */
export interface VbaModule {
  name: string;
  stream: string;
  offset: number;
}

/** @internal Parses a decompressed `dir` stream (MS-OVBA 2.3.4.2). */
export function parseDir(dir: Uint8Array): { codepage: number; modules: VbaModule[] } {
  let codepage = 1252;
  const modules: VbaModule[] = [];
  let cur: VbaModule | undefined;
  let p = 0;
  let guard = 0;
  while (p + 6 <= dir.length && guard++ < 100_000) {
    const id = u16le(dir, p);
    let size = u32le(dir, p + 2);
    if (id === 0x0009) size = 6; // PROJECTVERSION: Size is 4 but 6 bytes follow
    const data = dir.subarray(p + 6, Math.min(dir.length, p + 6 + size));
    p += 6 + size;
    switch (id) {
      case 0x0003:
        codepage = u16le(data, 0);
        break;
      case 0x0019:
        cur = { name: decode(data, "windows-1252"), stream: "", offset: 0 };
        modules.push(cur);
        break;
      case 0x0047:
        if (cur) cur.name = decode(data, "utf-16le") || cur.name;
        break;
      case 0x001a:
        if (cur) cur.stream = decode(data, "windows-1252");
        break;
      case 0x0032:
        if (cur && data.length > 0) cur.stream = decode(data, "utf-16le") || cur.stream;
        break;
      case 0x0031:
        if (cur) cur.offset = u32le(data, 0);
        break;
      default:
        break;
    }
  }
  return { codepage, modules };
}

/** @internal TextDecoder label for a Windows code page. */
export function codepageLabel(cp: number): string {
  if (cp === 65001) return "utf-8";
  if (cp === 932) return "shift_jis";
  if (cp === 936) return "gbk";
  if (cp === 949) return "euc-kr";
  if (cp === 950) return "big5";
  if (cp >= 874 && cp <= 1258) return `windows-${cp}`;
  if (cp === 10000) return "macintosh";
  return "windows-1252";
}

/** Auto-executing procedure names (olevba AUTOEXEC_KEYWORDS, Microsoft "Auto macros" documentation). */
export const AUTOEXEC_NAMES: readonly string[] = [
  "AutoExec", "AutoOpen", "DocumentOpen", "AutoExit", "AutoClose", "Document_Close", "DocumentBeforeClose", "DocumentChange", "AutoNew",
  "Document_New", "NewDocument", "Document_Open", "Document_BeforeClose", "Auto_Open", "Workbook_Open", "Workbook_Activate", "Auto_Close",
  "Workbook_Close", "Workbook_BeforeClose", "Worksheet_Calculate",
];
/** ActiveX control events that fire without deliberate user action (olevba AUTOEXEC_KEYWORDS_REGEX subset). */
const AUTOEXEC_EVENTS = ["Painted", "Painting", "GotFocus", "Layout", "Resize", "DocumentComplete", "NavigateComplete2", "BeforeNavigate2", "MouseHover", "MouseEnter", "ContentControlOnEnter"];

/** Curated high-signal subset of olevba SUSPICIOUS_KEYWORDS. */
const SUSPICIOUS: readonly (readonly [string, RegExp])[] = [
  ["Shell", /(?:^|[^\w.])Shell\s{0,10}[("]|(?:^|[^\w.])Shell\s{1,10}\w/im],
  ["WScript.Shell", /WScript\.Shell/i],
  ["Shell.Application", /Shell\.Application/i],
  ["ShellExecute", /\bShellExecute/i],
  ["PowerShell", /\bpowershell/i],
  ["cmd.exe /c", /\bcmd(?:\.exe)?\s{1,10}\/[ck]\b/i],
  ["mshta", /\bmshta\b/i],
  ["URLDownloadToFile", /\bURLDownloadToFile/i],
  ["XMLHTTP", /XMLHTTP/i],
  ["WinHttpRequest", /WinHttp\.WinHttpRequest/i],
  ["Net.WebClient", /Net\.WebClient/i],
  ["ADODB.Stream", /ADODB\.Stream/i],
  ["SaveToFile", /\.SaveToFile\b/i],
  ["WMI Win32_Process", /winmgmts:|Win32_Process/i],
  ["CreateThread", /\bCreateThread\b/i],
  ["VirtualAlloc", /\bVirtualAlloc/i],
  ["RtlMoveMemory", /\bRtlMoveMemory\b/i],
  ["WriteProcessMemory", /\bWriteProcessMemory\b/i],
  ["EnumSystemLanguageGroups/callback execution", /\b(?:EnumSystemLanguageGroupsW?|EnumDateFormats\w*|EnumWindows|CallWindowProc\w*)\b/i],
  ["CallByName", /\bCallByName\b/i],
  ["ExecuteExcel4Macro", /\bExecuteExcel4Macro\b/i],
  ["MacScript", /\bMacScript\b/i],
  ["Trust Center tampering (AccessVBOM/VBAWarnings)", /\bAccessVBOM\b|\bVBAWarnings\b/i],
  ["VBProject code modification", /\.VBProject\b|\.CodeModule\b/i],
  ["Run via Application.Run on a string", /Application\.Run\s{0,10}\(?\s{0,10}"/i],
  ["certutil -decode", /certutil(?:\.exe)?\s{1,10}-(?:decode|urlcache)/i],
  ["regsvr32/rundll32", /\b(?:regsvr32|rundll32)(?:\.exe)?\b/i],
  ["schtasks", /\bschtasks\b/i],
];

/** @internal Removes comment lines and trailing comments (outside string literals) so keywords in comments do not count. */
export function stripComments(src: string): string {
  const out: string[] = [];
  for (const line of src.split(/\r\n|\r|\n/)) {
    if (/^\s*(?:'|Rem\b)/i.test(line) || /^\s*Attribute\s/i.test(line)) continue;
    let inStr = false;
    let cut = line.length;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') inStr = !inStr;
      else if (c === "'" && !inStr) {
        cut = i;
        break;
      }
    }
    out.push(line.slice(0, cut));
  }
  return out.join("\n");
}

/** @internal Keyword analysis result for one module. */
export interface VbaAnalysis {
  autoexec: string[];
  suspicious: string[];
  chrCalls: number;
}

/** @internal Analyzes VBA source code. */
export function analyzeVba(source: string): VbaAnalysis {
  const code = stripComments(source);
  const autoexec = new Set<string>();
  const proc = /^[ \t]{0,100}(?:(?:Public|Private|Friend|Static)[ \t]{1,10}){0,2}(?:Sub|Function)[ \t]{1,10}([A-Za-z_][A-Za-z0-9_]{0,200})/gim;
  const autoLower = new Map(AUTOEXEC_NAMES.map((n) => [n.toLowerCase(), n]));
  for (let m = proc.exec(code); m; m = proc.exec(code)) {
    const name = m[1] as string;
    const known = autoLower.get(name.toLowerCase());
    if (known) autoexec.add(known);
    else {
      const us = name.lastIndexOf("_");
      if (us > 0 && AUTOEXEC_EVENTS.some((e) => e.toLowerCase() === name.slice(us + 1).toLowerCase())) autoexec.add(name);
    }
  }
  const suspicious = SUSPICIOUS.filter(([, re]) => re.test(code)).map(([k]) => k);
  let chrCalls = 0;
  const chr = /\bChr[WB]?\$?\s{0,10}\(/gi;
  while (chr.exec(code) && chrCalls < 100_000) chrCalls++;
  return { autoexec: [...autoexec], suspicious, chrCalls };
}

/** Chr() calls in one module above which string building is treated as obfuscation. */
export const CHR_OBFUSCATION_THRESHOLD = 50;
