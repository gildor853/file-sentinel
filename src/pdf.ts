/**
 * Lenient PDF analysis: a linear lexer that skips stream data, a small value
 * parser, object streams, and keyword checks modeled on Didier Stevens' pdfid.
 * Nothing is rendered or executed; JavaScript is only quoted as evidence.
 */
import { decode, excerpt, indexOf, latin1 } from "./bytes.js";
import type { Env } from "./env.js";
import { inflateZlib } from "./inflate.js";
import type { DetectedType } from "./types.js";
import { checkTrailing as trailing } from "./trailing.js";
import { dangerousSchemeOf } from "./urls.js";

/** @internal PDF values. Dictionaries are Maps so hostile keys cannot reach Object.prototype. */
export type PdfValue = number | boolean | null | PdfName | PdfString | PdfRef | PdfValue[] | PdfDict | PdfKeyword;
export interface PdfName { t: "name"; v: string; raw: string }
export interface PdfString { t: "str"; v: Uint8Array }
export interface PdfRef { t: "ref"; n: number; g: number }
export interface PdfKeyword { t: "kw"; v: string }
export type PdfDict = Map<string, PdfValue>;

const WS = new Uint8Array(256);
for (const c of [0, 9, 10, 12, 13, 32]) WS[c] = 1;
const DELIM = new Uint8Array(256);
for (const c of "()<>[]{}/%") DELIM[c.charCodeAt(0)] = 1;
const ENDSTREAM = new TextEncoder().encode("endstream");

const isDict = (v: PdfValue | undefined): v is PdfDict => v instanceof Map;
const isName = (v: PdfValue | undefined): v is PdfName => typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Map) && v.t === "name";
const isRef = (v: PdfValue | undefined): v is PdfRef => typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Map) && v.t === "ref";
const isStr = (v: PdfValue | undefined): v is PdfString => typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Map) && v.t === "str";

/** Names pdfid counts (plus a few action types); hex escapes in these indicate evasion. */
const SENSITIVE = new Set(["JS", "JavaScript", "AA", "OpenAction", "AcroForm", "JBIG2Decode", "RichMedia", "Launch", "EmbeddedFile", "EmbeddedFiles", "XFA", "URI", "ObjStm", "Encrypt", "SubmitForm", "ImportData", "GoToR", "GoToE", "FileAttachment", "S", "Type", "Filter", "FlateDecode"]);

/** @internal Text of a PDF string (UTF-16BE with BOM, otherwise PDFDocEncoding approximated by Latin-1). */
export function pdfText(s: PdfString): string {
  const v = s.v;
  if (v[0] === 0xfe && v[1] === 0xff) return decode(v.subarray(2), "utf-16be");
  if (v[0] === 0xef && v[1] === 0xbb && v[2] === 0xbf) return decode(v.subarray(3), "utf-8");
  return latin1(v);
}

interface PdfObject {
  n: number;
  g: number;
  value: PdfValue;
  stream?: Uint8Array;
}

class Lexer {
  pos = 0;
  eofMarkers = 0;
  lastEof = -1;
  malformed = "";
  constructor(
    readonly b: Uint8Array,
    readonly step: (n: number) => void,
  ) {}

  skipWs(): void {
    const b = this.b;
    while (this.pos < b.length) {
      const c = b[this.pos] as number;
      if (WS[c]) this.pos++;
      else if (c === 0x25) {
        // comment; %%EOF markers are counted here (never inside skipped streams)
        if (b[this.pos + 1] === 0x25 && b[this.pos + 2] === 0x45 && b[this.pos + 3] === 0x4f && b[this.pos + 4] === 0x46) {
          this.eofMarkers++;
          this.lastEof = this.pos + 5;
        }
        while (this.pos < b.length && b[this.pos] !== 10 && b[this.pos] !== 13) this.pos++;
      } else break;
    }
  }

  /** Reads one value. Keywords (obj, endobj, stream, R, trailer, ...) come back as {t:"kw"}. */
  value(depth = 0): PdfValue | undefined {
    this.skipWs();
    const b = this.b;
    if (this.pos >= b.length) return undefined;
    this.step(1);
    const c = b[this.pos] as number;
    if (c === 0x2f) return this.name();
    if (c === 0x28) return this.literal();
    if (c === 0x3c && b[this.pos + 1] === 0x3c) {
      this.pos += 2;
      const d: PdfDict = new Map();
      for (;;) {
        this.skipWs();
        if (this.pos >= b.length) {
          this.malformed ||= "unterminated dictionary";
          return d;
        }
        if (b[this.pos] === 0x3e && b[this.pos + 1] === 0x3e) {
          this.pos += 2;
          return d;
        }
        const k = this.value(depth + 1);
        if (k === undefined) return d;
        if (!isName(k)) {
          if (typeof k === "object" && k !== null && !Array.isArray(k) && !(k instanceof Map) && k.t === "kw" && (k.v === "endobj" || k.v === "stream")) {
            this.malformed ||= "unterminated dictionary";
            this.pos -= k.v.length;
            return d;
          }
          continue; // junk key: skip
        }
        if (depth > 64) {
          this.malformed ||= "nesting too deep";
          this.skipValueShallow();
          continue;
        }
        const v = this.value(depth + 1);
        if (v === undefined) return d;
        d.set(k.v, v);
      }
    }
    if (c === 0x3c) return this.hex();
    if (c === 0x5b) {
      this.pos++;
      const arr: PdfValue[] = [];
      for (;;) {
        this.skipWs();
        if (this.pos >= b.length) return arr;
        if (b[this.pos] === 0x5d) {
          this.pos++;
          return arr;
        }
        if (depth > 64) {
          this.malformed ||= "nesting too deep";
          this.skipValueShallow();
          continue;
        }
        const v = this.value(depth + 1);
        if (v === undefined) return arr;
        if (typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Map) && v.t === "kw" && v.v === "R" && arr.length >= 2) {
          const g = arr.pop();
          const n = arr.pop();
          if (typeof n === "number" && typeof g === "number") arr.push({ t: "ref", n, g });
          continue;
        }
        if (typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Map) && v.t === "kw" && (v.v === "endobj" || v.v === "stream")) {
          this.malformed ||= "unterminated array";
          this.pos -= v.v.length;
          return arr;
        }
        arr.push(v);
      }
    }
    if (c === 0x3e || c === 0x5d || c === 0x29 || c === 0x7b || c === 0x7d) {
      this.pos++;
      return { t: "kw", v: String.fromCharCode(c) };
    }
    // number or keyword
    const start = this.pos;
    while (this.pos < b.length && !WS[b[this.pos] as number] && !DELIM[b[this.pos] as number] && this.pos - start < 256) this.pos++;
    if (this.pos === start) this.pos++;
    const tok = latin1(b, start, this.pos);
    if (/^[+-]?(?:\d{1,20}(?:\.\d{0,20})?|\.\d{1,20})$/.test(tok)) {
      const num = Number(tok);
      // indirect reference "n g R" (only at dictionary-value level; arrays handle it above)
      if (Number.isInteger(num) && num >= 0 && depth > 0) {
        const save = this.pos;
        this.skipWs();
        const g = this.peekInt();
        if (g !== undefined) {
          this.skipWs();
          if (b[this.pos] === 0x52 && (this.pos + 1 >= b.length || WS[b[this.pos + 1] as number] || DELIM[b[this.pos + 1] as number])) {
            this.pos++;
            return { t: "ref", n: num, g };
          }
        }
        this.pos = save;
      }
      return num;
    }
    if (tok === "true") return true;
    if (tok === "false") return false;
    if (tok === "null") return null;
    return { t: "kw", v: tok };
  }

  readonly names: PdfName[] = [];

  private peekInt(): number | undefined {
    const b = this.b;
    const start = this.pos;
    while (this.pos < b.length && (b[this.pos] as number) >= 0x30 && (b[this.pos] as number) <= 0x39 && this.pos - start < 10) this.pos++;
    if (this.pos === start || (this.pos < b.length && !WS[b[this.pos] as number])) {
      this.pos = start;
      return undefined;
    }
    return Number(latin1(b, start, this.pos));
  }

  private skipValueShallow(): void {
    // skip one token without recursion (used beyond the nesting limit)
    const b = this.b;
    while (this.pos < b.length && !WS[b[this.pos] as number] && b[this.pos] !== 0x3e && b[this.pos] !== 0x5d) this.pos++;
    if (this.pos < b.length && (b[this.pos] === 0x3e || b[this.pos] === 0x5d) && !WS[b[this.pos] as number]) this.pos++;
  }

  private name(): PdfName {
    const b = this.b;
    const start = ++this.pos;
    while (this.pos < b.length && !WS[b[this.pos] as number] && !DELIM[b[this.pos] as number] && this.pos - start < 1024) this.pos++;
    const raw = latin1(b, start, this.pos);
    const v = raw.includes("#") ? raw.replace(/#([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))) : raw;
    const n: PdfName = { t: "name", v, raw };
    if (raw !== v) this.names.push(n);
    return n;
  }

  private literal(): PdfString {
    const b = this.b;
    this.pos++;
    const out: number[] = [];
    let depth = 1;
    while (this.pos < b.length) {
      const c = b[this.pos++] as number;
      if (c === 0x5c) {
        const e = b[this.pos++];
        if (e === undefined) break;
        if (e >= 0x30 && e <= 0x37) {
          let v = e - 0x30;
          for (let k = 0; k < 2 && (b[this.pos] ?? 0) >= 0x30 && (b[this.pos] ?? 0) <= 0x37; k++) v = v * 8 + ((b[this.pos++] as number) - 0x30);
          out.push(v & 0xff);
        } else if (e === 0x6e) out.push(10);
        else if (e === 0x72) out.push(13);
        else if (e === 0x74) out.push(9);
        else if (e === 0x62) out.push(8);
        else if (e === 0x66) out.push(12);
        else if (e === 13) {
          if (b[this.pos] === 10) this.pos++;
        } else if (e !== 10) out.push(e);
      } else if (c === 0x28) {
        depth++;
        out.push(c);
      } else if (c === 0x29) {
        if (--depth === 0) break;
        out.push(c);
      } else if (out.length < 1 << 20) out.push(c);
    }
    this.step(out.length >>> 4);
    return { t: "str", v: Uint8Array.from(out) };
  }

  private hex(): PdfString {
    const b = this.b;
    this.pos++;
    const out: number[] = [];
    let hi = -1;
    while (this.pos < b.length) {
      const c = b[this.pos++] as number;
      if (c === 0x3e) break;
      const d = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 55 : c >= 0x61 && c <= 0x66 ? c - 87 : -1;
      if (d < 0) continue;
      if (hi < 0) hi = d;
      else {
        out.push((hi << 4) | d);
        hi = -1;
      }
    }
    if (hi >= 0) out.push(hi << 4);
    this.step(out.length >>> 4);
    return { t: "str", v: Uint8Array.from(out) };
  }

  /** After the `stream` keyword: returns the raw stream data and moves past `endstream`. */
  streamData(dict: PdfDict): Uint8Array {
    const b = this.b;
    if (b[this.pos] === 13) this.pos++;
    if (b[this.pos] === 10) this.pos++;
    const start = this.pos;
    const len = dict.get("Length");
    if (typeof len === "number" && len >= 0 && start + len <= b.length) {
      let e = start + len;
      while (e < b.length && WS[b[e] as number] && e - start - len < 4) e++;
      if (indexOf(b, ENDSTREAM, e, Math.min(b.length, e + 9)) === e) {
        this.pos = e + 9;
        return b.subarray(start, start + len);
      }
    }
    const end = indexOf(b, ENDSTREAM, start);
    if (end < 0) {
      this.malformed ||= "stream without endstream";
      this.pos = b.length;
      return b.subarray(start);
    }
    this.pos = end + 9;
    let e = end;
    if (b[e - 1] === 10) e--;
    if (b[e - 1] === 13) e--;
    this.step((end - start) >>> 8);
    return b.subarray(start, Math.max(start, e));
  }
}

/** @internal Parses a sequence of top-level objects (also used for object stream contents). */
function parseObjects(lx: Lexer, objects: PdfObject[], trailers: PdfDict[]): void {
  const stack: PdfValue[] = [];
  for (;;) {
    const v = lx.value(0);
    if (v === undefined) break;
    if (typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Map) && v.t === "kw") {
      if (v.v === "obj" && stack.length >= 2) {
        const g = stack[stack.length - 1];
        const n = stack[stack.length - 2];
        stack.length = 0;
        if (typeof n !== "number" || typeof g !== "number") continue;
        const value = lx.value(1) ?? null;
        const obj: PdfObject = { n, g, value };
        const save = lx.pos;
        const next = lx.value(1);
        if (isDict(value) && typeof next === "object" && next !== null && !Array.isArray(next) && !(next instanceof Map) && next.t === "kw" && next.v === "stream") {
          obj.stream = lx.streamData(value);
        } else lx.pos = save;
        objects.push(obj);
        continue;
      }
      if (v.v === "trailer") {
        const t = lx.value(1);
        if (isDict(t)) trailers.push(t);
      }
      stack.length = 0;
      continue;
    }
    stack.push(v);
    if (stack.length > 2) stack.shift();
  }
}

function ascii85(src: Uint8Array): Uint8Array {
  const out: number[] = [];
  let group: number[] = [];
  for (let i = 0; i < src.length; i++) {
    const c = src[i] as number;
    if (c === 0x7e) break;
    if (WS[c]) continue;
    if (c === 0x7a && group.length === 0) {
      out.push(0, 0, 0, 0);
      continue;
    }
    if (c < 0x21 || c > 0x75) continue;
    group.push(c - 33);
    if (group.length === 5) {
      let v = 0;
      for (const d of group) v = v * 85 + d;
      out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
      group = [];
    }
  }
  if (group.length > 1) {
    const n = group.length;
    while (group.length < 5) group.push(84);
    let v = 0;
    for (const d of group) v = v * 85 + d;
    for (let k = 0; k < n - 1; k++) out.push((v >>> (24 - 8 * k)) & 255);
  }
  return Uint8Array.from(out);
}

function asciiHex(src: Uint8Array): Uint8Array {
  const out: number[] = [];
  let hi = -1;
  for (const c of src) {
    if (c === 0x3e) break;
    const d = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 55 : c >= 0x61 && c <= 0x66 ? c - 87 : -1;
    if (d < 0) continue;
    if (hi < 0) hi = d;
    else {
      out.push((hi << 4) | d);
      hi = -1;
    }
  }
  if (hi >= 0) out.push(hi << 4);
  return Uint8Array.from(out);
}

/** @internal Decodes a stream through its filters; undefined when a filter is unsupported or the data is corrupt. */
function decodeStream(env: Env, obj: PdfObject, problems: string[]): Uint8Array | undefined {
  const dict = obj.value as PdfDict;
  let data = obj.stream ?? new Uint8Array(0);
  const f = dict.get("Filter");
  const filters = (Array.isArray(f) ? f : f === undefined ? [] : [f]).filter(isName).map((n) => n.v);
  for (const name of filters) {
    env.ctx.step(data.length >>> 6);
    if (name === "FlateDecode" || name === "Fl") {
      const ratioCap = Math.max(1 << 20, data.length * env.ctx.limits.maxCompressionRatio);
      const allowance = env.ctx.allowance();
      const cap = Math.min(allowance, ratioCap);
      const r = inflateZlib(data, cap, (n) => env.ctx.step(n));
      env.ctx.inflated(r.data.length);
      if (r.status === "limit") {
        if (cap === ratioCap) env.add("ARCHIVE_BOMB", { element: `obj ${obj.n} ${obj.g}`, evidence: `FlateDecode stream decompresses beyond ${env.ctx.limits.maxCompressionRatio}:1` });
        else {
          env.ctx.hit(allowance < env.ctx.limits.maxItemBytes ? "maxDecompressedBytes" : "maxItemBytes");
          env.add("SCAN_LIMIT", { element: `obj ${obj.n} ${obj.g}`, detail: "A stream was only partially decompressed." });
        }
        return undefined;
      }
      if (r.status === "corrupt" && r.data.length === 0) {
        problems.push(`obj ${obj.n} ${obj.g}: corrupt FlateDecode data`);
        return undefined;
      }
      data = r.data;
    } else if (name === "ASCIIHexDecode" || name === "AHx") data = asciiHex(data);
    else if (name === "ASCII85Decode" || name === "A85") data = ascii85(data);
    else return undefined; // LZW, RunLength, image filters: not needed for the checks
  }
  return data;
}

/** @internal PDF handler. */
export function scanPdf(env: Env, detected: DetectedType): DetectedType {
  const b = env.item.bytes;
  const step = (n: number) => env.ctx.step(n);
  const lx = new Lexer(b, step);
  const objects: PdfObject[] = [];
  const trailers: PdfDict[] = [];
  parseObjects(lx, objects, trailers);
  const problems: string[] = [];
  if (lx.malformed) problems.push(lx.malformed);

  const byNum = new Map<number, PdfObject>();
  for (const o of objects) byNum.set(o.n, o); // later revisions win
  const encrypted = trailers.some((t) => t.has("Encrypt")) || objects.some((o) => isDict(o.value) && o.value.has("Encrypt") && isName(o.value.get("Type")) && (o.value.get("Type") as PdfName).v === "XRef");
  if (encrypted) env.add("PDF_ENCRYPTED");

  // object streams (PDF 1.5) are expanded unless the file is encrypted
  if (!encrypted) {
    const streams = objects.filter((o) => o.stream && isDict(o.value) && isName(o.value.get("Type")) && (o.value.get("Type") as PdfName).v === "ObjStm");
    for (const os of streams) {
      const data = decodeStream(env, os, problems);
      if (!data) continue;
      const d = os.value as PdfDict;
      const first = d.get("First");
      const count = d.get("N");
      if (typeof first !== "number" || typeof count !== "number") continue;
      const head = new Lexer(data.subarray(0, Math.min(first, data.length)), step);
      const offsets: [number, number][] = [];
      for (let k = 0; k < count && k < 100_000; k++) {
        const n = head.value(0);
        const off = head.value(0);
        if (typeof n !== "number" || typeof off !== "number") break;
        offsets.push([n, off]);
      }
      for (const [n, off] of offsets) {
        const sub = new Lexer(data, step);
        sub.pos = first + off;
        const value = sub.value(1);
        if (value === undefined) continue;
        const o: PdfObject = { n, g: 0, value };
        objects.push(o);
        if (!byNum.has(n)) byNum.set(n, o);
        lx.names.push(...sub.names);
      }
    }
  }
  if (objects.length === 0) problems.push("no objects");
  if (lx.eofMarkers === 0) problems.push("no %%EOF marker");
  if (lx.eofMarkers > 1) env.add("PDF_INCREMENTAL_UPDATE", { evidence: `${lx.eofMarkers} %%EOF markers` });

  // hex-escaped sensitive names
  for (const n of lx.names) {
    if (SENSITIVE.has(n.v)) env.add("PDF_OBFUSCATED_NAME", { element: `/${n.raw}`, evidence: excerpt(`/${n.raw} = /${n.v}`) });
  }

  const resolve = (v: PdfValue | undefined, hops = 0): PdfValue | undefined => (isRef(v) && hops < 16 ? resolve(byNum.get(v.n)?.value, hops + 1) : v);
  const textOf = (v: PdfValue | undefined): string | undefined => {
    if (isStr(v)) return pdfText(v);
    if (isRef(v)) {
      const o = byNum.get(v.n);
      if (o?.stream && !encrypted) {
        const d = decodeStream(env, o, problems);
        return d ? decode(d.subarray(0, 4096), "windows-1252") : undefined;
      }
      return isStr(o?.value) ? pdfText(o.value as PdfString) : undefined;
    }
    return undefined;
  };

  const embedded = new Map<number, string>(); // stream object number → file name
  const visit = (v: PdfValue, el: string, depth: number) => {
    if (depth > 64) return;
    env.ctx.step(1);
    if (Array.isArray(v)) {
      for (const x of v) visit(x, el, depth + 1);
      return;
    }
    if (!isDict(v)) return;
    const type = v.get("Type");
    const s = v.get("S");
    const sName = isName(s) ? s.v : "";
    if (v.has("JS") || sName === "JavaScript" || v.has("JavaScript")) {
      const js = textOf(v.get("JS"));
      env.add("PDF_JAVASCRIPT", { element: el, evidence: js ? excerpt(js) : undefined });
    }
    if (v.has("OpenAction")) {
      const oa = resolve(v.get("OpenAction"));
      const kind = isDict(oa) && isName(oa.get("S")) ? `${(oa.get("S") as PdfName).v} action` : Array.isArray(oa) ? "destination" : "action";
      // a plain destination (initial view) is common and harmless; only actions are reported
      if (!Array.isArray(oa)) env.add("PDF_OPEN_ACTION", { element: el, evidence: kind });
    }
    if (v.has("AA")) env.add("PDF_ADDITIONAL_ACTIONS", { element: el });
    if (sName === "Launch" || v.has("Launch")) {
      const target = textOf(v.get("F")) ?? (isDict(resolve(v.get("F"))) ? textOf((resolve(v.get("F")) as PdfDict).get("F")) : undefined);
      const win = resolve(v.get("Win"));
      const winCmd = isDict(win) ? [textOf(win.get("F")), textOf(win.get("P"))].filter(Boolean).join(" ") : "";
      env.add("PDF_LAUNCH", { element: el, evidence: excerpt(winCmd || target || "Launch") });
    }
    if (sName === "URI" || v.has("URI")) {
      const uri = textOf(v.get("URI"));
      if (uri && dangerousSchemeOf(uri)) env.add("PDF_SUSPICIOUS_URI", { element: el, evidence: excerpt(uri) });
    }
    if (sName === "SubmitForm") env.add("PDF_SUBMIT_FORM", { element: el, evidence: excerpt(textOf(isDict(resolve(v.get("F"))) ? (resolve(v.get("F")) as PdfDict).get("F") : v.get("F")) ?? "") });
    if (sName === "ImportData") env.add("PDF_IMPORT_DATA", { element: el });
    if (sName === "GoToR" || sName === "GoToE") {
      const f = resolve(v.get("F"));
      const target = isDict(f) ? textOf(f.get("UF") ?? f.get("F")) : textOf(v.get("F"));
      env.add("PDF_REMOTE_GOTO", { element: el, evidence: excerpt(`${sName} ${target ?? ""}`) });
      if (target && dangerousSchemeOf(target)) env.add("PDF_SUSPICIOUS_URI", { element: el, evidence: excerpt(target) });
    }
    if (v.has("RichMedia") || (isName(type) && type.v.startsWith("RichMedia")) || (isName(v.get("Subtype")) && (v.get("Subtype") as PdfName).v === "RichMedia")) env.add("PDF_RICH_MEDIA", { element: el });
    if (v.has("XFA")) {
      env.add("PDF_XFA", { element: el });
      const xfa = resolve(v.get("XFA"));
      const refs = Array.isArray(xfa) ? xfa.filter(isRef) : isRef(v.get("XFA")) ? [v.get("XFA") as PdfRef] : [];
      for (const r of refs.slice(0, 50)) {
        const o = byNum.get(r.n);
        if (!o?.stream || encrypted) continue;
        const d = decodeStream(env, o, problems);
        if (!d) continue;
        const t = latin1(d, 0, Math.min(d.length, 4 << 20));
        const m = /<script\b[^>]{0,200}>([\s\S]{0,300})/i.exec(t);
        if (m) env.add("PDF_JAVASCRIPT", { element: `obj ${o.n} ${o.g} (XFA)`, evidence: excerpt(m[1] ?? m[0]) });
      }
    }
    if (isName(v.get("Subtype")) && (v.get("Subtype") as PdfName).v === "FileAttachment") env.add("PDF_EMBEDDED_FILE", { element: el, evidence: "FileAttachment annotation" });
    const ef = resolve(v.get("EF"));
    if (isDict(ef)) {
      const name = textOf(v.get("UF")) ?? textOf(v.get("F")) ?? "";
      for (const k of ["F", "UF", "DOS", "Mac", "Unix"]) {
        const r = ef.get(k);
        if (isRef(r) && !embedded.has(r.n)) embedded.set(r.n, name);
      }
    }
    const filter = v.get("Filter");
    if ((isName(filter) && filter.v === "JBIG2Decode") || (Array.isArray(filter) && filter.some((x) => isName(x) && x.v === "JBIG2Decode"))) env.add("PDF_JBIG2", { element: el });
    for (const x of v.values()) if (Array.isArray(x) || isDict(x)) visit(x, el, depth + 1);
  };
  for (const o of objects) visit(o.value, `obj ${o.n} ${o.g}`, 0);
  for (const t of trailers) visit(t, "trailer", 0);

  // embedded files
  for (const o of objects) {
    if (!o.stream || !isDict(o.value)) continue;
    const t = o.value.get("Type");
    const isEf = (isName(t) && t.v === "EmbeddedFile") || embedded.has(o.n);
    if (!isEf) continue;
    const name = embedded.get(o.n) ?? "";
    env.add("PDF_EMBEDDED_FILE", { element: `obj ${o.n} ${o.g}`, evidence: name ? excerpt(name) : undefined });
    if (encrypted) continue;
    const d = decodeStream(env, o, problems);
    if (d && d.length > 0) env.child(d, `obj ${o.n} ${o.g}${name ? ` (${name})` : ""}`, name || undefined);
  }

  // data after the last %%EOF
  if (lx.lastEof > 0) {
    let e = lx.lastEof;
    while (e < b.length && WS[b[e] as number]) e++;
    if (b.length - e > 0) trailing(env, b, e);
  }
  if (problems.length) env.add("PDF_MALFORMED", { evidence: excerpt(problems.slice(0, 3).join("; ")) });
  return detected;
}

