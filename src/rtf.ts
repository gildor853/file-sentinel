/** RTF: embedded OLE objects, Equation Editor, remote templates, DDE fields and obfuscation. */
import { excerpt, latin1, startsWith, u32le } from "./bytes.js";
import type { Env } from "./env.js";
import { parseOle10Native } from "./office-cfb.js";
import { DDE_FIELD } from "./ooxml.js";
import type { DetectedType } from "./types.js";
import { isExternalUrl } from "./urls.js";

const CFB_SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const MAX_NESTING = 100;
const MAX_OBJDATA = 64 << 20;

interface Group {
  dest: string | null;
  /** Inside an ignorable destination (`{\*\...}`) that we do not track. */
  skip: boolean;
}

interface Obj {
  offset: number;
  cls: string;
  update: boolean;
  data: ByteBuf;
  garbage: number;
  bin: Uint8Array[];
}

/** @internal Parses an OLE1 (OLESaveToStream) object: class name and native data. */
export function parseOle1(d: Uint8Array): { cls: string; native: Uint8Array } | undefined {
  if (d.length < 12) return undefined;
  let p = 8; // OLEVersion, FormatID
  const lps = () => {
    const n = u32le(d, p);
    if (n > 1024 || p + 4 + n > d.length) throw new RangeError("bad string");
    const s = latin1(d, p + 4, p + 4 + n).replace(/\0+$/, "");
    p += 4 + n;
    return s;
  };
  try {
    const cls = lps();
    lps(); // topic
    lps(); // item
    const size = u32le(d, p);
    return { cls, native: d.subarray(p + 4, Math.min(d.length, p + 4 + size)) };
  } catch {
    return undefined;
  }
}

/** @internal RTF handler. */
export function scanRtf(env: Env, detected: DetectedType): DetectedType {
  const b = env.item.bytes;
  if (!startsWith(b, Array.from("{\\rtf1", (c) => c.charCodeAt(0)))) env.add("RTF_OBFUSCATION", { offset: 0, evidence: excerpt(latin1(b, 0, 16)) });
  const stack: Group[] = [];
  let cur: Group = { dest: null, skip: false };
  let maxDepth = 0;
  const objects: Obj[] = [];
  let obj: Obj | undefined;
  let objDepth = -1;
  let text = { objclass: "", template: "", fldinst: "" };
  let destStart = 0;
  let star = false;
  const ctx = env.ctx;
  const n = b.length;
  let i = 0;
  const appendText = (s: string) => {
    if (cur.skip || cur.dest === null) return;
    if (cur.dest === "objdata" && obj) {
      for (let k = 0; k < s.length; k++) {
        const c = s.charCodeAt(k);
        const h = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 55 : c >= 0x61 && c <= 0x66 ? c - 87 : -1;
        if (h >= 0) obj.data.nibble(h);
        else if (c > 0x20) obj.garbage++;
      }
    } else if (cur.dest === "objclass" || cur.dest === "template" || cur.dest === "fldinst") {
      if (text[cur.dest].length < 10_000) text[cur.dest] += s;
    }
  };
  const endDest = (g: Group) => {
    if (g.dest === "objclass" && obj && !obj.cls) obj.cls = text.objclass.trim();
    if (g.dest === "template") {
      const t = text.template.trim();
      if (t && (isExternalUrl(t) || t.startsWith("\\\\"))) env.add("RTF_REMOTE_TEMPLATE", { offset: destStart, evidence: excerpt(t) });
    }
    if (g.dest === "fldinst" && DDE_FIELD.test(text.fldinst)) env.add("OFFICE_DDE", { offset: destStart, evidence: excerpt(text.fldinst.trim()) });
  };
  while (i < n) {
    if ((i & 4095) === 0) ctx.step(64);
    const c = b[i] as number;
    if (c === 0x7b) {
      stack.push(cur);
      cur = { dest: cur.dest, skip: cur.skip };
      if (stack.length > maxDepth) maxDepth = stack.length;
      if (stack.length > 10_000) {
        env.add("RTF_OBFUSCATION", { offset: i, evidence: "group nesting deeper than 10000" });
        break;
      }
      star = false;
      i++;
      continue;
    }
    if (c === 0x7d) {
      const ended = cur;
      cur = stack.pop() ?? { dest: null, skip: false };
      if (ended.dest !== cur.dest) endDest(ended);
      if (obj && stack.length < objDepth) {
        objects.push(obj);
        obj = undefined;
        objDepth = -1;
      }
      i++;
      continue;
    }
    if (c === 0x5c) {
      const d = b[i + 1] ?? 0;
      if ((d >= 0x61 && d <= 0x7a) || (d >= 0x41 && d <= 0x5a)) {
        let j = i + 1;
        while (j < n && j - i <= 32 && (((b[j] as number) | 0x20) >= 0x61 && ((b[j] as number) | 0x20) <= 0x7a)) j++;
        const word = latin1(b, i + 1, j);
        let k = j;
        if (b[k] === 0x2d) k++;
        while (k < n && k - j <= 10 && (b[k] as number) >= 0x30 && (b[k] as number) <= 0x39) k++;
        const param = k > j ? Number(latin1(b, j, k)) : NaN;
        if (b[k] === 0x20) k++;
        i = k;
        switch (word) {
          case "object":
            if (obj) objects.push(obj);
            obj = { offset: i, cls: "", update: false, data: new ByteBuf(), garbage: 0, bin: [] };
            objDepth = stack.length;
            text.objclass = "";
            break;
          case "objupdate":
            if (obj) obj.update = true;
            break;
          case "objdata":
          case "objclass":
          case "template":
          case "fldinst":
            cur.dest = word;
            cur.skip = false;
            destStart = i;
            if (word !== "objdata") text = { ...text, [word]: "" };
            if (word === "objdata" && !obj) {
              obj = { offset: i, cls: "", update: false, data: new ByteBuf(), garbage: 0, bin: [] };
              objDepth = stack.length;
            }
            break;
          case "bin":
            if (param > 0) {
              const len = Math.min(param, n - i);
              if (cur.dest === "objdata" && obj) obj.bin.push(b.subarray(i, i + len));
              i += len;
            }
            break;
          default:
            // unknown ignorable destination (also junk groups inside \objdata): Word skips its text
            if (star) cur.skip = true;
        }
        star = false;
        continue;
      }
      if (d === 0x2a) {
        star = true;
        i += 2;
        continue;
      }
      if (d === 0x27) {
        const hx = latin1(b, i + 2, i + 4);
        if (/^[0-9a-fA-F]{2}$/.test(hx)) appendText(String.fromCharCode(parseInt(hx, 16)));
        i += 4;
        continue;
      }
      if (d === 0x5c || d === 0x7b || d === 0x7d) appendText(String.fromCharCode(d));
      i += 2;
      continue;
    }
    // plain text run
    let j = i;
    while (j < n && b[j] !== 0x7b && b[j] !== 0x7d && b[j] !== 0x5c && j - i < 65536) j++;
    if (!cur.skip && cur.dest !== null) appendText(latin1(b, i, j));
    i = j;
  }
  if (obj) objects.push(obj);
  if (maxDepth > MAX_NESTING) env.add("RTF_OBFUSCATION", { evidence: `group nesting depth ${maxDepth}` });

  for (const o of objects) {
    const bytes = o.bin.length ? concatBytes(o.bin) : o.data.bytes();
    ctx.step(bytes.length >>> 4);
    const ole = parseOle1(bytes);
    const cls = o.cls || ole?.cls || "";
    env.add("RTF_OLE_OBJECT", { offset: o.offset, element: `\\object@${o.offset}`, evidence: excerpt(cls ? `class ${cls}, ${bytes.length} bytes` : `${bytes.length} bytes`) });
    if (o.update) env.add("RTF_OBJUPDATE", { offset: o.offset, element: `\\object@${o.offset}`, evidence: excerpt(cls) });
    if (o.garbage >= 8) env.add("RTF_OBFUSCATION", { offset: o.offset, element: `\\objdata@${o.offset}`, evidence: `${o.garbage} non-hex characters inside \\objdata` });
    if (/^equation\.3/i.test(cls) || /^equation/i.test(ole?.cls ?? "") || (ole && hasEquationClsid(ole.native))) {
      env.add("OLE_EQUATION_EDITOR", { offset: o.offset, element: `\\object@${o.offset}`, evidence: excerpt(cls || "Equation Native") });
    }
    if (!ole) continue;
    const seg = `\\object@${o.offset}`;
    if (/^package$/i.test(ole.cls)) {
      const pkg = parseOle10Native(ole.native, 2);
      if (pkg) {
        env.add("OLE_PACKAGE", { offset: o.offset, element: seg, evidence: excerpt(`${pkg.label} (${pkg.path})`) });
        if (pkg.data.length > 0) env.child(pkg.data, seg, pkg.label || pkg.path);
      }
    } else if (ole.native.length > 0) env.child(ole.native, seg);
  }
  return detected;
}

function hasEquationClsid(native: Uint8Array): boolean {
  if (!startsWith(native, CFB_SIG)) return false;
  // root entry CLSID check without a full parse: search the directory for the Equation.3 CLSID bytes
  const want = [0x02, 0xce, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
  for (let i = 512; i + 16 <= native.length && i < 1 << 22; i++) if (native[i] === 0x02 && startsWith(native, want, i)) return true;
  return false;
}

/** Collects hex nibbles into bytes (bounded). */
class ByteBuf {
  #buf = new Uint8Array(1024);
  #len = 0;
  #half = -1;
  nibble(h: number): void {
    if (this.#half < 0) {
      this.#half = h;
      return;
    }
    if (this.#len >= MAX_OBJDATA) return;
    if (this.#len === this.#buf.length) {
      const next = new Uint8Array(this.#buf.length * 2);
      next.set(this.#buf);
      this.#buf = next;
    }
    this.#buf[this.#len++] = (this.#half << 4) | h;
    this.#half = -1;
  }
  bytes(): Uint8Array {
    return this.#buf.subarray(0, this.#len);
  }
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
