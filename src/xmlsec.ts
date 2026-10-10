/** DOCTYPE analysis shared by XML-based formats: entity declarations, XXE, expansion bombs, external DTDs. */
import { excerpt } from "./bytes.js";
import type { Env } from "./env.js";

interface EntityDecl {
  name: string;
  parameter: boolean;
  external: boolean;
  value: string;
  raw: string;
}

/** @internal Extracts `<!ENTITY ...>` declarations from a DOCTYPE's internal subset. */
export function entityDeclarations(doctype: string): EntityDecl[] {
  const out: EntityDecl[] = [];
  let i = 0;
  for (let guard = 0; guard < 10_000; guard++) {
    const k = doctype.indexOf("<!ENTITY", i);
    if (k < 0) break;
    let j = k + 8;
    const skip = () => {
      while (j < doctype.length && /\s/.test(doctype[j] as string)) j++;
    };
    skip();
    let parameter = false;
    if (doctype[j] === "%") {
      parameter = true;
      j++;
      skip();
    }
    const ns = j;
    while (j < doctype.length && !/[\s>"']/.test(doctype[j] as string)) j++;
    const name = doctype.slice(ns, j);
    skip();
    let external = false;
    let value = "";
    const kw = doctype.slice(j, j + 6).toUpperCase();
    if (kw === "SYSTEM" || kw === "PUBLIC") {
      external = true;
      j += 6;
    }
    // read up to two quoted literals (PUBLIC id + system literal), then up to '>'
    for (let q = 0; q < 2; q++) {
      skip();
      const quote = doctype[j];
      if (quote !== '"' && quote !== "'") break;
      const e = doctype.indexOf(quote, j + 1);
      if (e < 0) {
        j = doctype.length;
        break;
      }
      value = doctype.slice(j + 1, e);
      j = e + 1;
      if (!external) break;
    }
    const gt = doctype.indexOf(">", j);
    const end = gt < 0 ? doctype.length : gt + 1;
    out.push({ name, parameter, external, value, raw: doctype.slice(k, end) });
    i = end;
  }
  return out;
}

/** Expanded length of each entity, following references (cycles count as infinite). */
function expansion(decls: EntityDecl[]): number {
  const general = new Map<string, EntityDecl>();
  const param = new Map<string, EntityDecl>();
  for (const d of decls) {
    const m = d.parameter ? param : general;
    if (!m.has(d.name)) m.set(d.name, d);
  }
  const memo = new Map<EntityDecl, number>();
  const active = new Set<EntityDecl>();
  const size = (d: EntityDecl): number => {
    const cached = memo.get(d);
    if (cached !== undefined) return cached;
    if (active.has(d)) return Infinity;
    active.add(d);
    let total = d.value.length;
    if (!d.external) {
      const re = /([&%])([A-Za-z_:][\w.:-]{0,100});/g;
      for (let m = re.exec(d.value); m; m = re.exec(d.value)) {
        const target = (m[1] === "&" ? general : param).get(m[2] as string);
        if (target) total += size(target);
        if (total > 1e12) break;
      }
    }
    active.delete(d);
    memo.set(d, total);
    return total;
  };
  let max = 0;
  for (const d of decls) max = Math.max(max, size(d));
  return max;
}

const EXPANSION_LIMIT = 100_000;

/** @internal Reports DOCTYPE-related findings. */
export function checkDoctype(env: Env, raw: string, offset: number): void {
  const lb = raw.indexOf("[");
  const subset = lb >= 0 ? raw.slice(lb) : "";
  const head = lb >= 0 ? raw.slice(0, lb) : raw;
  // external DTD in the DOCTYPE itself
  const ext = /\b(SYSTEM|PUBLIC)\s{0,100}(?:"([^"]{0,2000})"|'([^']{0,2000})')(?:\s{0,100}(?:"([^"]{0,2000})"|'([^']{0,2000})'))?/i.exec(head);
  const sysLit = !ext ? "" : ext[1]?.toUpperCase() === "SYSTEM" ? (ext[2] ?? ext[3] ?? "") : (ext[4] ?? ext[5] ?? "");
  if (sysLit && !isStandardDtd(sysLit)) env.add("XML_EXTERNAL_DTD", { offset, element: "<!DOCTYPE>", evidence: excerpt(sysLit) });
  const decls = entityDeclarations(subset);
  if (decls.length === 0) return;
  let reported = false;
  for (const d of decls) {
    if (d.external) {
      env.add("XML_EXTERNAL_ENTITY", { offset, element: `<!ENTITY ${d.parameter ? "% " : ""}${d.name}>`, evidence: excerpt(d.raw) });
      reported = true;
    }
  }
  const size = expansion(decls);
  if (size > EXPANSION_LIMIT) {
    env.add("XML_ENTITY_EXPANSION", {
      offset,
      element: "<!DOCTYPE>",
      evidence: excerpt(decls.slice(-1)[0]?.raw ?? ""),
      detail: size === Infinity ? "Entities reference each other recursively." : `Expanded size would be about ${formatSize(size)} characters.`,
    });
    reported = true;
  }
  if (!reported) env.add("XML_ENTITY_DECLARATION", { offset, element: "<!DOCTYPE>", evidence: excerpt(decls[0]?.raw ?? "") });
}

function formatSize(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} billion`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} million`;
  return String(Math.round(n));
}

/** W3C-hosted DTDs (SVG 1.0/1.1, XHTML, HTML 4) are referenced by many legitimate files and never fetched by browsers. */
export function isStandardDtd(uri: string): boolean {
  return /^https?:\/\/www\.w3\.org\//i.test(uri.trim());
}

/** @internal Checks an `xml-stylesheet` processing instruction for an external stylesheet. */
export function checkStylesheetPi(env: Env, target: string, data: string, offset: number): void {
  if (target.toLowerCase() !== "xml-stylesheet") return;
  const m = /href\s*=\s*(?:"([^"]{0,2000})"|'([^']{0,2000})')/i.exec(data);
  const href = m ? (m[1] ?? m[2] ?? "") : "";
  if (href && !href.startsWith("#")) env.add("XML_EXTERNAL_DTD", { offset, element: "<?xml-stylesheet?>", evidence: excerpt(href) });
}
