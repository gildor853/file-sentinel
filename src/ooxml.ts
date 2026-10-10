/** OOXML (Office Open XML) and OpenDocument semantic checks on top of the ZIP container. */
import { decode, excerpt } from "./bytes.js";
import type { Env } from "./env.js";
import { detectedType } from "./formats.js";
import { analyzeSource } from "./office-cfb.js";
import type { DetectedType } from "./types.js";
import { dangerousSchemeOf } from "./urls.js";
import { decodeEntities, tokenize } from "./xml.js";
import { readEntry, type Zip, type ZipEntry } from "./zip.js";

const MAIN_TYPES: Readonly<Record<string, string>> = {
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": "docx",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": "dotx",
  "application/vnd.ms-word.document.macroenabled.main+xml": "docm",
  "application/vnd.ms-word.template.macroenabledtemplate.main+xml": "dotm",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": "xlsx",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": "xltx",
  "application/vnd.ms-excel.sheet.macroenabled.main+xml": "xlsm",
  "application/vnd.ms-excel.template.macroenabled.main+xml": "xltm",
  "application/vnd.ms-excel.addin.macroenabled.main+xml": "xlam",
  "application/vnd.ms-excel.sheet.binary.macroenabled.main": "xlsb",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": "pptx",
  "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": "ppsx",
  "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": "potx",
  "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml": "pptm",
  "application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml": "ppsm",
  "application/vnd.ms-powerpoint.template.macroenabled.main+xml": "potm",
};
const MACRO_FREE = new Set(["docx", "dotx", "xlsx", "xltx", "pptx", "ppsx", "potx"]);

/** XML parts read for analysis are small; larger ones are skipped (they are still scanned as items). */
const MAX_PART = 32 << 20;

/** @internal Reads entries for analysis, caching them for the recursive scan that follows. */
export class PartReader {
  readonly #cache = new Map<string, Uint8Array | undefined>();
  readonly #byName = new Map<string, ZipEntry>();
  constructor(
    readonly env: Env,
    readonly zip: Zip,
  ) {
    for (const e of zip.entries) if (!this.#byName.has(e.name.replace(/^\//, ""))) this.#byName.set(e.name.replace(/^\//, ""), e);
  }
  entry(name: string): ZipEntry | undefined {
    return this.#byName.get(name.replace(/^\//, ""));
  }
  bytes(e: ZipEntry): Uint8Array | undefined {
    if (this.#cache.has(e.name)) return this.#cache.get(e.name);
    const d = readEntry(this.env, this.zip, e);
    this.#cache.set(e.name, d);
    return d;
  }
  text(name: string): string | undefined {
    const e = this.entry(name);
    if (!e || e.usize > MAX_PART) return undefined;
    const d = this.bytes(e);
    return d ? decode(d, "utf-8") : undefined;
  }
  /** Bytes for the recursive scan; drops the cached copy. */
  take(e: ZipEntry): Uint8Array | undefined {
    const d = this.bytes(e);
    this.#cache.delete(e.name);
    this.#cache.set(e.name, undefined);
    return d;
  }
}

const attr = (attrs: { name: string; value: string }[], local: string) => attrs.find((a) => a.name === local || a.name.endsWith(`:${local}`))?.value;

/** @internal Resolves a relationship target relative to the part that owns the .rels file. */
function resolveTarget(relsName: string, target: string): string {
  if (target.startsWith("/")) return target.slice(1);
  const base = relsName.replace(/_rels\/[^/]*\.rels$/, "").split("/").filter(Boolean);
  for (const seg of target.split("/")) {
    if (seg === "..") base.pop();
    else if (seg !== "." && seg !== "") base.push(seg);
  }
  return base.join("/");
}

interface Rel { id: string; type: string; target: string; external: boolean }

function parseRels(env: Env, xml: string): Rel[] {
  const rels: Rel[] = [];
  tokenize(xml, {
    start(name, attrs) {
      if (name.endsWith("Relationship")) {
        rels.push({ id: attr(attrs, "Id") ?? "", type: attr(attrs, "Type") ?? "", target: attr(attrs, "Target") ?? "", external: (attr(attrs, "TargetMode") ?? "").toLowerCase() === "external" });
      }
    },
  }, { step: (n) => env.ctx.step(n) });
  return rels;
}

/** @internal Matches a Word field instruction that starts a DDE / DDEAUTO field. */
export const DDE_FIELD = /^\s{0,100}DDE(?:AUTO)?\b/i;

function checkWordFields(env: Env, part: string, xml: string): void {
  let depth = 0;
  let instr = "";
  let inInstr = false;
  const flush = () => {
    if (DDE_FIELD.test(instr)) env.addAt([part], "OFFICE_DDE", { evidence: excerpt(instr.trim()) });
    instr = "";
  };
  tokenize(xml, {
    start(name, attrs, self) {
      if (name === "w:fldChar") {
        const t = attr(attrs, "fldCharType");
        if (t === "begin") {
          if (depth === 0) instr = "";
          depth++;
        } else if (t === "separate" || t === "end") {
          if (depth === 1 && instr) flush();
          if (t === "end") depth = Math.max(0, depth - 1);
        }
      } else if (name === "w:instrText" && !self) inInstr = true;
      else if (name === "w:fldSimple") {
        const ins = attr(attrs, "instr") ?? "";
        if (DDE_FIELD.test(ins)) env.addAt([part], "OFFICE_DDE", { evidence: excerpt(ins.trim()) });
      }
    },
    end(name) {
      if (name === "w:instrText") inInstr = false;
    },
    text(t) {
      if (inInstr && depth === 1 && instr.length < 10_000) instr += t;
    },
  }, { step: (n) => env.ctx.step(n) });
}

/** Excel DDE formula: =cmd|'/c calc'!A0 (application|topic!item). */
const DDE_FORMULA = /(?:^|[=+\-*,(\s@])(?:'[^']{1,200}'|[A-Za-z][\w.]{0,60})\|\s{0,10}'[^']{0,2000}'\s{0,10}!/;

function checkSheetFormulas(env: Env, part: string, xml: string): void {
  let inF = false;
  let f = "";
  tokenize(xml, {
    start(name, _a, self) {
      if ((name === "f" || name.endsWith(":f")) && !self) {
        inF = true;
        f = "";
      }
    },
    end(name) {
      if (name === "f" || name.endsWith(":f")) {
        inF = false;
        if (DDE_FORMULA.test(f)) env.addAt([part], "OFFICE_DDE", { evidence: excerpt(f) });
      }
    },
    text(t) {
      if (inF && f.length < 10_000) f += t;
    },
  }, { step: (n) => env.ctx.step(n) });
}

/** @internal OOXML analysis. Returns the refined type. */
export function analyzeOoxml(env: Env, parts: PartReader, ctXml: string): DetectedType {
  const zip = parts.zip;
  // main document type from the content types and the package relationships
  const overrides = new Map<string, string>();
  tokenize(ctXml, {
    start(name, attrs) {
      if (name.endsWith("Override")) overrides.set((attr(attrs, "PartName") ?? "").replace(/^\//, ""), (attr(attrs, "ContentType") ?? "").toLowerCase());
    },
  }, { step: (n) => env.ctx.step(n) });
  const pkgRels = parseRels(env, parts.text("_rels/.rels") ?? "");
  const mainRel = pkgRels.find((r) => r.type.endsWith("/officeDocument") && !r.external);
  const mainPart = mainRel ? resolveTarget("_rels/.rels", mainRel.target) : "";
  const format = MAIN_TYPES[overrides.get(mainPart) ?? ""] ?? [...overrides.values()].map((t) => MAIN_TYPES[t]).find(Boolean) ?? "ooxml";
  const type = detectedType(format, format === "ooxml" ? "medium" : "high");

  const names = zip.entries.map((e) => e.name);
  const vba = names.filter((n) => /(?:^|\/)vbaProject\.bin$/i.test(n));
  if (vba.length && MACRO_FREE.has(format)) env.addAt([vba[0] as string], "OFFICE_MACRO_CONTENT_TYPE", { evidence: excerpt(`${format} package contains ${vba[0]}`) });

  // relationships
  for (const relsName of names.filter((n) => /\.rels$/i.test(n))) {
    const xml = parts.text(relsName);
    if (!xml) continue;
    for (const r of parseRels(env, xml)) {
      const kind = r.type.slice(r.type.lastIndexOf("/") + 1);
      const scheme = dangerousSchemeOf(r.target);
      const ev = excerpt(`${kind} → ${r.target}`);
      if (scheme && (r.external || /^[a-z][a-z0-9+.-]*:/i.test(r.target))) env.addAt([relsName], "OOXML_SUSPICIOUS_SCHEME", { element: r.id, evidence: ev });
      if (!r.external) continue;
      if (kind === "attachedTemplate") env.addAt([relsName], "OOXML_REMOTE_TEMPLATE", { element: r.id, evidence: ev });
      else if (kind === "oleObject") env.addAt([relsName], "OOXML_EXTERNAL_OLE_LINK", { element: r.id, evidence: ev });
      else if (kind === "frame" || kind === "subDocument") env.addAt([relsName], "OOXML_EXTERNAL_FRAME", { element: r.id, evidence: ev });
      else if (kind !== "hyperlink" && !scheme) env.addAt([relsName], "OOXML_EXTERNAL_RELATIONSHIP", { element: r.id, evidence: ev });
    }
  }

  // DDE and fields
  for (const n of names) {
    if (/^word\/(?:document|header\d*|footer\d*|footnotes|endnotes|comments|glossary\/document)\.xml$/i.test(n)) {
      const xml = parts.text(n);
      if (xml) checkWordFields(env, n, xml);
    } else if (/^xl\/externalLinks\/[^/]+\.xml$/i.test(n)) {
      const xml = parts.text(n);
      if (xml && /<(?:\w+:)?ddeLink\b/.test(xml)) env.addAt([n], "OFFICE_DDE", { evidence: excerpt(/ddeService="[^"]{0,200}"[^>]{0,300}/.exec(xml)?.[0] ?? "ddeLink") });
    } else if (/^xl\/worksheets\/[^/]+\.xml$/i.test(n)) {
      const xml = parts.text(n);
      if (xml && xml.includes("|")) checkSheetFormulas(env, n, xml);
    }
  }

  // Excel 4.0 macro sheets and Auto_Open
  const macroSheets = names.filter((n) => /^xl\/macrosheets\//i.test(n) && !/\/_rels\//.test(n));
  if (macroSheets.length || names.some((n) => /^xl\/workbook\.xml$/i.test(n))) {
    const wb = parts.text("xl/workbook.xml") ?? "";
    const wbRels = parseRels(env, parts.text("xl/_rels/workbook.xml.rels") ?? "");
    const state = new Map<string, string>();
    tokenize(wb, {
      start(name, attrs) {
        if (name.endsWith("sheet") && !name.endsWith("Sheet")) {
          const rid = attr(attrs, "id") ?? "";
          const rel = wbRels.find((r) => r.id === rid);
          if (rel) state.set(resolveTarget("xl/_rels/workbook.xml.rels", rel.target).toLowerCase(), `${attr(attrs, "name") ?? ""} (${attr(attrs, "state") ?? "visible"})`);
        }
        if (name.endsWith("definedName")) {
          const nm = (attr(attrs, "name") ?? "").toLowerCase();
          if (nm === "_xlnm.auto_open" || nm.startsWith("auto_open")) env.addAt(["xl/workbook.xml"], "XLM_AUTO_OPEN", { evidence: excerpt(attr(attrs, "name") ?? "") });
        }
      },
    }, { step: (n) => env.ctx.step(n) });
    for (const m of macroSheets) env.addAt([m], "XLM_MACRO_SHEET", { evidence: excerpt(state.get(m.toLowerCase()) ?? m) });
    // xlsb workbooks keep sheet state in binary records; the macro sheet part itself is the signal
  }

  if (names.some((n) => /\/activeX\//i.test(n))) env.add("OOXML_ACTIVEX", { evidence: `${names.filter((n) => /\/activeX\/[^/]+\.(?:xml|bin)$/i.test(n)).length} ActiveX part(s)` });
  for (const n of names) if (/\/embeddings\/[^/]+$/i.test(n)) env.addAt([n], "OOXML_EMBEDDED_OBJECT", { evidence: excerpt(n) });
  if (names.some((n) => /^customXml\/item\d*\.xml$/i.test(n))) env.add("OOXML_CUSTOM_XML", { evidence: `${names.filter((n) => /^customXml\//i.test(n)).length} custom XML part(s)` });
  return type;
}

const ODF_TYPES: Readonly<Record<string, string>> = {
  "application/vnd.oasis.opendocument.text": "odt",
  "application/vnd.oasis.opendocument.spreadsheet": "ods",
  "application/vnd.oasis.opendocument.presentation": "odp",
  "application/vnd.oasis.opendocument.graphics": "odg",
  "application/vnd.oasis.opendocument.text-template": "odt",
  "application/vnd.oasis.opendocument.spreadsheet-template": "ods",
  "application/vnd.oasis.opendocument.presentation-template": "odp",
};

/** @internal OpenDocument analysis (StarBasic macros and load events). */
export function analyzeOdf(env: Env, parts: PartReader, mimetype: string): DetectedType {
  const format = ODF_TYPES[mimetype.trim()] ?? "odt";
  const modules = parts.zip.entries.filter((e) => /^Basic\/[^/]+\/[^/]+\.xml$/i.test(e.name) && !/\/script-l[bc]\.xml$/i.test(e.name));
  if (modules.length) {
    env.add("OFFICE_VBA_MACROS", { evidence: excerpt(`StarBasic: ${modules.map((m) => m.name).join(", ")}`) });
    for (const m of modules) {
      const xml = parts.text(m.name);
      if (!xml) continue;
      const open = xml.indexOf("<script:module");
      const gt = open < 0 ? -1 : xml.indexOf(">", open);
      const close = xml.lastIndexOf("</script:module>");
      const body = gt >= 0 && close > gt ? xml.slice(gt + 1, close) : "";
      analyzeSource(env, [m.name], decodeEntities(body.replace(/<!\[CDATA\[|\]\]>/g, "")));
    }
  }
  for (const part of ["content.xml", "styles.xml", "settings.xml"]) {
    const xml = parts.text(part);
    if (!xml) continue;
    const m = /script:event-name="(dom:load|office:load|office:new|office:open)"[^>]{0,500}/.exec(xml);
    if (m) env.addAt([part], "VBA_AUTOEXEC", { evidence: excerpt(m[0]) });
  }
  return detectedType(format, "high");
}
