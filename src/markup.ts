/** SVG, XML and HTML checks. */
import { decode, excerpt } from "./bytes.js";
import type { Env } from "./env.js";
import { isSmuggling, obfuscatedScript, smugglingSignals } from "./script-heuristics.js";
import { textEncoding } from "./sniff.js";
import type { DetectedType } from "./types.js";
import { isExternalUrl, isScriptUrl } from "./urls.js";
import { type Attr, tokenize } from "./xml.js";
import { checkDoctype, checkStylesheetPi } from "./xmlsec.js";

/** @internal Decodes a text file using its BOM or a declared XML/HTML encoding (default UTF-8). */
export function decodeText(b: Uint8Array): string {
  const enc = textEncoding(b);
  if (enc && enc.label !== "utf-8" && enc.label !== "windows-1252") return decode(b.subarray(enc.offset), enc.label);
  const head = decode(b.subarray(0, 1024), "windows-1252");
  const m = /^<\?xml[^>]{0,200}encoding\s{0,5}=\s{0,5}["']([A-Za-z0-9._-]{1,40})["']/.exec(head) ?? /<meta[^>]{0,200}charset\s{0,5}=\s{0,5}["']?([A-Za-z0-9._-]{1,40})/i.exec(head);
  return decode(b.subarray(enc?.offset ?? 0), m ? m[1]!.toLowerCase() : enc?.label ?? "utf-8");
}

const localName = (name: string) => name.slice(name.lastIndexOf(":") + 1).toLowerCase();
const attrEvidence = (a: Attr) => excerpt(`${a.name}="${a.value}"`);

const URL_ATTRS = new Set(["href", "src", "action", "formaction", "data", "from", "to", "values", "background", "poster", "codebase", "lowsrc", "dynsrc", "ping"]);
const EMBED_ELEMENTS = new Set(["iframe", "embed", "object", "frame", "frameset", "applet", "portal", "fencedframe"]);
const SVG_LOADS = new Set(["image", "feimage", "tref", "font-face-uri", "color-profile", "cursor", "audio", "video", "source", "track", "link", "mpath", "textpath", "filter", "pattern", "lineargradient", "radialgradient"]);
const HTML_IN_FOREIGN = new Set(["html", "body", "div", "span", "p", "a", "form", "input", "button", "textarea", "select", "img", "iframe", "style", "table", "h1", "h2", "h3", "video", "audio", "label", "meta", "link", "embed", "object"]);

/** @internal CSS checks used for `style` attributes and `<style>` elements. Returns true if anything was reported. */
function checkCss(env: Env, css: string, element: string, offset: number, svg: boolean): void {
  const lower = css.toLowerCase().replace(/\\0{0,4}([0-9a-f]{2})\s?/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))).replace(/\/\*[\s\S]{0,10000}?\*\//g, "");
  const active = /expression\s{0,10}\(|behavior\s{0,10}:|-moz-binding\s{0,10}:|url\s{0,10}\(\s{0,10}["']?\s{0,10}(?:javascript|vbscript):/.exec(lower);
  if (active) env.add(svg ? "SVG_CSS_ACTIVE" : "HTML_SCRIPT", { offset, element, evidence: excerpt(active[0]) });
  if (!svg) return;
  const imp = /@import\s{0,10}(?:url\s{0,10}\()?\s{0,10}["']?([^"')\s;]{1,500})/.exec(lower);
  if (imp && isExternalUrl(imp[1] as string)) env.add("SVG_EXTERNAL_RESOURCE", { offset, element, evidence: excerpt(imp[0]) });
  const re = /url\s{0,10}\(\s{0,10}["']?([^"')\s]{1,500})/g;
  for (let m = re.exec(lower), k = 0; m && k < 50; m = re.exec(lower), k++) {
    if (isExternalUrl(m[1] as string)) {
      env.add("SVG_EXTERNAL_RESOURCE", { offset, element, evidence: excerpt(m[0]) });
      break;
    }
  }
}

function scriptChecks(env: Env, script: string, element: string, offset: number, downloadAttr: boolean): void {
  if (script.length === 0) return;
  const sig = smugglingSignals(script);
  if (isSmuggling(sig, downloadAttr)) {
    env.add("HTML_SMUGGLING", {
      offset,
      element,
      evidence: excerpt([sig.blob ? "Blob/createObjectURL" : "", sig.save || downloadAttr ? "download/msSaveOrOpenBlob" : "", sig.decode ? "decoding" : "", sig.payload >= 4096 ? `${sig.payload}-char base64` : ""].filter(Boolean).join(" + ")),
    });
  }
  const obf = obfuscatedScript(script);
  if (obf) env.add("HTML_OBFUSCATED_SCRIPT", { offset, element, evidence: excerpt(obf) });
}

/** @internal SVG handler. */
export function scanSvg(env: Env, detected: DetectedType): DetectedType {
  const text = decodeText(env.item.bytes);
  const stack: string[] = [];
  let foreign = 0;
  let foreignReported = false;
  const scripts: { text: string; offset: number }[] = [];
  tokenize(
    text,
    {
      start(name, attrs, selfClosing, offset) {
        const local = localName(name);
        const el = `<${name}>`;
        if (local === "script" || local === "handler" || local === "listener") {
          const src = attrs.find((a) => localName(a.name) === "href" || a.name === "src");
          if (src || local !== "script") env.add("SVG_SCRIPT", { offset, element: el, evidence: src ? attrEvidence(src) : undefined });
        }
        if (EMBED_ELEMENTS.has(local)) env.add("SVG_EMBEDDED_CONTENT", { offset, element: el });
        if (foreign > 0 && !foreignReported && (HTML_IN_FOREIGN.has(local) || attrs.some((a) => a.name === "xmlns" && a.value.includes("xhtml")))) {
          env.add("SVG_FOREIGN_OBJECT_HTML", { offset, element: el });
          foreignReported = true;
        }
        const animate = local === "animate" || local === "set";
        const animatesHref = animate && attrs.some((a) => a.name === "attributeName" && /^(?:xlink:)?href$/i.test(a.value.trim()));
        for (const a of attrs) {
          const an = a.name.toLowerCase();
          const al = localName(an);
          if (al.startsWith("on") && al.length > 2 && /^[a-z]+$/.test(al)) {
            env.add("SVG_EVENT_HANDLER", { offset, element: el, evidence: attrEvidence(a) });
            continue;
          }
          if (an === "style") checkCss(env, a.value, el, offset, true);
          if (!URL_ATTRS.has(al)) continue;
          const values = al === "values" ? a.value.split(";") : [a.value];
          for (const v of values) {
            if (isScriptUrl(v)) {
              env.add(animatesHref && (al === "to" || al === "values" || al === "from") ? "SVG_ANIMATE_SCRIPT_URL" : "SVG_SCRIPT_URL", { offset, element: el, evidence: attrEvidence(a) });
            } else if (al === "href" && local === "use" && !v.trim().startsWith("#") && v.trim() !== "") {
              env.add("SVG_EXTERNAL_USE", { offset, element: el, evidence: attrEvidence(a) });
            } else if ((al === "href" || al === "src") && SVG_LOADS.has(local) && isExternalUrl(v)) {
              env.add("SVG_EXTERNAL_RESOURCE", { offset, element: el, evidence: attrEvidence(a) });
            }
          }
        }
        if (local === "foreignobject" && !selfClosing) foreign++;
        if (!selfClosing) stack.push(local);
        if (stack.length > 10_000) stack.length = 10_000;
      },
      end(name) {
        const local = localName(name);
        // pop to the matching element (tolerates broken nesting)
        const k = stack.lastIndexOf(local);
        if (k >= 0) {
          for (let j = stack.length - 1; j >= k; j--) if (stack[j] === "foreignobject") foreign = Math.max(0, foreign - 1);
          stack.length = k;
        }
      },
      raw(body, element, offset) {
        if (element === "#cdata" && stack[stack.length - 1] === "style") checkCss(env, body, "<style>", offset, true);
        else if (localName(element) === "script") scripts.push({ text: body, offset });
      },
      text(body, offset) {
        if (stack[stack.length - 1] === "style") checkCss(env, body, "<style>", offset, true);
      },
      doctype(raw, offset) {
        checkDoctype(env, raw, offset);
      },
      pi(target, data, offset) {
        checkStylesheetPi(env, target, data, offset);
      },
    },
    { step: (n) => env.ctx.step(n) },
  );
  for (const s of scripts) {
    if (s.text.trim()) env.add("SVG_SCRIPT", { offset: s.offset, element: "<script>", evidence: excerpt(s.text) });
    scriptChecks(env, s.text, "<script>", s.offset, false);
  }
  return detected;
}

/** @internal Generic XML: only DOCTYPE / stylesheet checks (also used for Office XML parts). */
export function scanXml(env: Env, detected: DetectedType, text?: string): DetectedType {
  const src = text ?? decodeText(env.item.bytes);
  // Only the prolog can contain a DOCTYPE; stop tokenizing at the first element.
  const firstEl = src.search(/<[A-Za-z_]/);
  const prolog = firstEl < 0 ? src : src.slice(0, firstEl);
  tokenize(prolog, {
    doctype(raw, offset) {
      checkDoctype(env, raw, offset);
    },
    pi(target, data, offset) {
      checkStylesheetPi(env, target, data, offset);
    },
  }, { step: (n) => env.ctx.step(n) });
  // an XHTML or SVG root further down (after comments) is handled by sniffing; nothing else to check in plain XML
  return detected;
}

/** @internal HTML handler. */
export function scanHtml(env: Env, detected: DetectedType): DetectedType {
  const text = decodeText(env.item.bytes);
  const scripts: string[] = [];
  let firstScriptOffset = -1;
  let downloadAttr = false;
  let downloadData = 0;
  tokenize(
    text,
    {
      start(name, attrs, _self, offset) {
        const el = `<${name}>`;
        if (name === "hta:application") env.add("HTML_HTA", { offset, element: el });
        if (name === "script") {
          const src = attrs.find((a) => a.name === "src");
          env.add("HTML_SCRIPT", { offset, element: el, evidence: src ? attrEvidence(src) : undefined });
          if (firstScriptOffset < 0) firstScriptOffset = offset;
        }
        if (name === "input" && attrs.some((a) => a.name === "type" && a.value.trim().toLowerCase() === "password")) {
          env.add("HTML_CREDENTIAL_FORM", { offset, element: el });
        }
        if (name === "meta" && attrs.some((a) => a.name === "http-equiv" && a.value.trim().toLowerCase() === "refresh")) {
          const content = attrs.find((a) => a.name === "content")?.value ?? "";
          const url = /url\s{0,5}=\s{0,5}['"]?([^'"]{0,2000})/i.exec(content)?.[1] ?? "";
          if (url) env.add(isScriptUrl(url) ? "HTML_SCRIPT" : "HTML_REDIRECT", { offset, element: el, evidence: excerpt(content) });
        }
        const hasDownload = attrs.some((a) => a.name === "download");
        if (hasDownload) downloadAttr = true;
        for (const a of attrs) {
          if (a.name.startsWith("on") && a.name.length > 2 && /^on[a-z]+$/.test(a.name)) {
            env.add("HTML_SCRIPT", { offset, element: el, evidence: attrEvidence(a) });
            scripts.push(a.value);
          } else if (URL_ATTRS.has(a.name) || a.name === "srcdoc") {
            if (isScriptUrl(a.value)) {
              env.add("HTML_SCRIPT", { offset, element: el, evidence: attrEvidence(a) });
              scripts.push(a.value);
            }
            if (hasDownload && /^\s*data:[^,]{0,100};base64,/i.test(a.value)) downloadData = Math.max(downloadData, a.value.length);
          } else if (a.name === "style") checkCss(env, a.value, el, offset, false);
        }
      },
      raw(body, element, offset) {
        if (element === "script") {
          scripts.push(body);
          if (firstScriptOffset < 0) firstScriptOffset = offset;
        } else if (element === "style") checkCss(env, body, "<style>", offset, false);
      },
      doctype(raw, offset) {
        checkDoctype(env, raw, offset);
      },
    },
    { html: true, step: (n) => env.ctx.step(n) },
  );
  if (downloadData >= 4096) {
    env.add("HTML_SMUGGLING", { element: "<a download>", evidence: `download link with a ${downloadData}-character data: URL` });
  }
  scriptChecks(env, scripts.join("\n;\n"), "<script>", Math.max(0, firstScriptOffset), downloadAttr);
  return detected;
}
