/**
 * Tolerant, linear-time markup tokenizer for XML and HTML. It never builds a
 * DOM, never resolves external resources and never expands entities other
 * than the five predefined ones and numeric character references.
 */

export interface MarkupHandler {
  start?(name: string, attrs: Attr[], selfClosing: boolean, offset: number): void;
  end?(name: string, offset: number): void;
  text?(text: string, offset: number): void;
  /** Contents of HTML raw-text elements (script, style) and of CDATA sections. */
  raw?(text: string, element: string, offset: number): void;
  pi?(target: string, data: string, offset: number): void;
  doctype?(raw: string, offset: number): void;
  comment?(text: string, offset: number): void;
}

export interface Attr {
  /** Name as written (lowercased in HTML mode). */
  name: string;
  /** Value with character references decoded. */
  value: string;
}

const RAW_TEXT = new Set(["script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "plaintext"]);

const XML_ENTITIES = new Map([["lt", "<"], ["gt", ">"], ["amp", "&"], ["quot", '"'], ["apos", "'"]]);
/** The XML five plus the HTML named references that matter for URL and script obfuscation. */
const HTML_ENTITIES = new Map([...XML_ENTITIES, ["colon", ":"], ["tab", "\t"], ["newline", "\n"], ["sol", "/"], ["lpar", "("], ["rpar", ")"], ["nbsp", "\u00a0"], ["period", "."], ["comma", ","], ["semi", ";"], ["equals", "="]]);

/** @internal Decodes the five predefined entities and numeric character references; other `&name;` stay literal. */
export function decodeEntities(s: string, html = false): string {
  if (!s.includes("&")) return s;
  let out = "";
  let i = 0;
  while (i < s.length) {
    const amp = s.indexOf("&", i);
    if (amp < 0) {
      out += s.slice(i);
      break;
    }
    out += s.slice(i, amp);
    const semi = s.indexOf(";", amp + 1);
    const body = semi > amp && semi - amp <= 12 ? s.slice(amp + 1, semi) : undefined;
    let rep: string | undefined;
    if (body !== undefined) {
      if (body[0] === "#") {
        const hex = body[1] === "x" || body[1] === "X";
        const digits = hex ? body.slice(2) : body.slice(1);
        if (digits.length > 0 && (hex ? /^[0-9a-fA-F]{1,8}$/ : /^[0-9]{1,10}$/).test(digits)) {
          const cp = parseInt(digits, hex ? 16 : 10);
          rep = cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "\uFFFD";
        }
      } else {
        rep = (html ? HTML_ENTITIES : XML_ENTITIES).get(body) ?? (html ? HTML_ENTITIES.get(body.toLowerCase()) : undefined);
      }
    } else if (html && s[amp + 1] === "#") {
      // HTML also accepts numeric references without the trailing semicolon (&#106avascript:)
      const m = /^&#(?:[xX]([0-9a-fA-F]{1,8})|([0-9]{1,10}))/.exec(s.slice(amp, amp + 13));
      if (m) {
        const cp = m[1] !== undefined ? parseInt(m[1], 16) : parseInt(m[2] as string, 10);
        out += cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "\uFFFD";
        i = amp + m[0].length;
        continue;
      }
    }
    if (rep !== undefined && body !== undefined) {
      out += rep;
      i = semi + 1;
    } else {
      out += "&";
      i = amp + 1;
    }
  }
  return out;
}

const isNameStart = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 58 || c > 127;
const isSpace = (c: number) => c === 32 || c === 9 || c === 10 || c === 13 || c === 12;

/**
 * @internal Tokenizes `src`. `step(n)` is charged per token (may throw to abort).
 * Malformed markup is skipped or treated as text, never thrown on.
 */
export function tokenize(src: string, h: MarkupHandler, opts: { html?: boolean; step?: (n: number) => void } = {}): void {
  const html = opts.html === true;
  const step = opts.step ?? (() => {});
  const n = src.length;
  let i = 0;
  while (i < n) {
    const lt = src.indexOf("<", i);
    if (lt < 0) {
      if (h.text) h.text(decodeEntities(src.slice(i), html), i);
      step((n - i) >>> 6);
      return;
    }
    if (lt > i && h.text) h.text(decodeEntities(src.slice(i, lt), html), i);
    step(1 + ((lt - i) >>> 6));
    i = lt;
    const c1 = src.charCodeAt(i + 1);
    if (src.startsWith("<!--", i)) {
      const e = src.indexOf("-->", i + 4);
      const end = e < 0 ? n : e;
      if (h.comment) h.comment(src.slice(i + 4, end), i);
      i = e < 0 ? n : e + 3;
    } else if (src.startsWith("<![CDATA[", i)) {
      const e = src.indexOf("]]>", i + 9);
      const end = e < 0 ? n : e;
      if (h.raw) h.raw(src.slice(i + 9, end), "#cdata", i);
      i = e < 0 ? n : e + 3;
    } else if (c1 === 33 /* ! */) {
      // DOCTYPE (with an optional internal subset) or another declaration
      let j = i + 2;
      let depth = 0;
      let quote = 0;
      for (; j < n; j++) {
        const c = src.charCodeAt(j);
        if (quote) {
          if (c === quote) quote = 0;
        } else if (c === 34 || c === 39) quote = depth > 0 || !html ? c : 0;
        else if (c === 91) depth++;
        else if (c === 93) depth = Math.max(0, depth - 1);
        else if (c === 62 && depth === 0) break;
      }
      step((j - i) >>> 6);
      const raw = src.slice(i, Math.min(j + 1, n));
      if (/^<!doctype/i.test(raw)) {
        if (h.doctype) h.doctype(raw, i);
      } else if (h.comment) h.comment(raw.slice(2, -1), i);
      i = j + 1;
    } else if (c1 === 63 /* ? */) {
      const e = src.indexOf(html ? ">" : "?>", i + 2);
      const end = e < 0 ? n : e;
      const body = src.slice(i + 2, end);
      const m = /^([^\s?>]{0,100})\s?/.exec(body);
      if (h.pi) h.pi(m?.[1] ?? "", body.slice(m?.[0].length ?? 0), i);
      i = e < 0 ? n : e + (html ? 1 : 2);
    } else if (c1 === 47 /* / */) {
      const e = src.indexOf(">", i + 2);
      const end = e < 0 ? n : e;
      let name = src.slice(i + 2, end).trim();
      const sp = name.search(/[\s/]/);
      if (sp >= 0) name = name.slice(0, sp);
      if (html) name = name.toLowerCase();
      if (h.end && name) h.end(name, i);
      i = e < 0 ? n : e + 1;
    } else if (isNameStart(c1)) {
      // start tag
      let j = i + 1;
      while (j < n) {
        const c = src.charCodeAt(j);
        if (isSpace(c) || c === 47 || c === 62) break;
        j++;
      }
      let name = src.slice(i + 1, j);
      if (html) name = name.toLowerCase();
      const attrs: Attr[] = [];
      let selfClosing = false;
      // attributes
      for (;;) {
        while (j < n && isSpace(src.charCodeAt(j))) j++;
        if (j >= n) break;
        const c = src.charCodeAt(j);
        if (c === 62) {
          j++;
          break;
        }
        if (c === 47) {
          if (src.charCodeAt(j + 1) === 62) {
            selfClosing = true;
            j += 2;
            break;
          }
          j++;
          continue;
        }
        if (!html && c === 60) break; // broken tag: let the next iteration handle '<'
        const ns = j;
        while (j < n) {
          const d = src.charCodeAt(j);
          if (isSpace(d) || d === 61 || d === 62 || (d === 47 && src.charCodeAt(j + 1) === 62) || (!html && d === 60)) break;
          j++;
        }
        let aname = src.slice(ns, j);
        if (j === ns) {
          j++;
          continue;
        }
        if (html) aname = aname.toLowerCase();
        while (j < n && isSpace(src.charCodeAt(j))) j++;
        let value = "";
        if (src.charCodeAt(j) === 61) {
          j++;
          while (j < n && isSpace(src.charCodeAt(j))) j++;
          const q = src.charCodeAt(j);
          if (q === 34 || q === 39) {
            const e = src.indexOf(q === 34 ? '"' : "'", j + 1);
            const end = e < 0 ? n : e;
            value = src.slice(j + 1, end);
            j = e < 0 ? n : e + 1;
          } else {
            const vs = j;
            while (j < n && !isSpace(src.charCodeAt(j)) && src.charCodeAt(j) !== 62) j++;
            value = src.slice(vs, j);
          }
        }
        if (attrs.length < 1000) attrs.push({ name: aname, value: decodeEntities(value, html) });
      }
      step(1 + attrs.length);
      if (h.start) h.start(name, attrs, selfClosing, i);
      i = j;
      const lname = name.toLowerCase();
      if (html && !selfClosing && RAW_TEXT.has(lname)) {
        // raw text until the matching end tag
        const close = indexOfCloseTag(src, lname, i);
        const end = close < 0 ? n : close;
        if (h.raw) h.raw(src.slice(i, end), lname, i);
        step((end - i) >>> 6);
        i = end;
      } else if (!html && !selfClosing && lname.endsWith("script") && (name === "script" || name.endsWith(":script"))) {
        // XML script elements: report their text (including CDATA) as raw text as well
        const close = indexOfCloseTag(src, name.toLowerCase(), i);
        const end = close < 0 ? n : close;
        const body = src.slice(i, end);
        if (h.raw) h.raw(body.replace(/<!\[CDATA\[|\]\]>/g, ""), name, i);
        step((end - i) >>> 6);
        i = end;
      }
    } else {
      // a lone '<': text
      if (h.text) h.text("<", i);
      i++;
    }
  }
}

function indexOfCloseTag(src: string, name: string, from: number): number {
  let i = from;
  const lower = name.toLowerCase();
  for (;;) {
    const k = src.indexOf("</", i);
    if (k < 0) return -1;
    if (src.slice(k + 2, k + 2 + lower.length).toLowerCase() === lower) {
      const c = src.charCodeAt(k + 2 + lower.length);
      if (Number.isNaN(c) || isSpace(c) || c === 62 || c === 47) return k;
    }
    i = k + 2;
  }
}
