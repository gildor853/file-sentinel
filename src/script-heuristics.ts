/** Heuristics over script text: HTML smuggling and run-time decoding/evaluation. */

/** @internal Length of the longest run of base64 characters (ignoring line breaks). */
export function longestBase64Run(s: string, stopAt = Infinity): number {
  let best = 0;
  let run = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47 || c === 61) {
      run++;
      if (run > best) {
        best = run;
        if (best >= stopAt) return best;
      }
    } else if (c === 10 || c === 13 || (c === 92 && (s[i + 1] === "n" || s[i + 1] === "r"))) {
      // line breaks inside the payload (also escaped ones in string literals)
      if (c === 92) i++;
    } else if (c === 34 || c === 39) {
      // string concatenation of chunks: "AAAA" + "BBBB"
      let j = i + 1;
      while (j < s.length && j - i < 8 && " \t\r\n+".includes(s[j] as string)) j++;
      if (j < s.length && (s[j] === '"' || s[j] === "'") && j > i + 1) i = j;
      else run = 0;
    } else run = 0;
  }
  return best;
}

/** Size of an encoded blob that suggests a smuggled file rather than an icon or font. */
export const SMUGGLING_PAYLOAD = 4096;

export interface SmugglingSignals {
  blob: boolean;
  save: boolean;
  decode: boolean;
  payload: number;
}

/** @internal Signals of HTML smuggling (MITRE ATT&CK T1027.006) in script text. */
export function smugglingSignals(script: string): SmugglingSignals {
  return {
    blob: /\bnew\s{0,10}(?:Blob|File)\s{0,10}\(|createObjectURL\s{0,10}\(/.test(script),
    save: /msSaveOrOpenBlob|msSaveBlob|\.download\s{0,10}=|setAttribute\s{0,10}\(\s{0,10}["']download["']|\bdownload\s{0,10}:/.test(script),
    decode: /\batob\s{0,10}\(|base64ToArrayBuffer|\bUint8Array\b|charCodeAt\s{0,10}\(|fromCharCode/.test(script),
    payload: longestBase64Run(script, 1 << 20),
  };
}

/** @internal True when the signals amount to a smuggling pattern. */
export function isSmuggling(s: SmugglingSignals, downloadAttr: boolean): boolean {
  const save = s.save || downloadAttr;
  const encoded = s.payload >= SMUGGLING_PAYLOAD;
  return (s.blob && save && (encoded || s.decode)) || (/* msSaveOrOpenBlob alone with a payload */ s.save && s.decode && encoded);
}

/** @internal Run-time decode-and-execute patterns; returns the matched snippet or undefined. */
export function obfuscatedScript(script: string): string | undefined {
  const res = [
    /\beval\s{0,10}\(\s{0,10}(?:atob|unescape|decodeURIComponent|escape|String\.fromCharCode|window\.atob)\s{0,10}\(/,
    /\beval\s{0,10}\(\s{0,10}function\s{0,10}\(\s{0,10}p\s{0,10},\s{0,10}a\s{0,10},\s{0,10}c\s{0,10},\s{0,10}k\s{0,10},\s{0,10}e/,
    /document\.write(?:ln)?\s{0,10}\(\s{0,10}(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s{0,10}\(/,
    /\b(?:new\s{1,10})?Function\s{0,10}\(\s{0,10}(?:atob|unescape|decodeURIComponent)\s{0,10}\(/,
    /(?:\\x[0-9a-fA-F]{2}){40}/,
    /(?:%u[0-9a-fA-F]{4}){20}/,
  ];
  for (const re of res) {
    const m = re.exec(script);
    if (m) return m[0];
  }
  // String.fromCharCode(104, 116, 116, ...) with many numeric arguments
  for (let k = script.indexOf("fromCharCode("); k >= 0; k = script.indexOf("fromCharCode(", k + 13)) {
    let commas = 0;
    let j = k + 13;
    for (; j < script.length && j - k < 4096; j++) {
      const c = script[j] as string;
      if (c === ",") commas++;
      else if (c === ")") break;
      else if (!/[\d\s]/.test(c)) break;
    }
    if (commas >= 24 && script[j] === ")") return script.slice(k, Math.min(j + 1, k + 120));
  }
  return undefined;
}
