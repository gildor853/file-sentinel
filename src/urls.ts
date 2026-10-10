/** URL classification shared by the markup, PDF and Office checks. */

/** @internal Lowercased URL with ASCII whitespace and control characters removed (browsers ignore them in schemes). */
export function normalizeUrl(u: string): string {
  let out = "";
  for (let i = 0; i < u.length && out.length < 4096; i++) {
    const c = u.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f || (c >= 0x200b && c <= 0x200d) || c === 0xfeff || c === 0xad) continue;
    out += u[i];
  }
  return out.toLowerCase();
}

/** @internal Scheme (lowercase, without ':') or undefined for relative references. */
export function schemeOf(u: string): string | undefined {
  const m = /^([a-z][a-z0-9+.-]{0,40}):/.exec(normalizeUrl(u));
  return m ? m[1] : undefined;
}

/** @internal `javascript:`, `vbscript:` and HTML/XHTML `data:` URLs. */
export function isScriptUrl(u: string): boolean {
  const n = normalizeUrl(u);
  if (/^(?:javascript|vbscript|livescript|mocha):/.test(n)) return true;
  return /^data:(?:text\/html|application\/xhtml\+xml|text\/xml|application\/xml|image\/svg\+xml)[;,]/.test(n);
}

/** @internal URLs that make a renderer fetch something from elsewhere. */
export function isExternalUrl(u: string): boolean {
  const n = normalizeUrl(u);
  return /^(?:https?|ftp|file|smb|gopher|ws|wss):/.test(n) || n.startsWith("//") || n.startsWith("\\\\");
}

/**
 * @internal Schemes that are dangerous as link or relationship targets in documents:
 * script URLs, local files, UNC/SMB paths (NTLM leaks) and Windows protocol
 * handlers abused for code execution (ms-msdt: Follina, search-ms:, mhtml:, ...).
 */
export function dangerousSchemeOf(u: string): string | undefined {
  const n = normalizeUrl(u);
  if (n.startsWith("\\\\")) return "UNC path";
  const s = schemeOf(n);
  if (s === undefined) return undefined;
  if (/^[a-z]$/.test(s)) return "local path"; // C:\...
  const BAD = new Set([
    "javascript", "vbscript", "livescript", "file", "smb", "data", "mhtml", "mk", "ms-its", "its", "ms-msdt", "search-ms", "search",
    "ms-search", "ms-officecmd", "ms-word", "ms-excel", "ms-powerpoint", "ms-appinstaller", "ms-cxh", "ms-cxh-full", "hcp", "jar",
    "shell", "ms-settings", "microsoft-edge", "ms-access", "ms-visio", "ms-project", "ms-publisher", "ms-spd", "ms-infopath", "cmd", "powershell",
  ]);
  return BAD.has(s) ? `${s}:` : undefined;
}
