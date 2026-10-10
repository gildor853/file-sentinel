/** Format catalogue: canonical MIME type, accepted extensions and MIME types, and risk class. */

export type FormatKind = "document" | "image" | "archive" | "executable" | "script" | "active" | "text" | "other";

export interface FormatInfo {
  readonly mime: string;
  readonly exts: readonly string[];
  /** Additional MIME types that are acceptable as a declaration for this format. */
  readonly mimes: readonly string[];
  readonly kind: FormatKind;
  readonly label: string;
}

const ZIPISH = ["application/zip", "application/x-zip-compressed", "application/x-zip"];
const OCTET = "application/octet-stream";

const f = (label: string, kind: FormatKind, mime: string, exts: string[], mimes: string[] = []): FormatInfo => ({ label, kind, mime, exts, mimes });

const TEXT_EXTS = ["txt", "text", "csv", "tsv", "log", "md", "markdown", "json", "ndjson", "yaml", "yml", "toml", "ini", "cfg", "conf", "sql", "srt", "vtt", "ics", "vcf", "eml", "css", "tex", "rst", "properties", "env"];
const SCRIPT_TEXT_EXTS = ["js", "mjs", "cjs", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "psd1", "bat", "cmd", "sh", "bash", "zsh", "py", "pl", "rb", "php", "lua", "applescript", "scpt", "sct", "reg", "inf", "url", "iqy", "slk", "settingcontent-ms", "library-ms", "searchconnector-ms", "appref-ms", "application"];

export const FORMATS: Readonly<Record<string, FormatInfo>> = {
  pdf: f("PDF document", "document", "application/pdf", ["pdf"], ["application/x-pdf"]),
  zip: f("ZIP archive", "archive", "application/zip", ["zip", "zipx"], ZIPISH),
  docx: f("Word document", "document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ["docx"], ZIPISH),
  docm: f("Word macro-enabled document", "document", "application/vnd.ms-word.document.macroEnabled.12", ["docm"], ZIPISH),
  dotx: f("Word template", "document", "application/vnd.openxmlformats-officedocument.wordprocessingml.template", ["dotx"], ZIPISH),
  dotm: f("Word macro-enabled template", "document", "application/vnd.ms-word.template.macroEnabled.12", ["dotm"], ZIPISH),
  xlsx: f("Excel workbook", "document", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ["xlsx"], ZIPISH),
  xlsm: f("Excel macro-enabled workbook", "document", "application/vnd.ms-excel.sheet.macroEnabled.12", ["xlsm"], ZIPISH),
  xltx: f("Excel template", "document", "application/vnd.openxmlformats-officedocument.spreadsheetml.template", ["xltx"], ZIPISH),
  xltm: f("Excel macro-enabled template", "document", "application/vnd.ms-excel.template.macroEnabled.12", ["xltm"], ZIPISH),
  xlam: f("Excel add-in", "document", "application/vnd.ms-excel.addin.macroEnabled.12", ["xlam"], ZIPISH),
  xlsb: f("Excel binary workbook", "document", "application/vnd.ms-excel.sheet.binary.macroEnabled.12", ["xlsb"], ZIPISH),
  pptx: f("PowerPoint presentation", "document", "application/vnd.openxmlformats-officedocument.presentationml.presentation", ["pptx"], ZIPISH),
  pptm: f("PowerPoint macro-enabled presentation", "document", "application/vnd.ms-powerpoint.presentation.macroEnabled.12", ["pptm"], ZIPISH),
  ppsx: f("PowerPoint show", "document", "application/vnd.openxmlformats-officedocument.presentationml.slideshow", ["ppsx"], ZIPISH),
  ppsm: f("PowerPoint macro-enabled show", "document", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12", ["ppsm"], ZIPISH),
  potx: f("PowerPoint template", "document", "application/vnd.openxmlformats-officedocument.presentationml.template", ["potx"], ZIPISH),
  potm: f("PowerPoint macro-enabled template", "document", "application/vnd.ms-powerpoint.template.macroEnabled.12", ["potm"], ZIPISH),
  ooxml: f("Office Open XML package", "document", "application/zip", ["docx", "xlsx", "pptx"], ZIPISH),
  odt: f("OpenDocument text", "document", "application/vnd.oasis.opendocument.text", ["odt", "ott"], ZIPISH),
  ods: f("OpenDocument spreadsheet", "document", "application/vnd.oasis.opendocument.spreadsheet", ["ods", "ots"], ZIPISH),
  odp: f("OpenDocument presentation", "document", "application/vnd.oasis.opendocument.presentation", ["odp", "otp"], ZIPISH),
  odg: f("OpenDocument drawing", "document", "application/vnd.oasis.opendocument.graphics", ["odg", "otg"], ZIPISH),
  epub: f("EPUB e-book", "document", "application/epub+zip", ["epub"], ZIPISH),
  jar: f("Java archive", "executable", "application/java-archive", ["jar", "war", "ear"], [...ZIPISH, "application/x-java-archive"]),
  apk: f("Android package", "executable", "application/vnd.android.package-archive", ["apk", "aab", "xapk"], ZIPISH),
  doc: f("Word 97-2003 document", "document", "application/msword", ["doc", "dot"]),
  xls: f("Excel 97-2003 workbook", "document", "application/vnd.ms-excel", ["xls", "xlt", "xla"]),
  ppt: f("PowerPoint 97-2003 presentation", "document", "application/vnd.ms-powerpoint", ["ppt", "pps", "pot"]),
  msi: f("Windows Installer package", "executable", "application/x-msi", ["msi", "msp", "mst"], ["application/x-ms-installer", "application/x-ole-storage"]),
  msg: f("Outlook message", "document", "application/vnd.ms-outlook", ["msg"]),
  cfb: f("Compound File Binary", "other", "application/x-ole-storage", ["doc", "xls", "ppt", "msg", "msi", "pub", "vsd", "db", "bin"]),
  "office-encrypted": f("Encrypted Office document", "document", "application/x-ole-storage", ["docx", "docm", "xlsx", "xlsm", "xlsb", "pptx", "pptm", "doc", "xls", "ppt"], [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
  ]),
  rtf: f("Rich Text Format", "document", "application/rtf", ["rtf", "doc"], ["text/rtf"]),
  svg: f("SVG image", "active", "image/svg+xml", ["svg", "svgz"]),
  html: f("HTML document", "active", "text/html", ["html", "htm", "xhtml", "xht", "shtml", "mht", "mhtml", "hta"], ["application/xhtml+xml", "application/hta"]),
  xml: f("XML document", "text", "application/xml", ["xml", "xsd", "xsl", "xslt", "rss", "atom", "plist", "kml", "gpx", "config", "resx", "csproj", "xaml", "drawio", "xlf"], ["text/xml"]),
  png: f("PNG image", "image", "image/png", ["png", "apng"], ["image/apng"]),
  jpeg: f("JPEG image", "image", "image/jpeg", ["jpg", "jpeg", "jpe", "jfif", "pjpeg", "pjp"], ["image/pjpeg"]),
  gif: f("GIF image", "image", "image/gif", ["gif"]),
  webp: f("WebP image", "image", "image/webp", ["webp"]),
  bmp: f("BMP image", "image", "image/bmp", ["bmp", "dib"], ["image/x-bmp", "image/x-ms-bmp"]),
  tiff: f("TIFF image", "image", "image/tiff", ["tif", "tiff", "dng", "nef", "cr2", "arw"]),
  ico: f("Windows icon", "image", "image/vnd.microsoft.icon", ["ico", "cur"], ["image/x-icon"]),
  gzip: f("gzip archive", "archive", "application/gzip", ["gz", "tgz", "svgz"], ["application/x-gzip"]),
  tar: f("tar archive", "archive", "application/x-tar", ["tar"]),
  "7z": f("7-Zip archive", "archive", "application/x-7z-compressed", ["7z"]),
  rar: f("RAR archive", "archive", "application/vnd.rar", ["rar"], ["application/x-rar-compressed", "application/x-rar"]),
  bzip2: f("bzip2 archive", "archive", "application/x-bzip2", ["bz2", "tbz2", "tbz"]),
  xz: f("xz archive", "archive", "application/x-xz", ["xz", "txz"]),
  zstd: f("Zstandard archive", "archive", "application/zstd", ["zst", "tzst"]),
  cab: f("Cabinet archive", "archive", "application/vnd.ms-cab-compressed", ["cab"]),
  iso: f("ISO 9660 disk image", "executable", "application/x-iso9660-image", ["iso", "img"], ["application/x-cd-image"]),
  vhd: f("Virtual hard disk", "executable", "application/x-vhd", ["vhd", "vhdx"]),
  pe: f("Windows executable (PE)", "executable", "application/vnd.microsoft.portable-executable", ["exe", "dll", "sys", "scr", "cpl", "ocx", "com", "efi", "xll", "drv", "msstyles", "mui", "ax", "pif"], ["application/x-msdownload", "application/x-dosexec", "application/x-msdos-program"]),
  elf: f("ELF executable", "executable", "application/x-executable", ["", "so", "o", "elf", "bin", "run", "ko", "axf", "out"], ["application/x-elf", "application/x-sharedlib", "application/x-pie-executable"]),
  macho: f("Mach-O executable", "executable", "application/x-mach-binary", ["", "dylib", "bundle", "so", "o"], ["application/x-mach-o-executable"]),
  class: f("Java class file", "executable", "application/java-vm", ["class"], ["application/x-java-class"]),
  dex: f("Dalvik executable", "executable", "application/vnd.android.dex", ["dex"]),
  lnk: f("Windows shortcut", "executable", "application/x-ms-shortcut", ["lnk"]),
  chm: f("Compiled HTML Help", "script", "application/vnd.ms-htmlhelp", ["chm"]),
  "script-encoded": f("Encoded Windows script", "script", "text/plain", ["jse", "vbe"]),
  script: f("Script", "script", "text/plain", ["sh", "bash", "zsh", "py", "pl", "rb", "php", "js", "mjs", "cjs", "ps1", "command", "", "cgi"], ["application/x-sh", "text/x-shellscript", "text/x-python", "application/javascript", "text/javascript"]),
  wasm: f("WebAssembly module", "other", "application/wasm", ["wasm"]),
  text: f("Text", "text", "text/plain", [...TEXT_EXTS, ...SCRIPT_TEXT_EXTS, "xml", "html", "htm", "svg", "rtf"], ["text/csv", "application/json", "text/markdown", "application/x-ndjson", "text/css", "application/javascript", "text/javascript", "application/x-sh", "text/x-python"]),
  empty: f("Empty file", "other", "application/x-empty", []),
  unknown: f("Unknown binary", "other", OCTET, []),
};

/** Lowercase extensions known to belong to some format (used for mismatch decisions). */
export const KNOWN_EXTS: ReadonlySet<string> = new Set(
  Object.entries(FORMATS)
    .filter(([id]) => id !== "unknown" && id !== "cfb" && id !== "ooxml")
    .flatMap(([, v]) => v.exts)
    .filter((e) => e !== ""),
);

/** Extensions Windows (or a typical desktop) executes or opens with a script host. */
export const EXECUTABLE_EXTS: ReadonlySet<string> = new Set([
  "exe", "scr", "com", "pif", "cpl", "dll", "ocx", "sys", "drv", "efi", "xll", "msi", "msp", "mst", "msc", "bat", "cmd", "ps1", "psm1", "psd1",
  "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "sct", "hta", "lnk", "url", "jar", "reg", "inf", "chm", "hlp", "iso", "img", "vhd", "vhdx",
  "appref-ms", "application", "gadget", "settingcontent-ms", "library-ms", "searchconnector-ms", "msix", "msixbundle", "appx", "appxbundle",
  "app", "command", "sh", "apk", "deb", "rpm", "run", "bin", "elf", "py", "pyw", "pl", "iqy", "slk", "one", "xbap",
]);

/** Extensions of formats users open as documents or media (the "decoy" half of a double extension). */
export const DECOY_EXTS: ReadonlySet<string> = new Set([
  "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt", "csv", "odt", "ods", "jpg", "jpeg", "png", "gif", "bmp",
  "tif", "tiff", "webp", "svg", "mp3", "mp4", "wav", "avi", "mov", "mkv", "wmv", "zip", "rar", "7z", "html", "htm", "eml", "msg", "ics",
]);

/** @internal The format record (falls back to `unknown`). */
export function formatInfo(id: string): FormatInfo {
  return FORMATS[id] ?? (FORMATS["unknown"] as FormatInfo);
}

/** @internal Lowercase extension of a file name ("" when none). */
export function extensionOf(name: string): string {
  const base = baseName(name);
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? "" : base.slice(dot + 1).trim().toLowerCase();
}

/** @internal File name without directories (both separators). */
export function baseName(name: string): string {
  const k = Math.max(name.lastIndexOf("/"), name.lastIndexOf("\\"));
  return k >= 0 ? name.slice(k + 1) : name;
}

/** @internal MIME type without parameters, lowercased. */
export function normalizeMime(m: string): string {
  return (m.split(";")[0] ?? "").trim().toLowerCase();
}

/** @internal True when `mime` is a MIME type that some catalogued format uses. */
export function knownMime(mime: string): boolean {
  for (const v of Object.values(FORMATS)) if (v.mime === mime || v.mimes.includes(mime)) return true;
  return false;
}

/** @internal A DetectedType record for a format id. */
export function detectedType(format: string, confidence: "high" | "medium" | "low"): import("./types.js").DetectedType {
  return { format, mime: formatInfo(format).mime, confidence };
}
