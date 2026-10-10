# file-sentinel

Provided as is, without warranty — see [DISCLAIMER.md](./DISCLAIMER.md).

Zero-dependency TypeScript library and CLI that **statically** inspects a file
for risky constructs: active content, macros, exploit building blocks, archive
tricks and type spoofing. It never executes, renders or evaluates anything.

```bash
npm install github:gildor853/file-sentinel#v1.0.0
```

## Honest positioning

**This is a static heuristic risk scanner, not an antivirus.**

- There is no signature database. It cannot detect novel malware in
  executables and every check can be evaded.
- A finding means *"a risky or unusual construct is present"*. The absence of
  findings means *"none of the checked constructs were found"* — **not**
  *"this file is safe"*.
- Layer it with antivirus (for example ClamAV) and CDR / sanitization for
  untrusted uploads. Do not use it as the only gate.
- See [DISCLAIMER.md](./DISCLAIMER.md): there is **no liability for missed threats**.

## Quick start

<!-- readme-check: skip (illustrative; bytes come from the caller) -->
```ts
import { scanSync } from "file-sentinel";

const report = scanSync(bytes, { filename: "upload.pdf" });
// report.verdict: "clean" | "suspicious" | "malicious-indicators" | "error"
// report.findings: [{ id, severity, title, description, location, evidence?, references }]
```

```ts
import { scanSync } from "file-sentinel";

const bytes = new TextEncoder().encode(
  '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
);
const report = scanSync(bytes, { filename: "a.svg" });
report.verdict; // "malicious-indicators"
report.findings.some((f) => f.id === "SVG_SCRIPT"); // true
```

```bash
file-sentinel ./uploads/* --fail-on high
file-sentinel suspect.pdf --json
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above
`--fail-on`, `2` usage / I/O / scan error.

## API

```ts
function scanSync(input: Uint8Array | ArrayBuffer | ArrayBufferView, options?: ScanOptions): ScanReport;
function scan(input: ScanInput | Blob, options?: ScanOptions): Promise<ScanReport>;
```

| Option | Meaning |
| --- | --- |
| `filename` | Declared name (extension + spoofing checks) |
| `declaredMime` | Declared Content-Type |
| `limits` | Resource budgets (see below) |
| `policy.ignore` | Rule ids to drop |
| `policy.minSeverity` | Drop findings below this severity |
| `policy.severity` | Re-rate rules (`{ OFFICE_VBA_MACROS: "high" }`) |

**Verdict:** any remaining `high`/`critical` → `malicious-indicators`;
`low`/`medium` → `suspicious`; only `info` or none → `clean`; internal
failure → `error` (with a `SCAN_ERROR` finding). `FileSentinelError` is thrown
only for invalid arguments, never for hostile file content.

Also exported: `RULES`, `SEVERITIES`, `DEFAULT_LIMITS`, `FileSentinelError`,
`isFileSentinelError`.

## What is checked (high level)

| Area | Examples of rules |
| --- | --- |
| Type / name | Magic vs extension/MIME, polyglots, double extensions, bidi / invisible chars in names |
| SVG / XML | `<script>`, event handlers, `javascript:` URLs, `foreignObject`, XXE / entity expansion |
| HTML | Scripts, HTA, HTML smuggling (Blob + download + large base64), credential forms |
| PDF | `/JavaScript`, `/OpenAction`, `/Launch`, embedded files, suspicious `/URI`, XFA, obfuscated names (pdfid-style) |
| OOXML | VBA (`vbaProject.bin`), DDE, remote templates, external OLE/frame links, XLM macro sheets, ActiveX |
| Legacy Office | VBA, XLM `BOUNDSHEET`, Ole10Native packages, Equation Editor, encryption |
| RTF | `\object` / `\objdata`, Equation.3, `\objupdate`, remote `\template` |
| Archives | Zip-slip, bombs (ratio / overlapping), symlinks, encryption, nested archives; GZIP/TAR; 7z/RAR identified only |
| Executables | PE/ELF/Mach-O, scripts, encoded JSE/VBE, LNK command lines, disk images |
| Images | Pixel bombs, script/HTML in metadata, trailing data |
| Generic | EICAR test file, large base64 / high entropy (info) |

Every rule (except `SCAN_ERROR`) carries references — OWASP, CWE, MITRE ATT&CK,
Microsoft docs, Didier Stevens' pdfid keywords, olevba keyword lists. Run
`file-sentinel --list-rules` for the full catalogue.

## Rules

The table below is generated from `RULES` in the package (`node scripts/rules-table.mjs --write`).

<!-- rules-table:begin -->
| Id | Severity | Scope | Title |
| --- | --- | --- | --- |
| `ACTIVE_CONTENT_DISGUISED` | high | all | HTML or SVG content disguised as another type |
| `EICAR_TEST_FILE` | high | all | EICAR anti-malware test file |
| `EXECUTABLE_DISGUISED` | high | all | Executable content disguised as another type |
| `POLYGLOT` | high | all | File is valid as more than one format |
| `SCAN_ERROR` | medium | all | Scanner error |
| `SCAN_LIMIT` | medium | all | Scan limit reached (not fully inspected) |
| `TYPE_MISMATCH` | medium | all | Declared type does not match content |
| `FILENAME_BIDI_CONTROL` | high | filename | Bidirectional control character in the file name |
| `FILENAME_DOUBLE_EXTENSION` | high | filename | Executable extension behind a document extension |
| `FILENAME_INVISIBLE_CHAR` | medium | filename | Invisible character in the file name |
| `HTML_CREDENTIAL_FORM` | medium | html | HTML form asking for a password |
| `HTML_HTA` | high | html, hta | HTML Application (HTA) |
| `HTML_OBFUSCATED_SCRIPT` | medium | html, svg | Obfuscated script in HTML |
| `HTML_REDIRECT` | low | html | HTML redirects automatically |
| `HTML_SCRIPT` | medium | html | Script in HTML |
| `HTML_SMUGGLING` | high | html, svg | HTML smuggling pattern |
| `SVG_ANIMATE_SCRIPT_URL` | high | svg | SVG animation sets a script URL |
| `SVG_CSS_ACTIVE` | high | svg | Active CSS in SVG |
| `SVG_EMBEDDED_CONTENT` | high | svg | Frame or plugin element in SVG |
| `SVG_EVENT_HANDLER` | high | svg | Event handler attribute in SVG |
| `SVG_EXTERNAL_RESOURCE` | low | svg | SVG loads an external resource |
| `SVG_EXTERNAL_USE` | medium | svg | SVG <use> references an external document |
| `SVG_FOREIGN_OBJECT_HTML` | medium | svg | HTML inside SVG foreignObject |
| `SVG_SCRIPT` | high | svg | Script in SVG |
| `SVG_SCRIPT_URL` | high | svg | Script URL in SVG |
| `XML_ENTITY_DECLARATION` | medium | svg, xml, office parts | XML document declares entities |
| `XML_ENTITY_EXPANSION` | high | svg, xml, office parts | XML entity expansion bomb |
| `XML_EXTERNAL_DTD` | low | svg, xml | XML document loads an external DTD or stylesheet |
| `XML_EXTERNAL_ENTITY` | high | svg, xml, office parts | XML external entity (XXE) |
| `PDF_ADDITIONAL_ACTIONS` | medium | pdf | PDF additional actions |
| `PDF_EMBEDDED_FILE` | medium | pdf | File embedded in PDF |
| `PDF_ENCRYPTED` | low | pdf | Encrypted PDF (contents not inspected) |
| `PDF_HEADER_OFFSET` | medium | pdf | PDF header is not at the start of the file |
| `PDF_IMPORT_DATA` | medium | pdf | PDF imports data |
| `PDF_INCREMENTAL_UPDATE` | info | pdf | PDF has incremental updates |
| `PDF_JAVASCRIPT` | high | pdf | JavaScript in PDF |
| `PDF_JBIG2` | low | pdf | JBIG2 image stream |
| `PDF_LAUNCH` | critical | pdf | PDF launches an application |
| `PDF_MALFORMED` | low | pdf | Malformed PDF structure |
| `PDF_OBFUSCATED_NAME` | high | pdf | Hex-escaped PDF keyword |
| `PDF_OPEN_ACTION` | medium | pdf | PDF runs an action when opened |
| `PDF_REMOTE_GOTO` | medium | pdf | PDF opens another document |
| `PDF_RICH_MEDIA` | medium | pdf | Rich media in PDF |
| `PDF_SUBMIT_FORM` | low | pdf | PDF submits form data |
| `PDF_SUSPICIOUS_URI` | high | pdf | PDF link with a dangerous scheme |
| `PDF_XFA` | medium | pdf | XFA form in PDF |
| `OLE_EQUATION_EDITOR` | high | doc, docx, rtf | Equation Editor 3.0 object |
| `OLE_PACKAGE` | medium | doc, xls, ppt, docx, rtf | Embedded package (Ole10Native) |
| `OFFICE_VBA_MACROS` | medium | docm, xlsm, pptm, doc, xls | VBA macros |
| `VBA_AUTOEXEC` | high | docm, xlsm, pptm, doc, xls | Macro runs automatically |
| `VBA_SUSPICIOUS` | high | docm, xlsm, pptm, doc, xls | Suspicious VBA code |
| `OFFICE_DDE` | high | docx, xlsx, doc, rtf | Dynamic Data Exchange (DDE) |
| `OFFICE_ENCRYPTED` | medium | docx, xlsx, pptx, doc, xls, ppt | Encrypted Office document (not inspected) |
| `OFFICE_MACRO_CONTENT_TYPE` | medium | docx, xlsx, pptx | Macro project in a non-macro document |
| `OOXML_ACTIVEX` | medium | docx, xlsx, pptx | ActiveX controls |
| `OOXML_CUSTOM_XML` | info | docx, xlsx, pptx | Custom XML parts |
| `OOXML_EMBEDDED_OBJECT` | info | docx, xlsx, pptx | Embedded object |
| `OOXML_EXTERNAL_FRAME` | high | docx | External frame |
| `OOXML_EXTERNAL_OLE_LINK` | high | docx, xlsx, pptx | Linked OLE object from an external location |
| `OOXML_EXTERNAL_RELATIONSHIP` | low | docx, xlsx, pptx | External relationship |
| `OOXML_REMOTE_TEMPLATE` | high | docx, docm, dotx | Remote template |
| `OOXML_SUSPICIOUS_SCHEME` | high | docx, xlsx, pptx | Office relationship with a dangerous scheme |
| `RTF_OBFUSCATION` | medium | rtf | Obfuscated RTF |
| `RTF_OBJUPDATE` | medium | rtf | RTF object updates automatically |
| `RTF_OLE_OBJECT` | medium | rtf | OLE object in RTF |
| `RTF_REMOTE_TEMPLATE` | high | rtf | RTF remote template |
| `XLM_AUTO_OPEN` | high | xls, xlsx, xlsm | Excel Auto_Open name |
| `XLM_MACRO_SHEET` | high | xls, xlsx, xlsm, xlsb | Excel 4.0 (XLM) macro sheet |
| `ARCHIVE_UNSUPPORTED` | low | 7z, rar, bzip2, xz, zstd, cab, zip | Archive content not inspected |
| `ARCHIVE_BOMB` | high | zip, gzip, pdf, png | Decompression bomb |
| `ARCHIVE_CORRUPT` | low | zip, gzip, tar | Corrupt archive |
| `ARCHIVE_DUPLICATE_NAMES` | medium | zip, tar | Duplicate entry names in archive |
| `ARCHIVE_ENCRYPTED` | medium | zip | Encrypted archive entries (not inspected) |
| `ARCHIVE_HEADER_MISMATCH` | medium | zip | Archive headers disagree |
| `ARCHIVE_NESTED` | info | zip, gzip, tar | Nested archive |
| `ARCHIVE_OVERLAPPING_ENTRIES` | high | zip | Overlapping archive entries |
| `ARCHIVE_PATH_TRAVERSAL` | high | zip, tar | Archive entry escapes the extraction directory |
| `ARCHIVE_SYMLINK` | medium | zip, tar | Archive contains links |
| `SCRIPT_ENCODED` | high | js, vbs | Encoded Windows script |
| `SCRIPT_FILE` | medium | js, vbs, ps1, bat, hta, wsf, chm, ... | Script file |
| `LNK_FILE` | medium | lnk | Windows shortcut |
| `LNK_SUSPICIOUS_COMMAND` | high | lnk | Shortcut runs a suspicious command |
| `EXECUTABLE` | medium | pe, elf, macho, msi, jar, apk, dex, class | Executable file |
| `IMAGE_DIMENSIONS_BOMB` | high | png, jpeg, gif, bmp, webp | Image decompression bomb |
| `IMAGE_EMBEDDED_CODE` | high | png, jpeg, gif, bmp, webp | Script or markup inside an image |
| `IMAGE_MALFORMED` | low | png, jpeg, gif, bmp, webp | Malformed image structure |
| `TRAILING_DATA` | info | png, jpeg, gif, pdf, webp, zip | Data after the end of the file format |
| `DISK_IMAGE` | medium | iso, vhd, vhdx | Disk image |
| `BASE64_BLOB` | info | text, html, svg, xml, scripts | Large base64 block |
| `HIGH_ENTROPY` | info | text, html, svg, xml, scripts, unknown | High-entropy region in a text file |
<!-- rules-table:end -->

## What is not covered

- Signature-based malware detection or sandboxed detonation
- Packed / novel executables, shellcode as raw bytes
- Full VBA deobfuscation, PowerQuery / XL4 beyond sheet detection
- Password-encrypted contents (reported as encrypted, not inspected)
- Unpacking 7z, RAR, cab, xz, zstd, bzip2 (identified, `ARCHIVE_UNSUPPORTED`)
- Email (`.eml`) as a first-class container, ISO/VHD contents
- Guarantees against evasion — assume a motivated attacker can bypass this

## Limits and hardening

Defaults: 128 MiB input, depth 8, 10 000 entries, 256 MiB total decompressed,
64 MiB per item, compression ratio 100∶1 (entries &gt; 1 MiB), ~179 M image
pixels, 200 M operation budget, 500 findings.

Parsing is linear-time where it matters: own bounded DEFLATE (so output can be
capped without relying on platform `zlib`), markup tokenizer without a DOM and
without expanding custom entities, Maps instead of objects for hostile keys,
no catastrophic backtracking. Hitting a limit adds `SCAN_LIMIT` and records
the name in `limitsHit`.

## CLI

```
file-sentinel <file...> [--json] [--min-severity <s>] [--fail-on <s>]
                        [--ignore <ids>] [--severity <id=s>] [--name <filename>]
                        [--mime <type>] [--max-bytes <n>] [--list-rules]
```

## Install from GitHub

```bash
npm install github:gildor853/file-sentinel#v1.0.0
```

Pinned to the release tag. Not published to the npm registry.

## Disclaimer

**Use at your own risk.** This software is provided as is, without warranty of any kind. It is a static heuristic scanner, **not an antivirus**: missed threats, false positives and false negatives are expected. The author accepts no liability for reliance on its output. See the full legal text in [DISCLAIMER.md](./DISCLAIMER.md).

## Contributing

Single-author project. External pull requests are not accepted; please open an
issue for bugs or ideas. Security reports: see [SECURITY.md](./SECURITY.md).

## License

MIT © 2026 Gildor
