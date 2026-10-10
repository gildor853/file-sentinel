/** Severity of a finding, from purely informational to a strong malicious indicator. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * Overall result.
 * - `clean`: no finding above `info` (none of the checked constructs was found; this is not a statement that the file is safe).
 * - `suspicious`: at least one `low` or `medium` finding.
 * - `malicious-indicators`: at least one `high` or `critical` finding.
 * - `error`: the scanner itself failed on this input (see the `SCAN_ERROR` finding); treat the file as not scanned.
 */
export type Verdict = "clean" | "suspicious" | "malicious-indicators" | "error";

/** Where a finding was made. */
export interface FindingLocation {
  /** Path through containers, outermost first, e.g. `["word/vbaProject.bin", "VBA/Module1"]`. Empty for the top-level file. */
  path: string[];
  /** Byte offset inside the innermost item, when known. */
  offset?: number;
  /** Element, object, record or field, e.g. `<script>`, `obj 12 0`, `BOUNDSHEET "Macro1"`. */
  element?: string;
}

/** One detected construct. */
export interface Finding {
  /** Stable rule id such as `SVG_SCRIPT` (see `RULES`). */
  id: string;
  severity: Severity;
  title: string;
  description: string;
  location: FindingLocation;
  /** Short, sanitised excerpt (control characters escaped, at most 200 characters). Never the raw content. */
  evidence?: string;
  /** Documentation: OWASP, CWE, MITRE ATT&CK, vendor and format specifications. */
  references: readonly string[];
}

/** Content-based type identification. */
export interface DetectedType {
  /** Short format id, e.g. `pdf`, `docx`, `docm`, `zip`, `png`, `pe`, `unknown`. */
  format: string;
  /** Canonical MIME type of the detected format. */
  mime: string;
  /** `high`: magic bytes and structure agree; `medium`: magic bytes or strong markers only; `low`: guess (text, unknown). */
  confidence: "high" | "medium" | "low";
}

export interface ScanStats {
  /** Size of the input in bytes. */
  bytes: number;
  /** Number of items scanned, including the file itself and every embedded file, stream and archive entry. */
  itemsScanned: number;
  /** Deepest container nesting reached (0 = top-level file only). */
  maxDepth: number;
  /** Bytes produced by decompression (ZIP, gzip, PDF streams, VBA, PNG text). */
  decompressedBytes: number;
  /** Work units consumed (the `maxOperations` budget). */
  operations: number;
  /** Wall-clock time in milliseconds. */
  durationMs: number;
}

export interface ScanReport {
  verdict: Verdict;
  detectedType: DetectedType;
  /** True when the declared filename extension or MIME type does not match the content. */
  typeMismatch: boolean;
  findings: Finding[];
  stats: ScanStats;
  /** True when part of the input was not inspected (input larger than `maxBytes`, or a limit stopped the scan). */
  truncated: boolean;
  /** Names of the limits that were reached, e.g. `["maxDecompressedBytes"]`. */
  limitsHit: string[];
}

/** Resource limits. All sizes are in bytes. */
export interface ScanLimits {
  /** Input bytes inspected; the rest is ignored and `truncated` is set. Default 128 MiB. */
  maxBytes: number;
  /** Container nesting depth (archive in archive, file embedded in a PDF, ...). Default 8. */
  maxDepth: number;
  /** Entries per archive / objects per container. Default 10 000. */
  maxEntries: number;
  /** Total decompressed output across the whole scan. Default 256 MiB. */
  maxDecompressedBytes: number;
  /** Decompressed size of a single item. Default 64 MiB. */
  maxItemBytes: number;
  /** Compression ratio above which a large entry (> 1 MiB uncompressed) is reported as a bomb. Default 100. */
  maxCompressionRatio: number;
  /** Width × height above which an image is reported as a decompression bomb. Default 178 956 970 (Pillow's error threshold). */
  maxImagePixels: number;
  /** Work budget (roughly bytes and records processed). Bounds the time spent on any input. Default 200 000 000. */
  maxOperations: number;
  /** Findings kept; further findings are counted in `limitsHit`. Default 500. */
  maxFindings: number;
}

/** Report filtering applied after scanning. */
export interface ScanPolicy {
  /** Rule ids to drop from the report. */
  ignore?: readonly string[];
  /** Drop findings below this severity (after `severity` overrides). Default `info` (keep everything). */
  minSeverity?: Severity;
  /** Re-rate rules ("treat as"), e.g. `{ OFFICE_VBA_MACROS: "high" }`. */
  severity?: Readonly<Record<string, Severity>>;
}

export interface ScanOptions {
  /** Declared file name (from the upload or the path); used for extension and name-spoofing checks. */
  filename?: string;
  /** Declared MIME type (e.g. the upload's Content-Type). */
  declaredMime?: string;
  limits?: Partial<ScanLimits>;
  policy?: ScanPolicy;
}

/** Accepted inputs: bytes in any common form. `scan()` also accepts a `Blob`. */
export type ScanInput = Uint8Array | ArrayBuffer | ArrayBufferView;

/** A rule in the catalogue. */
export interface RuleInfo {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  /** Formats the rule applies to (documentation only). */
  scope: string;
  references: readonly string[];
}
