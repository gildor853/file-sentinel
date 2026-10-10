/** Orchestration: input validation, per-item dispatch, limits, policy and verdict. */
import { scanGzip, scanOpaqueArchive, scanTar, scanZip } from "./archive.js";
import { excerpt } from "./bytes.js";
import { Ctx, DEFAULT_LIMITS, LimitReached } from "./ctx.js";
import type { Env, Handler, Item } from "./env.js";
import { fail, show } from "./errors.js";
import { scanExecutable, scriptByName } from "./exec.js";
import { checkFilename } from "./filename.js";
import { detectedType, formatInfo } from "./formats.js";
import { contentStats, isEicar, mismatchChecks, polyglotChecks } from "./generic.js";
import { scanImage } from "./images.js";
import { scanLnk } from "./lnk.js";
import { scanHtml, scanSvg, scanXml } from "./markup.js";
import { scanCfb } from "./office-cfb.js";
import { scanPdf } from "./pdf.js";
import { scanRtf } from "./rtf.js";
import { RULES, SEVERITIES, severityRank } from "./rules.js";
import { sniff } from "./sniff.js";
import type { DetectedType, Finding, ScanInput, ScanLimits, ScanOptions, ScanPolicy, ScanReport, Severity, Verdict } from "./types.js";

const HANDLERS: Readonly<Record<string, Handler>> = {
  pdf: scanPdf,
  zip: scanZip,
  cfb: scanCfb,
  rtf: scanRtf,
  svg: scanSvg,
  html: scanHtml,
  xml: scanXml,
  png: scanImage,
  jpeg: scanImage,
  gif: scanImage,
  webp: scanImage,
  bmp: scanImage,
  tiff: scanImage,
  ico: scanImage,
  gzip: scanGzip,
  tar: scanTar,
  "7z": scanOpaqueArchive,
  rar: scanOpaqueArchive,
  bzip2: scanOpaqueArchive,
  xz: scanOpaqueArchive,
  zstd: scanOpaqueArchive,
  cab: scanOpaqueArchive,
  lnk: scanLnk,
  pe: scanExecutable,
  elf: scanExecutable,
  macho: scanExecutable,
  class: scanExecutable,
  dex: scanExecutable,
  iso: scanExecutable,
  vhd: scanExecutable,
  chm: scanExecutable,
  "script-encoded": scanExecutable,
};

/** Formats that a handler may produce by refining a container and that are executables in their own right. */
const REFINED_EXECUTABLES = new Set(["msi", "jar", "apk"]);

const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

function scanItem(ctx: Ctx, item: Item, onType?: (t: DetectedType) => void): DetectedType {
  ctx.items++;
  ctx.maxDepth = Math.max(ctx.maxDepth, item.depth);
  ctx.step(16);
  const env: Env = {
    ctx,
    item,
    child(bytes, segment, name) {
      const path = [...item.path, segment];
      if (item.depth + 1 > ctx.limits.maxDepth) {
        ctx.hit("maxDepth");
        ctx.add("SCAN_LIMIT", path, { detail: `Content nested deeper than maxDepth (${ctx.limits.maxDepth}) was not inspected.` });
        return undefined;
      }
      if (bytes.length > ctx.limits.maxItemBytes) {
        ctx.hit("maxItemBytes");
        ctx.add("SCAN_LIMIT", path, { detail: `Embedded content larger than maxItemBytes was only partly inspected.` });
        bytes = bytes.subarray(0, ctx.limits.maxItemBytes);
      }
      try {
        return scanItem(ctx, { bytes, path, name, declaredMime: undefined, depth: item.depth + 1 });
      } catch (e) {
        if (e instanceof LimitReached) throw e;
        ctx.add("SCAN_ERROR", path, { evidence: excerpt(e instanceof Error ? e.message : String(e)) });
        ctx.errored = true;
        return undefined;
      }
    },
    add(id, opts) {
      ctx.add(id, item.path, opts);
    },
    addAt(segments, id, opts) {
      ctx.add(id, [...item.path, ...segments], opts);
    },
  };
  if (item.name) checkFilename(env, item.name);
  const sn = sniff(item.bytes);
  let detected = detectedType(sn.format, sn.confidence);
  onType?.(detected);
  if (isEicar(item.bytes)) {
    env.add("EICAR_TEST_FILE", { evidence: "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" });
    return detected;
  }
  const handler = HANDLERS[detected.format];
  if (handler) {
    detected = handler(env, detected) ?? detected;
    onType?.(detected);
  }
  if (REFINED_EXECUTABLES.has(detected.format)) env.add("EXECUTABLE", { evidence: formatInfo(detected.format).label });
  scriptByName(env, detected);
  mismatchChecks(env, detected);
  polyglotChecks(env, detected);
  contentStats(env, detected);
  return detected;
}

function toBytes(input: unknown): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof SharedArrayBuffer !== "undefined" && input instanceof SharedArrayBuffer) return new Uint8Array(input);
  return fail("InvalidInput", `Expected a Uint8Array, Buffer, ArrayBuffer or ArrayBufferView, got ${show(input)}.`);
}

const LIMIT_KEYS = Object.keys(DEFAULT_LIMITS) as (keyof ScanLimits)[];

function resolveLimits(limits: unknown): ScanLimits {
  if (limits === undefined) return { ...DEFAULT_LIMITS };
  if (limits === null || typeof limits !== "object" || Array.isArray(limits)) return fail("InvalidOption", `options.limits must be an object, got ${show(limits)}.`);
  const out: ScanLimits = { ...DEFAULT_LIMITS };
  for (const [k, v] of Object.entries(limits)) {
    if (!LIMIT_KEYS.includes(k as keyof ScanLimits)) fail("InvalidOption", `Unknown limit "${k}". Known limits: ${LIMIT_KEYS.join(", ")}.`);
    if (v === undefined) continue;
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0 || !Number.isInteger(v)) fail("InvalidOption", `options.limits.${k} must be a positive integer, got ${show(v)}.`);
    out[k as keyof ScanLimits] = v;
  }
  return out;
}

function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && (SEVERITIES as readonly string[]).includes(v);
}

function checkPolicy(policy: unknown): ScanPolicy {
  if (policy === undefined) return {};
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)) return fail("InvalidOption", `options.policy must be an object, got ${show(policy)}.`);
  const p = policy as Record<string, unknown>;
  for (const k of Object.keys(p)) if (!["ignore", "minSeverity", "severity"].includes(k)) fail("InvalidOption", `Unknown policy option "${k}".`);
  if (p.ignore !== undefined) {
    if (!Array.isArray(p.ignore)) fail("InvalidOption", `options.policy.ignore must be an array of rule ids, got ${show(p.ignore)}.`);
    for (const id of p.ignore) if (typeof id !== "string" || !own(RULES, id)) fail("InvalidOption", `Unknown rule id ${show(id)} in options.policy.ignore.`);
  }
  if (p.minSeverity !== undefined && !isSeverity(p.minSeverity)) fail("InvalidOption", `options.policy.minSeverity must be one of ${SEVERITIES.join(", ")}, got ${show(p.minSeverity)}.`);
  if (p.severity !== undefined) {
    if (p.severity === null || typeof p.severity !== "object" || Array.isArray(p.severity)) fail("InvalidOption", `options.policy.severity must be an object, got ${show(p.severity)}.`);
    for (const [id, s] of Object.entries(p.severity)) {
      if (!own(RULES, id)) fail("InvalidOption", `Unknown rule id ${show(id)} in options.policy.severity.`);
      if (!isSeverity(s)) fail("InvalidOption", `options.policy.severity.${id} must be one of ${SEVERITIES.join(", ")}, got ${show(s)}.`);
    }
  }
  return p as ScanPolicy;
}

function checkOptions(options: unknown): { filename?: string; declaredMime?: string; limits: ScanLimits; policy: ScanPolicy } {
  if (options === undefined) return { limits: { ...DEFAULT_LIMITS }, policy: {} };
  if (options === null || typeof options !== "object" || Array.isArray(options)) return fail("InvalidOption", `options must be an object, got ${show(options)}.`);
  const o = options as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!["filename", "declaredMime", "limits", "policy"].includes(k)) fail("InvalidOption", `Unknown option "${k}".`);
  if (o.filename !== undefined && typeof o.filename !== "string") fail("InvalidOption", `options.filename must be a string, got ${show(o.filename)}.`);
  if (o.declaredMime !== undefined && typeof o.declaredMime !== "string") fail("InvalidOption", `options.declaredMime must be a string, got ${show(o.declaredMime)}.`);
  const out: { filename?: string; declaredMime?: string; limits: ScanLimits; policy: ScanPolicy } = { limits: resolveLimits(o.limits), policy: checkPolicy(o.policy) };
  if (typeof o.filename === "string" && o.filename !== "") out.filename = o.filename;
  if (typeof o.declaredMime === "string" && o.declaredMime !== "") out.declaredMime = o.declaredMime;
  return out;
}

/** @internal Applies severity overrides, ignore list and minimum severity. */
export function applyPolicy(findings: Finding[], policy: ScanPolicy): Finding[] {
  const ignore = new Set(policy.ignore ?? []);
  const min = severityRank(policy.minSeverity ?? "info");
  const out: Finding[] = [];
  for (const f of findings) {
    const s = policy.severity && own(policy.severity, f.id) ? (policy.severity[f.id] as Severity) : f.severity;
    if (ignore.has(f.id) || severityRank(s) < min) continue;
    out.push(s === f.severity ? f : { ...f, severity: s });
  }
  return out;
}

/** @internal Verdict from the (filtered) findings. */
export function verdictOf(findings: readonly Finding[], error: boolean): Verdict {
  let top = -1;
  for (const f of findings) top = Math.max(top, severityRank(f.severity));
  if (top >= severityRank("high")) return "malicious-indicators";
  if (error) return "error";
  if (top >= severityRank("low")) return "suspicious";
  return "clean";
}

const perf = (globalThis as { performance?: { now(): number } }).performance;
const now = (): number => (perf ? perf.now() : Date.now());
const MISMATCH_IDS = new Set(["TYPE_MISMATCH", "EXECUTABLE_DISGUISED", "ACTIVE_CONTENT_DISGUISED"]);

/**
 * Scans a file synchronously. Never executes, renders or evaluates content.
 * Throws {@link FileSentinelError} only for invalid arguments; hostile or broken
 * input yields a report (verdict `error` with a `SCAN_ERROR` finding at worst).
 */
export function scanSync(input: ScanInput, options?: ScanOptions): ScanReport {
  const bytesIn = toBytes(input);
  const opts = checkOptions(options);
  const started = now();
  const ctx = new Ctx(opts.limits);
  let bytes = bytesIn;
  if (bytes.length > opts.limits.maxBytes) {
    bytes = bytes.subarray(0, opts.limits.maxBytes);
    ctx.truncated = true;
    ctx.hit("maxBytes");
    ctx.add("SCAN_LIMIT", [], { detail: `Only the first ${opts.limits.maxBytes} of ${bytesIn.length} bytes were inspected (maxBytes).` });
  }
  let detected = detectedType("unknown", "low");
  try {
    scanItem(ctx, { bytes, path: [], name: opts.filename, declaredMime: opts.declaredMime, depth: 0 }, (t) => {
      detected = t;
    });
  } catch (e) {
    if (e instanceof LimitReached) {
      ctx.truncated = true;
      ctx.hit(e.limit);
      ctx.add("SCAN_LIMIT", [], { detail: `The scan stopped early because ${e.limit} was reached; findings are incomplete.` });
    } else {
      ctx.errored = true;
      ctx.add("SCAN_ERROR", [], { evidence: excerpt(e instanceof Error ? e.message : String(e)) });
    }
  }
  const error = ctx.errored;
  ctx.finish();
  if (ctx.limitsHit.size > 0 && !ctx.limitsHit.has("maxFindings")) ctx.truncated = true;
  const findings = applyPolicy(ctx.findings, opts.policy);
  return {
    verdict: verdictOf(findings, error),
    detectedType: detected,
    typeMismatch: ctx.findings.some((f) => MISMATCH_IDS.has(f.id) && f.location.path.length === 0),
    findings,
    stats: {
      bytes: bytesIn.length,
      itemsScanned: ctx.items,
      maxDepth: ctx.maxDepth,
      decompressedBytes: ctx.decompressed,
      operations: ctx.ops,
      durationMs: Math.round((now() - started) * 1000) / 1000,
    },
    truncated: ctx.truncated,
    limitsHit: [...ctx.limitsHit].sort(),
  };
}

/** Blob-like inputs accepted by {@link scan}. */
interface BlobLike {
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * Scans a file. Accepts the same inputs as {@link scanSync} plus a `Blob`/`File`.
 * The work itself is synchronous; the promise exists so callers can pass a Blob.
 */
export async function scan(input: ScanInput | BlobLike, options?: ScanOptions): Promise<ScanReport> {
  if (typeof input === "object" && input !== null && !ArrayBuffer.isView(input) && !(input instanceof ArrayBuffer) && typeof (input as BlobLike).arrayBuffer === "function") {
    checkOptions(options);
    return scanSync(new Uint8Array(await (input as BlobLike).arrayBuffer()), options);
  }
  return scanSync(input as ScanInput, options);
}

