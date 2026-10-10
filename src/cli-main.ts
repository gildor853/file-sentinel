/** Command-line front end (`file-sentinel <files...>`), independent of Node.js I/O for testing. */
import { excerpt } from "./bytes.js";
import { DEFAULT_LIMITS } from "./ctx.js";
import { RULES, SEVERITIES, severityRank } from "./rules.js";
import { scanSync } from "./scan.js";
import type { ScanReport, Severity } from "./types.js";

/** @internal I/O used by the CLI. */
export interface CliIo {
  /** Reads at most `max` bytes of a file. */
  readFile(path: string, max: number): Promise<Uint8Array>;
  readStdin(max: number): Promise<Uint8Array>;
  stdout(text: string): Promise<void>;
  stderr(text: string): void;
}

declare const __VERSION__: string | undefined;

export const USAGE = `Usage: file-sentinel <file...> [options]

Static heuristic risk scanner for untrusted files. It never executes, renders
or evaluates content. It is NOT an antivirus: no findings does not mean safe.
Use "-" to read stdin.

Options:
  --json                    print JSON (an array with one report per file)
  --min-severity <s>        hide findings below <s> (info, low, medium, high, critical)
  --fail-on <s>             exit 1 when a finding at or above <s> remains (default: low)
  --ignore <ids>            comma-separated rule ids to ignore
  --severity <id=s>         re-rate a rule, e.g. --severity OFFICE_VBA_MACROS=high (repeatable)
  --name <filename>         declared file name for stdin input
  --mime <type>             declared MIME type (applies to every input)
  --max-bytes <n>           inspect at most <n> bytes per file (default ${DEFAULT_LIMITS.maxBytes})
  --list-rules              print the rule catalogue and exit
  -h, --help                show this help
  -v, --version             show the version

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on,
2 usage, I/O or scan error.`;

class UsageError extends Error {}

interface Parsed {
  files: string[];
  json: boolean;
  minSeverity: Severity;
  failOn: Severity;
  ignore: string[];
  severity: Record<string, Severity>;
  name?: string;
  mime?: string;
  maxBytes: number;
  help: boolean;
  version: boolean;
  listRules: boolean;
}

function severity(value: string, flag: string): Severity {
  if (!(SEVERITIES as readonly string[]).includes(value)) throw new UsageError(`${flag} must be one of ${SEVERITIES.join(", ")}, got "${value}".`);
  return value as Severity;
}

function ruleId(id: string, flag: string): string {
  if (!Object.prototype.hasOwnProperty.call(RULES, id)) throw new UsageError(`Unknown rule id "${id}" in ${flag} (see --list-rules).`);
  return id;
}

/** @internal */
export function parseArgs(argv: readonly string[]): Parsed {
  const p: Parsed = { files: [], json: false, minSeverity: "info", failOn: "low", ignore: [], severity: {}, maxBytes: DEFAULT_LIMITS.maxBytes, help: false, version: false, listRules: false };
  let rest = false;
  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i] as string;
    if (rest || arg === "-" || !arg.startsWith("-")) {
      p.files.push(arg);
      continue;
    }
    if (arg === "--") {
      rest = true;
      continue;
    }
    let value: string | undefined;
    const eq = arg.indexOf("=");
    if (arg.startsWith("--") && eq > 0) {
      value = arg.slice(eq + 1);
      arg = arg.slice(0, eq);
    }
    const need = () => {
      if (value !== undefined) return value;
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`${arg} needs a value.`);
      return v;
    };
    switch (arg) {
      case "--json":
        p.json = true;
        break;
      case "--min-severity":
        p.minSeverity = severity(need(), arg);
        break;
      case "--fail-on":
        p.failOn = severity(need(), arg);
        break;
      case "--ignore":
        for (const id of need().split(",").map((s) => s.trim()).filter(Boolean)) p.ignore.push(ruleId(id, arg));
        break;
      case "--severity": {
        const v = need();
        const k = v.indexOf("=");
        if (k <= 0) throw new UsageError(`--severity expects RULE_ID=severity, got "${v}".`);
        p.severity[ruleId(v.slice(0, k), arg)] = severity(v.slice(k + 1), arg);
        break;
      }
      case "--name":
        p.name = need();
        break;
      case "--mime":
        p.mime = need();
        break;
      case "--max-bytes": {
        const v = need();
        const n = Number(v);
        if (!/^\d{1,16}$/.test(v) || !Number.isSafeInteger(n) || n <= 0) throw new UsageError(`--max-bytes must be a positive integer, got "${v}".`);
        p.maxBytes = n;
        break;
      }
      case "--list-rules":
        p.listRules = true;
        break;
      case "-h":
      case "--help":
        p.help = true;
        break;
      case "-v":
      case "--version":
        p.version = true;
        break;
      default:
        throw new UsageError(`Unknown option "${arg}".`);
    }
  }
  return p;
}

const LABEL: Record<Severity, string> = { info: "INFO", low: "LOW", medium: "MEDIUM", high: "HIGH", critical: "CRITICAL" };

/** @internal Human-readable report. */
export function formatReport(file: string, r: ScanReport): string {
  const lines = [`${excerpt(file, 300)}: ${r.verdict} (${r.detectedType.format}${r.typeMismatch ? ", type mismatch" : ""}, ${r.findings.length} finding${r.findings.length === 1 ? "" : "s"})`];
  const sorted = [...r.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  for (const f of sorted) {
    const where = [...f.location.path, f.location.element].filter((x) => x !== undefined && x !== "").map((x) => excerpt(String(x), 120)).join(" > ");
    lines.push(`  ${LABEL[f.severity].padEnd(8)} ${f.id}  ${f.title}${where ? `  [${where}]` : ""}`);
    if (f.evidence) lines.push(`           ${f.evidence}`);
  }
  if (r.truncated) lines.push(`  note: not everything was inspected (${r.limitsHit.join(", ") || "limits"})`);
  return `${lines.join("\n")}\n`;
}

function listRules(): string {
  const ids = Object.keys(RULES);
  const w = Math.max(...ids.map((i) => i.length));
  return `${ids.map((id) => `${id.padEnd(w)}  ${(RULES[id]?.severity ?? "").padEnd(8)}  ${RULES[id]?.title ?? ""}`).join("\n")}\n`;
}

/** @internal Runs the CLI; resolves to the exit code. */
export async function main(argv: readonly string[], io: CliIo): Promise<number> {
  let p: Parsed;
  try {
    p = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      io.stderr(`file-sentinel: ${e.message}\nRun "file-sentinel --help" for usage.\n`);
      return 2;
    }
    throw e;
  }
  if (p.help) {
    await io.stdout(`${USAGE}\n`);
    return 0;
  }
  if (p.version) {
    await io.stdout(`${typeof __VERSION__ === "string" ? __VERSION__ : "0.0.0-dev"}\n`);
    return 0;
  }
  if (p.listRules) {
    await io.stdout(listRules());
    return 0;
  }
  if (p.files.length === 0) {
    io.stderr(`file-sentinel: no input files.\n${USAGE}\n`);
    return 2;
  }
  const failRank = severityRank(p.failOn);
  let code = 0;
  const results: (ScanReport & { file: string })[] = [];
  const errors: { file: string; error: string }[] = [];
  for (const file of p.files) {
    let bytes: Uint8Array;
    try {
      // read one byte more than inspected so oversized input is reported as truncated
      bytes = file === "-" ? await io.readStdin(p.maxBytes + 1) : await io.readFile(file, p.maxBytes + 1);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      errors.push({ file, error: msg });
      io.stderr(`file-sentinel: cannot read ${excerpt(file, 300)}: ${excerpt(msg, 300)}\n`);
      code = 2;
      continue;
    }
    const name = file === "-" ? p.name : file;
    const report = scanSync(bytes, {
      ...(name !== undefined ? { filename: name } : {}),
      ...(p.mime !== undefined ? { declaredMime: p.mime } : {}),
      limits: { maxBytes: p.maxBytes },
      policy: { ignore: p.ignore, minSeverity: p.minSeverity, severity: p.severity },
    });
    if (report.verdict === "error") code = 2;
    else if (code !== 2 && report.findings.some((f) => severityRank(f.severity) >= failRank)) code = 1;
    if (p.json) results.push({ file, ...report });
    else await io.stdout(formatReport(file, report));
  }
  if (p.json) await io.stdout(`${JSON.stringify(errors.length ? [...results, ...errors] : results, null, 2)}\n`);
  return code;
}
