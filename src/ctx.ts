import { RULES } from "./rules.js";
import type { Finding, ScanLimits, Severity } from "./types.js";

/** @internal Thrown when a resource limit is reached; caught by the scanner, never escapes the API. */
export class LimitReached extends Error {
  readonly limit: keyof ScanLimits;
  constructor(limit: keyof ScanLimits) {
    super(`limit ${limit} reached`);
    this.limit = limit;
  }
}

/** Default limits. */
export const DEFAULT_LIMITS: Readonly<ScanLimits> = Object.freeze({
  maxBytes: 128 * 1024 * 1024,
  maxDepth: 8,
  maxEntries: 10_000,
  maxDecompressedBytes: 256 * 1024 * 1024,
  maxItemBytes: 64 * 1024 * 1024,
  maxCompressionRatio: 100,
  maxImagePixels: 178_956_970,
  maxOperations: 200_000_000,
  maxFindings: 500,
});

/** Same rule at the same place is reported at most this many times; later hits are counted. */
const PER_RULE_AND_ITEM = 5;

/** @internal Scan-wide state: limits, budget counters and collected findings. */
export class Ctx {
  readonly limits: ScanLimits;
  ops = 0;
  decompressed = 0;
  items = 0;
  maxDepth = 0;
  truncated = false;
  /** An internal error occurred while scanning some item. */
  errored = false;
  readonly findings: Finding[] = [];
  readonly limitsHit = new Set<string>();
  readonly #exact = new Set<string>();
  readonly #perItem = new Map<string, { first: Finding; distinct: number; suppressed: number }>();

  constructor(limits: ScanLimits) {
    this.limits = limits;
  }

  /** Charges `n` work units; throws LimitReached when the budget is exhausted. */
  step(n = 1): void {
    this.ops += n;
    if (this.ops > this.limits.maxOperations) throw new LimitReached("maxOperations");
  }

  /** Accounts decompressed output; throws when the scan-wide total is exceeded. */
  inflated(n: number): void {
    this.decompressed += n;
    this.step(n >>> 4);
    if (this.decompressed > this.limits.maxDecompressedBytes) throw new LimitReached("maxDecompressedBytes");
  }

  /** Remaining scan-wide decompression allowance, capped by the per-item limit. */
  allowance(): number {
    return Math.max(0, Math.min(this.limits.maxItemBytes, this.limits.maxDecompressedBytes - this.decompressed));
  }

  hit(limit: string): void {
    this.limitsHit.add(limit);
  }

  /**
   * Records a finding for rule `id`. `detail` is appended to the rule description.
   * Exact duplicates (same rule, item and element) are dropped; at most five
   * findings per rule and item are kept, further ones are counted.
   */
  add(id: string, path: readonly string[], opts: { offset?: number | undefined; element?: string | undefined; evidence?: string | undefined; detail?: string | undefined; severity?: Severity | undefined } = {}): void {
    const rule = RULES[id];
    if (rule === undefined) throw new Error(`unknown rule ${id}`);
    const itemKey = JSON.stringify([id, path]);
    const exactKey = JSON.stringify([id, path, opts.element ?? ""]);
    if (this.#exact.has(exactKey)) return;
    const group = this.#perItem.get(itemKey);
    if (group && group.distinct >= PER_RULE_AND_ITEM) {
      group.suppressed++;
      return;
    }
    if (this.findings.length >= this.limits.maxFindings) {
      this.hit("maxFindings");
      return;
    }
    const finding: Finding = {
      id,
      severity: opts.severity ?? rule.severity,
      title: rule.title,
      description: opts.detail ? `${rule.description} ${opts.detail}` : rule.description,
      location: { path: [...path] },
      references: rule.references,
    };
    if (opts.offset !== undefined) finding.location.offset = opts.offset;
    if (opts.element !== undefined) finding.location.element = opts.element;
    if (opts.evidence !== undefined && opts.evidence !== "") finding.evidence = opts.evidence;
    this.findings.push(finding);
    this.#exact.add(exactKey);
    if (group) group.distinct++;
    else this.#perItem.set(itemKey, { first: finding, distinct: 1, suppressed: 0 });
  }

  /** True when a finding with this rule id was recorded anywhere. */
  has(id: string): boolean {
    return this.findings.some((f) => f.id === id);
  }

  /** Notes suppressed repeats on the first finding of each group. */
  finish(): void {
    for (const { first, suppressed } of this.#perItem.values()) {
      if (suppressed > 0) first.description += ` (${suppressed} more occurrence${suppressed === 1 ? "" : "s"} in this item not listed.)`;
    }
  }
}
