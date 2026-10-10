import { describe, expect, it } from "vitest";
import { formatReport, main, parseArgs, USAGE, type CliIo } from "../src/cli-main.js";
import { scanSync } from "../src/index.js";

function io(files: Record<string, Uint8Array>): CliIo & { out: string; err: string } {
  const state = { out: "", err: "" };
  const api: CliIo & { out: string; err: string } = {
    get out() {
      return state.out;
    },
    set out(v: string) {
      state.out = v;
    },
    get err() {
      return state.err;
    },
    set err(v: string) {
      state.err = v;
    },
    async readFile(path: string) {
      const b = files[path];
      if (!b) throw new Error(`ENOENT: ${path}`);
      return b;
    },
    async readStdin() {
      return files["-"] ?? new Uint8Array();
    },
    async stdout(t: string) {
      state.out += t;
    },
    stderr(t: string) {
      state.err += t;
    },
  };
  return api;
}

describe("parseArgs", () => {
  it("parses flags", () => {
    const p = parseArgs(["a.svg", "--json", "--fail-on", "high", "--min-severity", "medium", "--ignore", "SVG_SCRIPT"]);
    expect(p.files).toEqual(["a.svg"]);
    expect(p.json).toBe(true);
    expect(p.failOn).toBe("high");
    expect(p.minSeverity).toBe("medium");
    expect(p.ignore).toEqual(["SVG_SCRIPT"]);
  });

  it("rejects unknown options and rules", () => {
    expect(() => parseArgs(["--nope"])).toThrow(/Unknown option/);
    expect(() => parseArgs(["--ignore", "NOPE"])).toThrow(/Unknown rule/);
  });
});

describe("main", () => {
  it("exits 0 for clean, 1 for findings, 2 for errors", async () => {
    const clean = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>');
    const bad = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>');
    expect(await main(["c.svg"], io({ "c.svg": clean }))).toBe(0);
    expect(await main(["b.svg"], io({ "b.svg": bad }))).toBe(1);
    expect(await main(["missing"], io({}))).toBe(2);
    expect(await main(["--help"], io({}))).toBe(0);
    expect(await main(["--version"], io({}))).toBe(0);
    expect(await main(["--list-rules"], io({}))).toBe(0);
  });

  it("emits JSON", async () => {
    const bad = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>');
    const i = io({ "b.svg": bad });
    await main(["b.svg", "--json"], i);
    const data = JSON.parse(i.out) as { verdict: string }[];
    expect(data[0]?.verdict).toBe("malicious-indicators");
  });

  it("USAGE mentions install-relevant flags", () => {
    expect(USAGE).toContain("--fail-on");
    expect(USAGE).toContain("--json");
  });

  it("formatReport lists findings", () => {
    const r = scanSync(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>'), { filename: "a.svg" });
    expect(formatReport("a.svg", r)).toContain("SVG_SCRIPT");
  });
});
