// Executes every ```ts code block of README.md against the built package
// (run `npm run build` first) and checks documented results.
//
// - A block preceded by `<!-- readme-check: skip -->` (optionally with a reason,
//   `<!-- readme-check: skip (needs qrcode) -->`) is only syntax-checked
//   (e.g. examples that need a third-party package).
// - An expression statement followed by a comment that starts with a literal,
//   object or array, e.g. `parseX("a"); // "A"` or `f(); // { ok: true, ... }`,
//   is asserted: primitives must be equal, objects/arrays are compared as a
//   deep subset (`...` in the comment is allowed and ignored). Inside an
//   expected string, `...` stands for any characters ("addr1...xyz").
// - If scripts/readme-setup.mjs exists it is preloaded (e.g. to stub fetch).
//
// No dependencies beyond the `typescript` devDependency. Generated files go to
// .readme-check/ inside the repository so that the package name resolves to
// ./dist through its own "exports" map.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readme = readFileSync(join(root, "README.md"), "utf8");
const outDir = join(root, ".readme-check");
const setup = join(root, "scripts", "readme-setup.mjs");

const HELPER = `
function __subset(actual, expected, path) {
  if (typeof expected === "string" && expected.includes("...")) {
    const parts = expected.split("...");
    let ok = typeof actual === "string" && actual.startsWith(parts[0]) && actual.endsWith(parts[parts.length - 1]);
    let at = parts[0].length;
    for (const part of parts.slice(1, -1)) {
      if (!ok) break;
      const found = actual.indexOf(part, at);
      ok = found >= 0;
      at = found + part.length;
    }
    ok = ok && at <= actual.length - parts[parts.length - 1].length;
    if (!ok) {
      throw new Error(path + ": expected " + JSON.stringify(expected) + ", got " + JSON.stringify(actual));
    }
    return;
  }
  if (expected === null || typeof expected !== "object") {
    if (!Object.is(actual, expected)) {
      throw new Error(path + ": expected " + JSON.stringify(expected) + ", got " + JSON.stringify(actual));
    }
    return;
  }
  if (actual === null || typeof actual !== "object") {
    throw new Error(path + ": expected an object, got " + JSON.stringify(actual));
  }
  if (Array.isArray(expected) && (!Array.isArray(actual) || actual.length !== expected.length)) {
    throw new Error(path + ": expected an array of length " + expected.length + ", got " + JSON.stringify(actual));
  }
  for (const key of Object.keys(expected)) __subset(actual[key], expected[key], path + "." + key);
}
function __check(actual, expected, where) {
  try { __subset(actual, expected, "value"); }
  catch (err) { throw new Error("README assertion failed at " + where + ": " + err.message); }
  globalThis.__readmeAssertions = (globalThis.__readmeAssertions ?? 0) + 1;
}
`;

function syntaxErrors(code, fileName) {
  const out = ts.transpileModule(code, {
    fileName,
    reportDiagnostics: true,
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return { js: out.outputText, diagnostics: out.diagnostics ?? [] };
}

/** Parses the literal/object/array at the start of a comment, or returns undefined. */
function expectedFrom(text, wholeOnly) {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, ts.LanguageVariant.Standard, text);
  const first = scanner.scan();
  let end;
  if (first === ts.SyntaxKind.OpenBraceToken || first === ts.SyntaxKind.OpenBracketToken) {
    let depth = 0;
    for (let tok = first; tok !== ts.SyntaxKind.EndOfFileToken; tok = scanner.scan()) {
      if (tok === ts.SyntaxKind.OpenBraceToken || tok === ts.SyntaxKind.OpenBracketToken) depth++;
      if (tok === ts.SyntaxKind.CloseBraceToken || tok === ts.SyntaxKind.CloseBracketToken) depth--;
      if (depth === 0) { end = scanner.getTextPos(); break; }
    }
    if (end === undefined) return undefined;
  } else if (
    first === ts.SyntaxKind.StringLiteral ||
    first === ts.SyntaxKind.NumericLiteral ||
    first === ts.SyntaxKind.TrueKeyword ||
    first === ts.SyntaxKind.FalseKeyword ||
    first === ts.SyntaxKind.NullKeyword ||
    (first === ts.SyntaxKind.Identifier && scanner.getTokenText() === "undefined")
  ) {
    end = scanner.getTextPos();
  } else {
    return undefined;
  }
  const rest = text.slice(end).trim();
  if (wholeOnly && rest !== "") return undefined;
  if (!wholeOnly && rest !== "" && !/^(\(|\s)/.test(text.slice(end))) return undefined;
  const literal = text.slice(0, end).replace(/,?\s*\.\.\.\s*(?=[}\]])/g, " ").replace(/\.\.\.\s*,/g, "");
  const { js, diagnostics } = syntaxErrors(`(${literal});`, "expected.ts");
  if (diagnostics.length > 0) return undefined;
  return js.trim().replace(/;$/, "");
}

function commentText(code, range) {
  return code.slice(range.pos + 2, range.end).trim();
}

function instrument(code, blockLine) {
  const sf = ts.createSourceFile("block.ts", code, ts.ScriptTarget.Latest, true);
  const edits = [];
  for (const stmt of sf.statements) {
    if (!ts.isExpressionStatement(stmt)) continue;
    const endLine = sf.getLineAndCharacterOfPosition(stmt.end).line;
    const single = (r) => r.kind === ts.SyntaxKind.SingleLineCommentTrivia;
    const trailing = (ts.getTrailingCommentRanges(code, stmt.end) ?? []).filter(single);
    const ranges = (ts.getLeadingCommentRanges(code, stmt.end) ?? []).filter(single);
    let expected;
    if (trailing[0]) expected = expectedFrom(commentText(code, trailing[0]), false);
    if (expected === undefined) {
      const own = [];
      let line = endLine + 1;
      for (let i = 0; i < ranges.length; i++) {
        if (sf.getLineAndCharacterOfPosition(ranges[i].pos).line !== line) break;
        own.push(commentText(code, ranges[i]));
        line++;
      }
      if (own.length > 0) expected = expectedFrom(own.join(" "), true);
    }
    if (expected === undefined) continue;
    const where = `README.md:${blockLine + endLine + 1}`;
    const expr = stmt.expression.getText(sf);
    edits.push({
      start: stmt.getStart(sf),
      end: stmt.end,
      text: `__check((${expr}), ${expected}, ${JSON.stringify(where)});`,
    });
  }
  let out = code;
  for (const e of edits.sort((a, b) => b.start - a.start)) {
    out = out.slice(0, e.start) + e.text + out.slice(e.end);
  }
  return { code: out, assertions: edits.length };
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const fence = /^```([\w-]*)[^\n]*\n([\s\S]*?)^```[ \t]*$/gm;
let failures = 0;
let ran = 0;
let n = 0;
for (let m = fence.exec(readme); m !== null; m = fence.exec(readme)) {
  const lang = m[1];
  if (!["ts", "typescript", "js", "javascript"].includes(lang)) continue;
  n++;
  const blockLine = readme.slice(0, m.index).split("\n").length; // line of the opening fence
  const skip = /<!--\s*readme-check:\s*skip\b[^>]*-->\s*$/.test(readme.slice(0, m.index));
  const source = m[2];
  const label = `README.md:${blockLine}`;

  const syntax = syntaxErrors(source, "block.ts");
  if (syntax.diagnostics.length > 0) {
    failures++;
    for (const d of syntax.diagnostics) {
      console.error(`FAIL ${label}: ${ts.flattenDiagnosticMessageText(d.messageText, "\n")}`);
    }
    continue;
  }
  if (skip) {
    console.log(`skip ${label} (syntax only)`);
    continue;
  }

  const { code, assertions } = instrument(source, blockLine);
  const { js } = syntaxErrors(code, "block.ts");
  const file = join(outDir, `block-${n}.mjs`);
  writeFileSync(file, `${js}\n${HELPER}\nif ((globalThis.__readmeAssertions ?? 0) !== ${assertions}) throw new Error("assertion count mismatch");\n`);
  const args = existsSync(setup) ? ["--import", pathToFileURL(setup).href, file] : [file];
  const res = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8" });
  ran++;
  if (res.status !== 0) {
    failures++;
    console.error(`FAIL ${label}\n${res.stdout}${res.stderr}`);
  } else {
    console.log(`ok   ${label} (${assertions} assertion${assertions === 1 ? "" : "s"})`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} README block(s) failed.`);
  process.exit(1);
}
console.log(`\nREADME check passed: ${ran} block(s) executed.`);
