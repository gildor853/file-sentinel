/** Data appended after a format's end marker. */
import { excerptBytes } from "./bytes.js";
import type { Env } from "./env.js";
import { formatInfo } from "./formats.js";

const UNREMARKABLE = new Set(["unknown", "text", "empty"]);

/** @internal Reports TRAILING_DATA, scans the appended bytes and reports POLYGLOT when they form a recognizable format. */
export function checkTrailing(env: Env, b: Uint8Array, offset: number): void {
  const tail = b.subarray(offset);
  if (tail.length === 0) return;
  // padding (NUL / 0xFF runs) is common and uninteresting
  let padding = true;
  for (let i = 0; i < tail.length && i < 65536; i++) if (tail[i] !== 0 && tail[i] !== 0xff) padding = false;
  if (padding && tail.length <= 65536) return;
  env.add("TRAILING_DATA", { offset, evidence: `${tail.length} bytes: ${excerptBytes(tail, 0, 48)}` });
  const child = env.child(tail, `trailing data@${offset}`);
  // images appended to images (multi-picture JPEG, depth maps) are normal
  if (child && !UNREMARKABLE.has(child.format) && formatInfo(child.format).kind !== "image") env.add("POLYGLOT", { offset, element: "trailing data", evidence: `${child.format} data appended at offset ${offset}` });
}
