/** File-name spoofing checks. */
import { excerpt } from "./bytes.js";
import type { Env } from "./env.js";
import { DECOY_EXTS, EXECUTABLE_EXTS } from "./formats.js";

const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const INVISIBLE = /[\u00AD\u034F\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200D\u2060-\u2064\u3164\uFEFF\uFFA0]/;

/** @internal Checks a (base) file name for display-spoofing tricks. */
export function checkFilename(env: Env, name: string): void {
  const base = name.slice(Math.max(name.lastIndexOf("/"), name.lastIndexOf("\\")) + 1);
  if (BIDI.test(base)) env.add("FILENAME_BIDI_CONTROL", { element: "filename", evidence: excerpt(base) });
  if (INVISIBLE.test(base)) env.add("FILENAME_INVISIBLE_CHAR", { element: "filename", evidence: excerpt(base) });
  const clean = base.replace(new RegExp(`${BIDI.source}|${INVISIBLE.source}`, "g"), "").toLowerCase();
  const parts = clean.split(".");
  if (parts.length < 3) return;
  const last = (parts[parts.length - 1] as string).trim();
  const prev = (parts[parts.length - 2] as string).trim();
  const padded = /\s{5,}$/.test(parts[parts.length - 2] as string);
  if (EXECUTABLE_EXTS.has(last) && (DECOY_EXTS.has(prev) || padded)) env.add("FILENAME_DOUBLE_EXTENSION", { element: "filename", evidence: excerpt(base) });
}
