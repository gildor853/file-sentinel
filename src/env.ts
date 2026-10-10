import type { Ctx } from "./ctx.js";
import type { DetectedType } from "./types.js";

/** @internal One item being scanned (the file itself or something embedded in it). */
export interface Item {
  readonly bytes: Uint8Array;
  /** Location path (container segments); empty for the top-level file. */
  readonly path: readonly string[];
  /** File name: the declared name at the top level, the entry/attachment name for embedded items. */
  readonly name: string | undefined;
  readonly declaredMime: string | undefined;
  readonly depth: number;
}

/** @internal What a format handler gets. */
export interface Env {
  readonly ctx: Ctx;
  readonly item: Item;
  /** Scans embedded content. `segment` is appended to the location path; `name` is its file name if known. */
  child(bytes: Uint8Array, segment: string, name?: string): DetectedType | undefined;
  /** Adds a finding at this item's path. */
  add(id: string, opts?: Parameters<Ctx["add"]>[2]): void;
  /** Adds a finding at a sub-path (e.g. a part inside a container that is not scanned as a separate item). */
  addAt(segments: readonly string[], id: string, opts?: Parameters<Ctx["add"]>[2]): void;
}

/** @internal A format handler may refine the detected type (e.g. zip → docx). */
export type Handler = (env: Env, detected: DetectedType) => DetectedType | void;
