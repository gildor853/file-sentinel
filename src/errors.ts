/** Thrown only for programming errors (invalid arguments or options), never for hostile file content. */
export class FileSentinelError extends Error {
  readonly code: "InvalidInput" | "InvalidOption";
  constructor(code: "InvalidInput" | "InvalidOption", message: string) {
    super(message);
    this.name = "FileSentinelError";
    this.code = code;
  }
}

/** True for errors thrown by this library. */
export function isFileSentinelError(e: unknown): e is FileSentinelError {
  return e instanceof FileSentinelError;
}

/** @internal */
export function fail(code: "InvalidInput" | "InvalidOption", message: string): never {
  throw new FileSentinelError(code, message);
}

/** @internal Short description of a value for error messages. */
export function show(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "an array";
  if (typeof v === "string") return JSON.stringify(v.length > 40 ? `${v.slice(0, 40)}…` : v);
  if (typeof v === "object") return "an object";
  return typeof v === "symbol" || typeof v === "function" ? `a ${typeof v}` : String(v);
}
