#!/usr/bin/env node
/** Node.js entry point for the `file-sentinel` command. */
import { type CliIo, main } from "./cli-main.js";

interface NodeStream {
  write(chunk: Uint8Array | string, callback?: (err?: Error | null) => void): boolean;
}
interface NodeProcess {
  argv: string[];
  exitCode?: number;
  stdin: AsyncIterable<Uint8Array>;
  stdout: NodeStream;
  stderr: NodeStream;
}
interface FileHandle {
  read(buffer: Uint8Array, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
  stat(): Promise<{ size: number; isFile(): boolean }>;
  close(): Promise<void>;
}
interface NodeFs {
  open(path: string, flags: string): Promise<FileHandle>;
}

const proc = (globalThis as unknown as { process: NodeProcess }).process;
const fsName = "node:fs/promises";
let fsModule: Promise<NodeFs> | undefined;
const fs = () => (fsModule ??= import(/* @vite-ignore */ fsName) as Promise<NodeFs>);

const write = (stream: NodeStream, data: Uint8Array | string) =>
  new Promise<void>((resolve, reject) => {
    stream.write(data, (err) => (err ? reject(err) : resolve()));
  });

const io: CliIo = {
  readFile: async (path, max) => {
    const fh = await (await fs()).open(path, "r");
    try {
      const st = await fh.stat();
      if (!st.isFile()) throw new Error("not a regular file");
      const n = Math.min(st.size, max);
      const buf = new Uint8Array(n);
      let off = 0;
      while (off < n) {
        const { bytesRead } = await fh.read(buf, off, n - off, off);
        if (bytesRead === 0) break;
        off += bytesRead;
      }
      return buf.subarray(0, off);
    } finally {
      await fh.close();
    }
  },
  readStdin: async (max) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of proc.stdin) {
      if (total >= max) continue; // drain the rest without keeping it
      const part = chunk.subarray(0, max - total);
      chunks.push(part);
      total += part.length;
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  },
  stdout: (text) => write(proc.stdout, text),
  stderr: (text) => {
    proc.stderr.write(text);
  },
};

main(proc.argv.slice(2), io).then(
  (code) => {
    proc.exitCode = code;
  },
  (err: unknown) => {
    proc.stderr.write(`file-sentinel: unexpected error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    proc.exitCode = 2;
  },
);
