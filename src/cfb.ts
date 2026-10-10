/**
 * Compound File Binary (MS-CFB) reader: header, FAT/DIFAT, mini stream and the
 * directory tree, with protection against cycles, overlong chains and
 * out-of-range sectors.
 */
import { u16le, u32le, utf16le } from "./bytes.js";

/** @internal Thrown for structures that cannot be read. */
export class CfbError extends Error {}

const END = 0xfffffffe;
const FREE = 0xffffffff;
const NOSTREAM = 0xffffffff;

/** @internal A directory entry with its full path. */
export interface CfbEntry {
  readonly name: string;
  /** Path segments from the root (excluding the root entry). */
  readonly path: readonly string[];
  /** 1 storage, 2 stream, 5 root. */
  readonly type: number;
  readonly clsid: string;
  readonly start: number;
  readonly size: number;
}

/** @internal An opened compound file. */
export interface Cfb {
  readonly root: CfbEntry;
  readonly entries: readonly CfbEntry[];
  read(e: CfbEntry): Uint8Array;
}

/** @internal Formats a 16-byte CLSID as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}. */
export function clsidAt(b: Uint8Array, o: number): string {
  const h = (n: number, w: number) => n.toString(16).padStart(w, "0");
  const tail = Array.from(b.subarray(o + 8, o + 16), (x) => h(x, 2)).join("");
  return `{${h(u32le(b, o), 8)}-${h(u16le(b, o + 4), 4)}-${h(u16le(b, o + 6), 4)}-${tail.slice(0, 4)}-${tail.slice(4)}}`.toUpperCase();
}

/** @internal Opens a compound file; `step` is charged with work units. */
export function openCfb(b: Uint8Array, step: (n: number) => void, maxEntries: number): Cfb {
  if (b.length < 512) throw new CfbError("file shorter than a CFB header");
  const shift = u16le(b, 0x1e);
  if (shift !== 9 && shift !== 12) throw new CfbError("unsupported sector size");
  const size = 1 << shift;
  if (u16le(b, 0x20) !== 6) throw new CfbError("unsupported mini sector size");
  const sectorCount = Math.ceil(Math.max(0, b.length - size) / size);
  const fatSectors = u32le(b, 0x2c);
  const firstDir = u32le(b, 0x30);
  const cutoff = u32le(b, 0x38) || 4096;
  const firstMiniFat = u32le(b, 0x3c);
  let difat = u32le(b, 0x44);
  const difatCount = u32le(b, 0x48);
  if (fatSectors > sectorCount + 1) throw new CfbError("FAT larger than the file");
  const offsetOf = (sid: number): number => {
    if (sid >= sectorCount) throw new CfbError(`sector ${sid} is out of range`);
    return (sid + 1) * size;
  };
  const fatList: number[] = [];
  for (let k = 0; k < 109 && fatList.length < fatSectors; k++) fatList.push(u32le(b, 0x4c + k * 4));
  const seenDifat = new Set<number>();
  for (let d = 0; d < difatCount && fatList.length < fatSectors; d++) {
    if (difat === END || difat === FREE || seenDifat.has(difat)) break;
    seenDifat.add(difat);
    const off = offsetOf(difat);
    const per = size / 4 - 1;
    for (let k = 0; k < per && fatList.length < fatSectors; k++) fatList.push(u32le(b, off + k * 4));
    difat = u32le(b, off + per * 4);
  }
  step(fatList.length);
  const perSector = size / 4;
  const fat = new Uint32Array(fatList.length * perSector);
  fatList.forEach((sid, k) => {
    const off = sid < sectorCount ? (sid + 1) * size : -1;
    for (let j = 0; j < perSector; j++) fat[k * perSector + j] = off >= 0 ? u32le(b, off + j * 4) : FREE;
  });
  const chain = (start: number, table: Uint32Array, limit: number): number[] => {
    const out: number[] = [];
    let sid = start;
    while (sid !== END && sid !== FREE) {
      if (sid >= table.length || out.length >= limit) throw new CfbError("broken sector chain");
      out.push(sid);
      sid = table[sid] as number;
    }
    step(out.length);
    return out;
  };
  const readChain = (start: number, length: number | undefined): Uint8Array => {
    const sids = chain(start, fat, Math.min(sectorCount, length === undefined ? sectorCount : Math.ceil(length / size) + 1));
    const total = Math.min(length ?? sids.length * size, sids.length * size);
    const out = new Uint8Array(total);
    let pos = 0;
    for (const sid of sids) {
      if (pos >= total) break;
      const off = offsetOf(sid);
      const part = b.subarray(off, Math.min(off + size, off + total - pos, b.length));
      out.set(part, pos);
      pos += part.length;
    }
    return pos < total ? out.subarray(0, pos) : out;
  };
  const dir = readChain(firstDir, undefined);
  interface Raw { name: string; type: number; left: number; right: number; child: number; clsid: string; start: number; size: number }
  const raws: Raw[] = [];
  for (let off = 0; off + 128 <= dir.length && raws.length < maxEntries; off += 128) {
    const nameLen = Math.min(u16le(dir, off + 0x40), 64);
    raws.push({
      name: utf16le(dir.subarray(off, off + Math.max(0, nameLen - 2))),
      type: dir[off + 0x42] as number,
      left: u32le(dir, off + 0x44),
      right: u32le(dir, off + 0x48),
      child: u32le(dir, off + 0x4c),
      clsid: clsidAt(dir, off + 0x50),
      start: u32le(dir, off + 0x74),
      size: shift === 9 ? u32le(dir, off + 0x78) : u32le(dir, off + 0x78) + u32le(dir, off + 0x7c) * 0x100000000,
    });
  }
  step(raws.length);
  const r0 = raws[0];
  if (!r0 || r0.type !== 5) throw new CfbError("missing root entry");
  const root: CfbEntry = { name: r0.name, path: [], type: 5, clsid: r0.clsid, start: r0.start, size: r0.size };
  const entries: CfbEntry[] = [];
  const visited = new Set<number>([0]);
  // iterative walk over the red-black trees
  const work: { id: number; parent: readonly string[] }[] = [{ id: r0.child, parent: [] }];
  while (work.length > 0) {
    const { id, parent } = work.pop() as { id: number; parent: readonly string[] };
    if (id === NOSTREAM || id >= raws.length || visited.has(id)) continue;
    visited.add(id);
    step(1);
    const r = raws[id] as Raw;
    if (r.type !== 1 && r.type !== 2) continue;
    const path = [...parent, r.name];
    entries.push({ name: r.name, path, type: r.type, clsid: r.clsid, start: r.start, size: r.size });
    work.push({ id: r.left, parent }, { id: r.right, parent });
    if (r.type === 1) work.push({ id: r.child, parent: path });
  }
  let mini: { stream: Uint8Array; fat: Uint32Array } | undefined;
  const miniData = () => {
    if (!mini) {
      const stream = readChain(root.start, root.size);
      const mfBytes = firstMiniFat === END || firstMiniFat === FREE ? new Uint8Array(0) : readChain(firstMiniFat, undefined);
      const mf = new Uint32Array(mfBytes.length >>> 2);
      for (let k = 0; k < mf.length; k++) mf[k] = u32le(mfBytes, k * 4);
      mini = { stream, fat: mf };
    }
    return mini;
  };
  const read = (e: CfbEntry): Uint8Array => {
    if (e.type !== 2) throw new CfbError("not a stream");
    if (e.size === 0) return new Uint8Array(0);
    if (e.size > b.length * 2 + 4096) throw new CfbError("stream larger than the file");
    if (e.size >= cutoff) return readChain(e.start, e.size);
    const m = miniData();
    const sids = chain(e.start, m.fat, Math.ceil(e.size / 64) + 1);
    const out = new Uint8Array(Math.min(e.size, sids.length * 64));
    let pos = 0;
    for (const sid of sids) {
      if (pos >= out.length) break;
      const off = sid * 64;
      if (off >= m.stream.length) break;
      const part = m.stream.subarray(off, Math.min(off + 64, off + out.length - pos));
      out.set(part, pos);
      pos += part.length;
    }
    return out.subarray(0, pos);
  };
  return { root, entries, read };
}
