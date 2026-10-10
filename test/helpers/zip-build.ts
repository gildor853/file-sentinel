function crc32(data: Uint8Array): number {
  let c = ~0;
  for (const x of data) {
    c ^= x;
    for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
  }
  return ~c >>> 0;
}

/** Minimal ZIP builders for tests (stored / flagged entries). */
export function zipStored(files: Record<string, Uint8Array | string>): Uint8Array {
  return zipEntries(Object.entries(files).map(([name, data]) => ({ name, data: typeof data === "string" ? new TextEncoder().encode(data) : data })));
}

export interface ZipEnt {
  name: string;
  data: Uint8Array;
  method?: number;
  flags?: number;
  crc?: number;
  csize?: number;
  usize?: number;
  externalAttr?: number;
  localOffset?: number;
  skipData?: boolean;
  /** Version made by (high byte = host OS; 3 = Unix). */
  madeBy?: number;
}

export function zipEntries(entries: ZipEnt[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const u16 = (n: number) => {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, n, true);
    return b;
  };
  const u32 = (n: number) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return b;
  };
  const cat = (parts: Uint8Array[]) => {
    let n = 0;
    for (const p of parts) n += p.length;
    const o = new Uint8Array(n);
    let i = 0;
    for (const p of parts) {
      o.set(p, i);
      i += p.length;
    }
    return o;
  };
  for (const e of entries) {
    const n = new TextEncoder().encode(e.name);
    const d = e.data;
    const method = e.method ?? 0;
    const flags = e.flags ?? 0;
    const crc = e.crc ?? (method === 0 ? crc32(d) : e.crc ?? 0);
    const csize = e.csize ?? d.length;
    const usize = e.usize ?? d.length;
    const local = cat([
      u32(0x04034b50),
      u16(20),
      u16(flags),
      u16(method),
      u16(0),
      u16(0),
      u32(crc),
      u32(csize),
      u32(usize),
      u16(n.length),
      u16(0),
      n,
    ]);
    const cd = cat([
      u32(0x02014b50),
      u16(e.madeBy ?? 20),
      u16(20),
      u16(flags),
      u16(method),
      u16(0),
      u16(0),
      u32(crc),
      u32(csize),
      u32(usize),
      u16(n.length),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(e.externalAttr ?? 0),
      u32(e.localOffset ?? offset),
      n,
    ]);
    central.push(cd);
    if (!e.skipData) {
      const payload = d.length >= csize ? d.subarray(0, csize) : cat([d, new Uint8Array(csize - d.length)]);
      chunks.push(local, payload);
      offset += local.length + csize;
    }
  }
  const cdBuf = cat(central);
  const eocd = cat([u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(cdBuf.length), u32(offset), u16(0)]);
  return cat([...chunks, cdBuf, eocd]);
}
