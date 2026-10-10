/** Image structure checks: dimensions (pixel bombs), code in metadata, trailing data. */
import { decode, excerpt, latin1, u16be, u16le, u32be, u32le } from "./bytes.js";
import { crc32 } from "./crc32.js";
import type { Env } from "./env.js";
import { inflateZlib } from "./inflate.js";
import { containsHtmlMarker } from "./sniff.js";
import { checkTrailing } from "./trailing.js";
import type { DetectedType } from "./types.js";

function dimensions(env: Env, w: number, h: number, where: string): void {
  if (w * h > env.ctx.limits.maxImagePixels) env.add("IMAGE_DIMENSIONS_BOMB", { element: where, evidence: `${w} × ${h} = ${w * h} pixels` });
}

function codeIn(env: Env, text: string, element: string): void {
  const m = /<script\b|<\?php|<\?=|<iframe\b|<html\b|<body\b|javascript:|<svg\b[^>]{0,200}\bon[a-z]{1,30}\s{0,5}=/i.exec(text);
  if (m) env.add("IMAGE_EMBEDDED_CODE", { element, evidence: excerpt(text.slice(Math.max(0, m.index - 20), m.index + 100)) });
}

function rawCode(env: Env, b: Uint8Array, end: number): void {
  const k = containsHtmlMarker(b, 0, end);
  if (k >= 0) env.add("IMAGE_EMBEDDED_CODE", { offset: k, evidence: excerpt(latin1(b, Math.max(0, k - 20), Math.min(end, k + 100))) });
}

function png(env: Env): void {
  const b = env.item.bytes;
  let p = 8;
  let first = true;
  let end = -1;
  let crcBad = 0;
  while (p + 12 <= b.length) {
    env.ctx.step(4);
    const len = u32be(b, p);
    const type = latin1(b, p + 4, p + 8);
    if (len > b.length - p - 12 || !/^[A-Za-z]{4}$/.test(type)) {
      env.add("IMAGE_MALFORMED", { offset: p, detail: "A PNG chunk is truncated or invalid." });
      break;
    }
    const data = b.subarray(p + 8, p + 8 + len);
    if (crc32(b.subarray(p + 4, p + 8 + len)) !== u32be(b, p + 8 + len)) crcBad++;
    if (first && type !== "IHDR") env.add("IMAGE_MALFORMED", { offset: p, detail: "The first PNG chunk is not IHDR." });
    first = false;
    if (type === "IHDR") dimensions(env, u32be(data, 0), u32be(data, 4), "IHDR");
    else if (type === "tEXt" || type === "zTXt" || type === "iTXt") {
      const z = data.indexOf(0);
      const key = latin1(data, 0, Math.max(0, z));
      let text = "";
      if (type === "tEXt") text = latin1(data, z + 1);
      else if (type === "zTXt") text = latin1(inflateZlib(data.subarray(z + 2), 1 << 20, (n) => env.ctx.step(n)).data);
      else {
        const compressed = data[z + 1] === 1;
        let q = z + 3;
        q = data.indexOf(0, q) + 1; // language tag
        q = data.indexOf(0, q) + 1; // translated keyword
        if (q > 0) text = decode(compressed ? inflateZlib(data.subarray(q), 4 << 20, (n) => env.ctx.step(n)).data : data.subarray(q), "utf-8");
      }
      codeIn(env, text, `${type} ${key}`);
    } else if (type === "IEND") {
      end = p + 12;
      break;
    }
    p += 12 + len;
  }
  if (crcBad) env.add("IMAGE_MALFORMED", { detail: `${crcBad} PNG chunk CRC mismatch(es).` });
  rawCode(env, b, end > 0 ? end : b.length);
  if (end > 0) checkTrailing(env, b, end);
}

const SOF = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

function jpeg(env: Env): void {
  const b = env.item.bytes;
  let p = 2;
  let end = -1;
  let sof = false;
  while (p + 4 <= b.length) {
    env.ctx.step(2);
    if (b[p] !== 0xff) {
      env.add("IMAGE_MALFORMED", { offset: p, detail: "A JPEG marker is missing." });
      break;
    }
    const m = b[p + 1] as number;
    if (m === 0xff) {
      p++;
      continue;
    }
    if (m === 0xd9) {
      end = p + 2;
      break;
    }
    if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) {
      p += 2;
      continue;
    }
    const len = u16be(b, p + 2);
    if (len < 2 || p + 2 + len > b.length) {
      env.add("IMAGE_MALFORMED", { offset: p, detail: "A JPEG segment is truncated." });
      break;
    }
    if (SOF.has(m)) {
      sof = true;
      dimensions(env, u16be(b, p + 7), u16be(b, p + 5), "SOF");
    }
    if (m === 0xfe || (m >= 0xe0 && m <= 0xef)) codeIn(env, latin1(b, p + 4, Math.min(p + 2 + len, p + 4 + 65536)), m === 0xfe ? "COM" : `APP${m - 0xe0}`);
    p += 2 + len;
    if (m === 0xda) {
      // entropy-coded data: runs until a marker other than stuffing (FF00) or restart markers
      let q = p;
      for (;;) {
        q = b.indexOf(0xff, q);
        if (q < 0 || q + 1 >= b.length) {
          q = b.length;
          break;
        }
        const x = b[q + 1] as number;
        if (x === 0 || (x >= 0xd0 && x <= 0xd7) || x === 0xff) q += x === 0xff ? 1 : 2;
        else break;
      }
      env.ctx.step((q - p) >>> 8);
      p = q;
    }
  }
  if (!sof && end > 0) env.add("IMAGE_MALFORMED", { detail: "The JPEG has no frame header." });
  rawCode(env, b, end > 0 ? end : b.length);
  if (end > 0) checkTrailing(env, b, end);
}

function gif(env: Env): void {
  const b = env.item.bytes;
  dimensions(env, u16le(b, 6), u16le(b, 8), "logical screen");
  let p = 13;
  if ((b[10] ?? 0) & 0x80) p += 3 * (1 << (((b[10] as number) & 7) + 1));
  let end = -1;
  const subBlocks = () => {
    while (p < b.length) {
      const n = b[p] as number;
      p += 1 + n;
      if (n === 0) return;
    }
  };
  while (p < b.length) {
    env.ctx.step(2);
    const c = b[p];
    if (c === 0x3b) {
      end = p + 1;
      break;
    }
    if (c === 0x21) {
      p += 2;
      subBlocks();
    } else if (c === 0x2c) {
      dimensions(env, u16le(b, p + 5), u16le(b, p + 7), "image descriptor");
      const flags = b[p + 9] ?? 0;
      p += 10;
      if (flags & 0x80) p += 3 * (1 << ((flags & 7) + 1));
      p++; // LZW minimum code size
      subBlocks();
    } else {
      env.add("IMAGE_MALFORMED", { offset: p, detail: "An unknown GIF block was found." });
      break;
    }
  }
  rawCode(env, b, end > 0 ? end : b.length);
  if (end > 0 && end < b.length) checkTrailing(env, b, end);
}

function webp(env: Env): void {
  const b = env.item.bytes;
  const end = 8 + u32le(b, 4);
  if (latin1(b, 12, 16) === "VP8X") dimensions(env, (u32le(b, 24) & 0xffffff) + 1, (u32le(b, 27) & 0xffffff) + 1, "VP8X");
  rawCode(env, b, Math.min(end, b.length));
  if (end < b.length) checkTrailing(env, b, end + (end & 1));
}

function bmp(env: Env): void {
  const b = env.item.bytes;
  if (u32le(b, 14) >= 40) {
    const w = Math.abs(u32le(b, 18) | 0);
    const h = Math.abs(u32le(b, 22) | 0);
    dimensions(env, w, h, "BITMAPINFOHEADER");
  }
  rawCode(env, b, b.length);
}

/** @internal Image handler. */
export function scanImage(env: Env, detected: DetectedType): DetectedType {
  switch (detected.format) {
    case "png":
      png(env);
      break;
    case "jpeg":
      jpeg(env);
      break;
    case "gif":
      gif(env);
      break;
    case "webp":
      webp(env);
      break;
    case "bmp":
      bmp(env);
      break;
    default:
      rawCode(env, env.item.bytes, env.item.bytes.length);
  }
  return detected;
}
