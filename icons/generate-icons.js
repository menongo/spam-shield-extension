/**
 * Generates icon16.png, icon48.png, icon128.png
 * Uses only built-in Node.js modules — no npm install needed.
 * Run: node generate-icons.js
 */
'use strict';

const zlib = require('zlib');
const fs   = require('fs');
const path = require('path');

// ─── CRC32 (required by PNG spec) ─────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buf[i]) & 0xFF];
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function pngChunk(type, data) {
  const lenBuf = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcVal  = Buffer.allocUnsafe(4);
  crcVal.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([lenBuf, typeBuf, data, crcVal]);
}

// ─── Geometry helpers ─────────────────────────────────────────────────────────

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const lenSq = dx * dx + dy * dy;
  if (lenSq === 0) return Math.hypot(px - ax, py - ay);
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / lenSq));
  return Math.hypot(px - ax - t * dx, py - ay - t * dy);
}

// ─── Draw icon pixels ─────────────────────────────────────────────────────────

/**
 * Returns [r, g, b, a] for a pixel at (x, y) in a size×size icon.
 * Design: indigo background, white shield, white checkmark.
 */
function getPixel(x, y, size) {
  const s = size;

  // Normalised coords centered at (0,0), range ±0.5
  const nx = (x - s / 2) / s;
  const ny = (y - s / 2) / s;

  // ── Background: solid indigo ──────────────────────────────────────────────
  const bgR = 79, bgG = 70, bgB = 229;

  // ── Shield shape ──────────────────────────────────────────────────────────
  // Shield occupies roughly: x ∈ [-0.30, 0.30], y ∈ [-0.38, 0.40]
  const shW = 0.29;   // half-width
  const shTop = -0.37;
  const shMid = 0.06; // where tapering starts
  const shBot = 0.41; // tip

  const inShield = (() => {
    if (ny < shTop || ny > shBot) return false;
    if (ny <= shMid) {
      // Top rectangular portion — slightly rounded corners
      const absX = Math.abs(nx), absY = Math.abs(ny);
      const cornerR = 0.06;
      if (absX > shW || absY > -shTop) return false;
      // Round top-left / top-right corners
      if (absX > shW - cornerR && absY < shTop + cornerR) {
        return Math.hypot(absX - (shW - cornerR), absY - (shTop + cornerR)) <= cornerR;
      }
      return true;
    } else {
      // Tapering bottom
      const t = (ny - shMid) / (shBot - shMid);
      return Math.abs(nx) <= shW * (1 - t);
    }
  })();

  if (!inShield) return [bgR, bgG, bgB, 255];

  // ── Shield fill: slightly lighter indigo ──────────────────────────────────
  const sfR = 99, sfG = 91, sfB = 242;

  // ── Checkmark (white) drawn inside shield ─────────────────────────────────
  // Three points: start (bottom-left of tick), knee, end (top-right)
  const sc = s; // use pixel coords directly for thickness
  const px2 = x - s / 2, py2 = y - s / 2; // pixel coords relative to center

  const ck = s * 0.28;  // checkmark scale
  const offY = s * 0.04; // vertical offset (shift down slightly)
  const p1 = { x: -ck * 0.90, y: offY + ck * 0.10 };
  const p2 = { x: -ck * 0.08, y: offY + ck * 0.70 };
  const p3 = { x:  ck * 0.95, y: offY - ck * 0.58 };
  const thick = Math.max(1.0, s * 0.075);

  const onCheck = distToSegment(px2, py2, p1.x, p1.y, p2.x, p2.y) < thick ||
                  distToSegment(px2, py2, p2.x, p2.y, p3.x, p3.y) < thick;

  if (onCheck) return [255, 255, 255, 255]; // white checkmark

  // ── Inner shield highlight (subtle lighter area at top) ───────────────────
  const inHighlight = ny < -0.05 && Math.abs(nx) < shW - 0.05;
  if (inHighlight) {
    return [sfR + 12, sfG + 10, sfB + 8, 255];
  }

  return [sfR, sfG, sfB, 255];
}

// ─── Build PNG buffer ─────────────────────────────────────────────────────────

function buildPNG(size) {
  // Raw image data: 1 filter byte + 4 bytes (RGBA) per pixel, per row
  const raw = Buffer.alloc(size * (1 + size * 4), 0);

  for (let y = 0; y < size; y++) {
    const rowOff  = y * (1 + size * 4);
    raw[rowOff]   = 0; // filter type: None
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = getPixel(x, y, size);
      const off = rowOff + 1 + x * 4;
      raw[off]     = r;
      raw[off + 1] = g;
      raw[off + 2] = b;
      raw[off + 3] = a;
    }
  }

  // IHDR: width, height, bit depth=8, color type=6 (RGBA), compress=0, filter=0, interlace=0
  const ihdr = Buffer.allocUnsafe(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8]  = 8; // bit depth
  ihdr[9]  = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), // PNG signature
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

// ─── Write files ──────────────────────────────────────────────────────────────

const outDir = __dirname;

for (const size of [16, 48, 128]) {
  const buf  = buildPNG(size);
  const file = path.join(outDir, `icon${size}.png`);
  fs.writeFileSync(file, buf);
  console.log(`✓ icon${size}.png  (${buf.length} bytes)`);
}

console.log('\nAll icons generated. You can now load the extension in Chrome / Edge / Brave.');
