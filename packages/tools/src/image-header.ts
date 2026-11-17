/** Width and height from an image's header alone. No pixel is ever decoded, so nothing can inflate. */
export interface ImageHeader {
  readonly format: 'png' | 'jpeg' | 'gif' | 'webp';
  readonly width: number;
  readonly height: number;
}

export type HeaderResult = ImageHeader | { readonly error: string };

/** JPEG start-of-frame markers that carry the frame size. */
const SOF = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
/** A JPEG with more segments than this before its frame is refused rather than walked further. */
const MAX_JPEG_SEGMENTS = 1_000;

function png(bytes: Buffer): HeaderResult {
  if (bytes.length < 24 || bytes.toString('ascii', 12, 16) !== 'IHDR') return { error: 'The PNG header is cut off.' };
  return { format: 'png', width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

function jpeg(bytes: Buffer): HeaderResult {
  let at = 2;
  for (let segment = 0; segment < MAX_JPEG_SEGMENTS && at + 9 < bytes.length; segment += 1) {
    if (bytes[at] !== 0xff) return { error: 'The JPEG has a broken segment.' };
    const marker = bytes[at + 1] as number;
    const length = bytes.readUInt16BE(at + 2);
    if (SOF.has(marker)) return { format: 'jpeg', height: bytes.readUInt16BE(at + 5), width: bytes.readUInt16BE(at + 7) };
    if (length < 2) return { error: 'The JPEG has a broken segment length.' };
    at += 2 + length;
  }
  return { error: 'The JPEG has no frame header where one was expected.' };
}

function webp(bytes: Buffer): HeaderResult {
  if (bytes.length < 30) return { error: 'The WebP header is cut off.' };
  const kind = bytes.toString('ascii', 12, 16);
  if (kind === 'VP8X') return { format: 'webp', width: 1 + bytes.readUIntLE(24, 3), height: 1 + bytes.readUIntLE(27, 3) };
  if (kind === 'VP8 ') return { format: 'webp', width: bytes.readUInt16LE(26) & 0x3fff, height: bytes.readUInt16LE(28) & 0x3fff };
  if (kind === 'VP8L') {
    const bits = bytes.readUInt32LE(21);
    return { format: 'webp', width: 1 + (bits & 0x3fff), height: 1 + ((bits >> 14) & 0x3fff) };
  }
  return { error: 'The WebP kind is not known.' };
}

export function parseImageHeader(bytes: Buffer): HeaderResult {
  if (bytes.length >= 8 && bytes.readUInt32BE(0) === 0x89504e47 && bytes.readUInt32BE(4) === 0x0d0a1a0a) return png(bytes);
  if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) return jpeg(bytes);
  if (bytes.length >= 10 && bytes.toString('ascii', 0, 4) === 'GIF8') {
    return { format: 'gif', width: bytes.readUInt16LE(6), height: bytes.readUInt16LE(8) };
  }
  const riff = bytes.length >= 12 && bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP';
  if (riff) return webp(bytes);
  return { error: 'This is not a PNG, JPEG, GIF or WebP image.' };
}
