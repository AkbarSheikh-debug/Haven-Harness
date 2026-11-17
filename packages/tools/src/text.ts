export type TextEncoding = 'utf8' | 'utf8-bom' | 'utf16le' | 'utf16be';

export interface DecodedText {
  readonly text: string;
  readonly encoding: TextEncoding;
  readonly eol: '\n' | '\r\n';
}

const swapBytes = (bytes: Buffer): Buffer => Buffer.from(bytes).swap16();

function evenLength(bytes: Buffer): Buffer {
  return bytes.length % 2 === 0 ? bytes : bytes.subarray(0, -1);
}

/** Returns `null` for binary, so no tool ever hands a model raw bytes as text. */
export function decodeText(bytes: Buffer): DecodedText | null {
  let text: string;
  let encoding: TextEncoding;
  if (bytes[0] === 0xff && bytes[1] === 0xfe) {
    text = evenLength(bytes.subarray(2)).toString('utf16le');
    encoding = 'utf16le';
  } else if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    text = swapBytes(evenLength(bytes.subarray(2))).toString('utf16le');
    encoding = 'utf16be';
  } else if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    text = bytes.subarray(3).toString('utf8');
    encoding = 'utf8-bom';
  } else {
    if (bytes.subarray(0, 8000).includes(0)) return null;
    text = bytes.toString('utf8');
    encoding = 'utf8';
  }
  const crlf = text.match(/\r\n/g)?.length ?? 0;
  const lf = (text.match(/\n/g)?.length ?? 0) - crlf;
  return { text, encoding, eol: crlf > lf ? '\r\n' : '\n' };
}

export function encodeText(text: string, encoding: TextEncoding): Buffer {
  switch (encoding) {
    case 'utf8':
      return Buffer.from(text, 'utf8');
    case 'utf8-bom':
      return Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, 'utf8')]);
    case 'utf16le':
      return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
    case 'utf16be':
      return Buffer.concat([Buffer.from([0xfe, 0xff]), swapBytes(Buffer.from(text, 'utf16le'))]);
  }
}
