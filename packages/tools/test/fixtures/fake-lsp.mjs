// A small language server for tests: real LSP framing over stdio, toy answers.
// definition and implementation: the line that says `function <word>`; references: every occurrence of the word;
// hover: a signature; documentSymbol: each function; diagnostics: an error on every line containing BROKEN.
import { writeFileSync } from 'node:fs';

const marker = process.argv[2];
if (marker) writeFileSync(marker, `started ${process.pid}\n`);
const docs = new Map();
let buffer = Buffer.alloc(0);

const send = (message) => {
  const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', ...message }), 'utf8');
  process.stdout.write(`Content-Length: ${body.length}\r\n\r\n`);
  process.stdout.write(body);
};

const wordAt = (text, line, character) => {
  const row = text.split(/\r?\n/)[line] ?? '';
  let start = character;
  let end = character;
  while (start > 0 && /\w/.test(row[start - 1])) start -= 1;
  while (end < row.length && /\w/.test(row[end])) end += 1;
  return row.slice(start, end);
};

const publish = (uri) => {
  const lines = (docs.get(uri) ?? '').split(/\r?\n/);
  const diagnostics = lines.flatMap((text, line) => (text.includes('BROKEN') ? [{ range: { start: { line, character: text.indexOf('BROKEN') }, end: { line, character: text.indexOf('BROKEN') + 6 } }, severity: 1, message: 'BROKEN is not defined', source: 'fake' }] : []));
  send({ method: 'textDocument/publishDiagnostics', params: { uri, diagnostics } });
};

const find = (pattern) => {
  const found = [];
  for (const [uri, text] of docs) {
    text.split(/\r?\n/).forEach((row, line) => {
      const match = pattern.exec(row);
      if (match) found.push({ uri, range: { start: { line, character: match.index }, end: { line, character: match.index + match[0].length } } });
    });
  }
  return found;
};

const handle = (message) => {
  const { id, method, params } = message;
  if (method === 'initialize') return send({ id, result: { capabilities: { textDocumentSync: 1, definitionProvider: true, referencesProvider: true, hoverProvider: true, documentSymbolProvider: true, implementationProvider: true } } });
  if (method === 'shutdown') return send({ id, result: null });
  if (method === 'exit') process.exit(0);
  if (method === 'textDocument/didOpen') {
    docs.set(params.textDocument.uri, params.textDocument.text);
    return publish(params.textDocument.uri);
  }
  if (method === 'textDocument/didChange') {
    docs.set(params.textDocument.uri, params.contentChanges.at(-1).text);
    return publish(params.textDocument.uri);
  }
  if (id === undefined) return;
  const text = docs.get(params?.textDocument?.uri) ?? '';
  const word = params?.position ? wordAt(text, params.position.line, params.position.character) : '';
  if (method === 'textDocument/definition' || method === 'textDocument/implementation') return send({ id, result: word ? find(new RegExp(`function ${word}\\b`)) : [] });
  if (method === 'textDocument/references') return send({ id, result: word ? find(new RegExp(`\\b${word}\\b`)) : [] });
  if (method === 'textDocument/hover') return send({ id, result: word ? { contents: { kind: 'plaintext', value: `function ${word}(): number` } } : null });
  if (method === 'textDocument/documentSymbol') {
    const symbols = text.split(/\r?\n/).flatMap((row, line) => {
      const match = /function (\w+)/.exec(row);
      return match ? [{ name: match[1], kind: 12, range: { start: { line, character: 0 }, end: { line, character: row.length } }, selectionRange: { start: { line, character: 0 }, end: { line, character: row.length } } }] : [];
    });
    return send({ id, result: symbols });
  }
  send({ id, error: { code: -32601, message: `unknown method ${method}` } });
};

process.stdin.on('data', (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    const end = buffer.indexOf('\r\n\r\n');
    if (end < 0) return;
    const length = Number(/Content-Length: (\d+)/i.exec(buffer.subarray(0, end).toString())?.[1]);
    if (buffer.length < end + 4 + length) return;
    const body = buffer.subarray(end + 4, end + 4 + length).toString('utf8');
    buffer = buffer.subarray(end + 4 + length);
    handle(JSON.parse(body));
  }
});
