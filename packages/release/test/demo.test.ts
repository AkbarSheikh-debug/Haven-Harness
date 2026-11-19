import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

interface Transcript {
  readonly recorded: string;
  readonly events: readonly { kind: 'out' | 'in'; text: string }[];
}

async function transcript(): Promise<{ text: string; typed: string[]; raw: Transcript }> {
  const raw = JSON.parse(await readFile(join(ROOT, 'scripts', 'demo', 'transcript.json'), 'utf8')) as Transcript;
  return { raw, text: raw.events.filter((event) => event.kind === 'out').map((event) => event.text).join(''), typed: raw.events.filter((event) => event.kind === 'in').map((event) => event.text) };
}

describe('the README demo', () => {
  it('is a valid GIF of a sensible size and length, shown at the top of the README with an honest caption', async () => {
    const gif = await readFile(join(ROOT, 'docs', 'demo.gif'));
    assert.equal(gif.subarray(0, 6).toString('latin1'), 'GIF89a');
    assert.ok(gif.length > 50_000 && gif.length < 2_000_000, `${gif.length} bytes`);
    const width = gif.readUInt16LE(6);
    const height = gif.readUInt16LE(8);
    assert.ok(width >= 600 && width <= 1200 && height >= 400 && height <= 900, `${width}x${height}`);
    // Several frames: each one starts with a graphic control extension (0x21 0xF9).
    let frames = 0;
    for (let index = 0; index < gif.length - 1; index += 1) if (gif[index] === 0x21 && gif[index + 1] === 0xf9) frames += 1;
    assert.ok(frames > 50, `${frames} frames`);
    const readme = await readFile(join(ROOT, 'README.md'), 'utf8');
    assert.ok(readme.indexOf('docs/demo.gif') > 0 && readme.indexOf('docs/demo.gif') < readme.indexOf('## Why another coding agent?'), 'the demo is not at the top');
    assert.match(readme, /The model is scripted/);
  });

  it('was recorded from a real run: the verified-box banner, three approval cards, a test passing in the box, and a refusal', async () => {
    const { text, typed, raw } = await transcript();
    assert.match(raw.recorded, /real hn run/);
    assert.match(text, /Sandboxed: a verified Windows box \(tier 3/);
    assert.equal((text.match(/hn approval: /g) ?? []).length, 3, 'the edit, the test run and the shell read each ask');
    assert.match(text, /hn approval: edit_file \(reversible[^]*return \$a - \$b[^]*return \$a \+ \$b/);
    assert.match(text, /hn approval: bash \(execution[^]*test\.ps1/);
    assert.match(text, /ok: Add-Numbers 2 3 = 5/);
    assert.match(text, /Blocked: ~\/demo\\outside\\secret\.txt is outside the project\./);
    assert.match(text, /Access is denied/);
    assert.match(text, /Brought back 1 file\(s\) to your project\./);
    assert.deepEqual(typed.filter((line) => line.length > 1), ['make the failing test in test.ps1 pass', 'now show me ../outside/secret.txt', 'try it from the shell', '/exit']);
  });

  it('carries no user name, machine path, key, token, email address or real session id', async () => {
    const { raw } = await transcript();
    const everything = JSON.stringify(raw);
    assert.doesNotMatch(everything, /C:\\\\Users|AppData|hn-demo-|XRIG|\/Users\/|\/home\/\w+/i);
    assert.doesNotMatch(everything, /sk-[a-z0-9]{8,}|ANTHROPIC_API_KEY|Bearer |BEGIN [A-Z ]*KEY/i);
    assert.doesNotMatch(everything, /@[a-z0-9-]+\.[a-z]{2,}/i, 'an email address');
    // The one id shown is a fixed stand-in, not a real session.
    assert.deepEqual([...everything.matchAll(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g)].map((match) => match[0]), ['3f2a9c1e-7b64-4d0a-9e51-0c8d2b6a47f3']);
  });
});
