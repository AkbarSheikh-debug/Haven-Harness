import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { REDACTED, Redactor, containsSentinel, sentinelWriteProblem } from '@hn/security';

const KEY = 'sk-ant-api03-Zq8vN2mXk4Lp7TrW9yBc3Dh6Fj1Gs5Aa';

describe('redaction', () => {
  it('replaces secrets by shape', () => {
    const redactor = new Redactor();
    const text = [
      `key ${KEY}`,
      'aws AKIAIOSFODNN7EXAMPLE',
      'gh ghp_abcdefghijklmnopqrstuvwxyz0123456789',
      'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r',
    ].join('\n');
    const out = redactor.redact(text);
    for (const secret of [KEY, 'AKIAIOSFODNN7EXAMPLE', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'eyJhbGci']) {
      assert.ok(!out.includes(secret), `${secret} survived`);
    }
    assert.ok(containsSentinel(out));
  });

  it('removes a whole private key block', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdef\n-----END RSA PRIVATE KEY-----';
    assert.equal(new Redactor().redact(`before\n${pem}\nafter`), `before\n${REDACTED}\nafter`);
  });

  it('keeps the name and drops the value of a secret-looking assignment', () => {
    const out = new Redactor().redact('DB_PASSWORD=hunter2hunter2 and {"api_key": "abc123def456"}');
    assert.equal(out, `DB_PASSWORD=${REDACTED} and {"api_key": "${REDACTED}"}`);
  });

  it('keeps a redacted JSON row valid JSON when a secret-named key holds a number or ends an object', () => {
    const redactor = new Redactor();
    for (const row of ['{"tokenBudget":3000000,"x":1}', '{"data":{"auth":12345678}}', '{"secretList":[1234567]}', '{"maxTokens": 128000}']) {
      const out = redactor.redact(row);
      assert.doesNotThrow(() => JSON.parse(out), out);
      assert.ok(out.includes(REDACTED), out);
      assert.doesNotMatch(out, /3000000|12345678|1234567|128000/);
    }
    assert.equal(redactor.redact('TOKEN=abcdef123456'), `TOKEN=${REDACTED}`, 'shell text keeps its plain form');
  });

  it('strips URL userinfo', () => {
    const out = new Redactor().redact('clone https://ghp_token123:x-oauth@github.com/a/b.git and https://tok@host/p');
    assert.equal(out, `clone https://${REDACTED}@github.com/a/b.git and https://${REDACTED}@host/p`);
  });

  it('catches a known secret in raw, percent, hex and base64 forms', () => {
    const secret = 'correct-horse-battery-staple-9';
    const redactor = new Redactor();
    redactor.addSecret(secret);
    const spellings = [
      secret,
      encodeURIComponent(`${secret}/&`),
      Buffer.from(secret).toString('hex'),
      Buffer.from(`user:${secret}`).toString('base64'),
      Buffer.from(`xx${secret}tail`).toString('base64'),
      Buffer.from(secret).toString('base64url'),
    ];
    for (const spelling of spellings) {
      const out = redactor.redact(`value=${spelling}`);
      assert.ok(containsSentinel(out), `not caught: ${spelling}`);
      assert.ok(!out.includes(spelling.slice(8, 24)), `a fragment of ${spelling} survived`);
    }
  });

  it('ignores a known secret that is too short to match safely', () => {
    const redactor = new Redactor();
    redactor.addSecret('abc');
    assert.equal(redactor.redact('abc abc'), 'abc abc');
  });

  it('redacts keys and values deep inside a value and leaves other things alone', () => {
    const out = new Redactor().redactDeep({ [KEY]: [{ note: `use ${KEY}` }, 7, null, true] });
    // Results have no prototype, so a key such as __proto__ can never reach Object.prototype.
    assert.equal(Object.getPrototypeOf(out), null);
    assert.deepEqual(JSON.parse(JSON.stringify(out)), { [REDACTED]: [{ note: `use ${REDACTED}` }, 7, null, true] });
  });

  it('catches a secret split across stream chunks and emits everything else in order', () => {
    const redactor = new Redactor();
    redactor.addSecret(KEY);
    const stream = redactor.stream();
    const filler = 'word '.repeat(120).trim();
    const text = `${filler} ${KEY} ${filler}`;
    let out = '';
    for (let at = 0; at < text.length; at += 7) out += stream.push(text.slice(at, at + 7));
    out += stream.end();
    assert.ok(!out.includes(KEY.slice(0, 20)), 'a fragment of the key leaked');
    assert.equal(out, `${filler} ${REDACTED} ${filler}`);
  });

  it('catches a shaped secret however a long text is chunked', () => {
    const filler = 'lorem ipsum dolor '.repeat(40);
    const text = `${filler}${KEY} ${filler}`;
    for (let size = 1; size <= 41; size += 1) {
      const stream = new Redactor().stream();
      let out = '';
      for (let at = 0; at < text.length; at += size) out += stream.push(text.slice(at, at + size));
      out += stream.end();
      assert.equal(out, `${filler}${REDACTED} ${filler}`, `chunk size ${size}`);
    }
  });

  it('catches a shaped secret at every possible chunk boundary', () => {
    const text = `prefix ${KEY} suffix`;
    for (let cut = 1; cut < text.length; cut += 1) {
      const stream = new Redactor().stream();
      const out = stream.push(text.slice(0, cut)) + stream.push(text.slice(cut)) + stream.end();
      assert.equal(out, `prefix ${REDACTED} suffix`, `cut at ${cut}`);
    }
  });
});

describe('the redaction sentinel on writes', () => {
  it('refuses a write that adds a sentinel the file did not have', () => {
    assert.match(sentinelWriteProblem('A=1\n', `A=${REDACTED}\n`) ?? '', /destroy the real value/);
  });

  it('allows a write that keeps the sentinels the file already holds', () => {
    assert.equal(sentinelWriteProblem(`A=${REDACTED}\n`, `A=${REDACTED}\nB=2\n`), null);
  });

  it('allows ordinary writes and new files', () => {
    assert.equal(sentinelWriteProblem(null, 'hello'), null);
  });

  it('refuses a new file that contains the sentinel', () => {
    assert.notEqual(sentinelWriteProblem(null, REDACTED), null);
  });
});
