import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { KeyStore, ProviderError, parseRetryAfter, retryDelayMs, withRetry } from '@hn/provider';
import { SessionWriter, loadOrCreateLogKey, parseLog } from '@hn/session';
import { withTempDir } from '@hn/testkit';

describe('retry', () => {
  const failing = (reasons: ProviderError[]) => {
    let calls = 0;
    return {
      get calls() {
        return calls;
      },
      run: async (): Promise<string> => {
        const next = reasons[calls];
        calls += 1;
        if (next !== undefined) throw next;
        return 'ok';
      },
    };
  };
  const noSleep = async (): Promise<void> => undefined;

  it('retries what can succeed and stops when it does', async () => {
    const call = failing([new ProviderError('overloaded', 'busy'), new ProviderError('timeout', 'slow')]);
    assert.equal(await withRetry(call.run, { sleep: noSleep }), 'ok');
    assert.equal(call.calls, 3);
  });

  it('gives up after 5 attempts', async () => {
    const call = failing(Array.from({ length: 9 }, () => new ProviderError('server_error', 'down')));
    await assert.rejects(withRetry(call.run, { sleep: noSleep }), ProviderError);
    assert.equal(call.calls, 5);
  });

  for (const reason of ['auth', 'permission', 'quota_exhausted', 'bad_request', 'context_too_long', 'aborted'] as const) {
    it(`never retries ${reason}`, async () => {
      const call = failing([new ProviderError(reason, 'no')]);
      await assert.rejects(withRetry(call.run, { sleep: noSleep }), ProviderError);
      assert.equal(call.calls, 1);
    });
  }

  it('lets Retry-After win over backoff, and caps backoff at 60 seconds', () => {
    assert.equal(retryDelayMs(3, 7000, () => 0.5), 7000);
    assert.equal(retryDelayMs(3, undefined, () => 0.5), 8500);
    assert.equal(retryDelayMs(20, undefined, () => 0), 60_000);
  });

  it('reads both forms of Retry-After', () => {
    assert.equal(parseRetryAfter('12'), 12_000);
    assert.equal(parseRetryAfter('Wed, 21 Oct 2026 07:28:10 GMT', Date.parse('Wed, 21 Oct 2026 07:28:00 GMT')), 10_000);
    assert.equal(parseRetryAfter('soon'), undefined);
  });

  it('stops waiting at once when the user aborts', async () => {
    const controller = new AbortController();
    const call = failing([new ProviderError('rate_limited', 'wait', { retryAfterMs: 60_000 })]);
    const pending = withRetry(call.run, { signal: controller.signal });
    setTimeout(() => controller.abort(), 5);
    await assert.rejects(pending, (error: ProviderError) => error.reason === 'aborted');
  });
});

describe('keys', () => {
  it('moves keys out of the environment, so a child process cannot see them', () => {
    const env: NodeJS.ProcessEnv = { ANTHROPIC_API_KEY: 'sk-secret-value', PATH: process.env['PATH'] };
    const store = KeyStore.capture(env);
    assert.equal(store.get('ANTHROPIC_API_KEY'), 'sk-secret-value');
    assert.equal(env['ANTHROPIC_API_KEY'], undefined);

    const child = spawnSync(process.execPath, ['-p', 'process.env.ANTHROPIC_API_KEY ?? "absent"'], { env, encoding: 'utf8' });
    assert.equal(child.stdout.trim(), 'absent');
  });

  it('reports a missing key as an auth failure', () => {
    assert.throws(() => KeyStore.capture({}).get('OPENAI_API_KEY'), (error: ProviderError) => error.reason === 'auth');
  });

  it('never lets a key reach the session log', async () => {
    const secret = `sk-${randomBytes(16).toString('hex')}`;
    const store = KeyStore.capture({ ANTHROPIC_API_KEY: secret });
    await withTempDir(async (directory) => {
      const key = randomBytes(32);
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({
        path,
        sessionId: 's',
        key,
        redact: (row) => store.redact(row),
      });
      writer.append('llm/retry', { message: `401 for key ${secret}` });
      await writer.close();

      const log = parseLog(await readFile(path), key);
      assert.equal(log.events[0]?.data['message'], '401 for key [REDACTED]');
      assert.equal(JSON.stringify(log.events).includes(secret), false);
    });
  });
});

describe('log key', () => {
  it('creates 32 bytes once and then reuses them', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'nested', 'log.key');
      const first = await loadOrCreateLogKey(path);
      assert.equal(first.length, 32);
      assert.deepEqual(await loadOrCreateLogKey(path), first);
    });
  });

  it('refuses a damaged key rather than replacing it', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log.key');
      await loadOrCreateLogKey(path);
      const { writeFile } = await import('node:fs/promises');
      await writeFile(path, 'short');
      await assert.rejects(loadOrCreateLogKey(path), /not a 32 byte key/);
    });
  });
});
