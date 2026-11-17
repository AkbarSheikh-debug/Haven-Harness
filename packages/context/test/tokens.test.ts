import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { SessionEvent } from '@hn/core';
import {
  anchorFrom,
  computeBudget,
  envelopeOf,
  estimateContext,
  estimateRow,
  estimateText,
  ROW_OVERHEAD,
  shouldFold,
} from '@hn/context';

function row(seq: number, text: string): SessionEvent {
  return { seq, ts: '2026-11-05T00:00:00.000Z', type: 'user/message', origin: 'user', data: { text } };
}

/** Text in several scripts, also used by the live calibration below. */
const SAMPLES: Record<string, string> = {
  english: 'The quick brown fox jumps over the lazy dog. Compaction keeps a summary; handoff keeps the goal. '.repeat(20),
  code: 'export function fitLoad(budget: Budget, parts: LoadParts): LoadFit {\n  const fixed = parts.system + parts.tools + parts.head;\n  if (room <= 0) throw new PrefixTooLargeError(fixed, budget.trigger);\n}\n'.repeat(10),
  chinese: '上下文压缩保留摘要，交接保留目标，子代理保留答案，编排器负责扩展。这是一个长期运行的会话。'.repeat(20),
  japanese: 'コンテキストの圧縮は要約を保持し、引き継ぎは目標を保持します。長時間のセッションです。'.repeat(20),
  korean: '컨텍스트 압축은 요약을 유지하고 인계는 목표를 유지합니다. 긴 세션입니다.'.repeat(20),
  russian: 'Сжатие контекста сохраняет сводку, передача сохраняет цель. Это длинная сессия.'.repeat(20),
  json: JSON.stringify({
    files: Array.from({ length: 30 }, (_, i) => ({ path: `src/module_${i}/index.ts`, size: i * 1234, hash: 'a1b2c3d4e5f6' })),
  }),
};

describe('token estimate', () => {
  it('does not use four characters per token for CJK, which undercounts it about fourfold', () => {
    const text = SAMPLES['chinese'] as string;
    assert.ok(estimateText(text) >= [...text].length, 'at least one token per CJK character');
  });

  it('counts empty text as nothing and every row with its overhead', () => {
    assert.equal(estimateText(''), 0);
    assert.equal(estimateRow(row(1, '')), ROW_OVERHEAD);
  });

  it('counts tool calls and tool results, not only text', () => {
    const call: SessionEvent = {
      seq: 2,
      ts: '2026-11-05T00:00:00.000Z',
      type: 'assistant/message',
      origin: 'model-derived',
      data: { text: '', toolCalls: [{ id: 'c1', name: 'read_file', args: { path: 'a/very/long/path/to/file.ts' } }] },
    };
    assert.ok(estimateRow(call) > ROW_OVERHEAD + 5);
  });

  it('grows with the text, so a bigger row is never cheaper', () => {
    for (const text of Object.values(SAMPLES)) {
      assert.ok(estimateText(text + text) >= estimateText(text));
    }
  });

  // Opt-in, because loading a 14B model next to the parallel suite runs this machine out of memory.
  it('live: never undercounts a real tokenizer (qwen3 through Ollama), and stays within 2x', async (t) => {
    const model = process.env['HN_LIVE_OLLAMA'] === '1' ? await ollamaModel() : null;
    if (model === null) {
      t.skip('set HN_LIVE_OLLAMA=1 with Ollama running');
      return;
    }
    try {
      for (const [name, text] of Object.entries(SAMPLES)) {
        const reference = await ollamaCount(model, text);
        const ratio = estimateText(text) / reference;
        assert.ok(ratio >= 1 && ratio <= 2, `${name}: estimate/reference = ${ratio.toFixed(2)}`);
      }
    } finally {
      await unload(model);
    }
  });
});

describe('usage anchor', () => {
  const envelope = envelopeOf({ model: 'm', system: 's', tools: [] });
  const rows = [row(1, 'hello'), row(2, 'reply'), row(3, 'a newer message with more words in it')];

  it('anchors on the provider count and estimates only the rows after it', () => {
    const anchor = anchorFrom({ input: 900, output: 100, cacheRead: 4_000, cacheWrite: 0 }, envelope, 2);
    const estimate = estimateContext({ rows, envelope, prefixTokens: 999_999, anchor });
    assert.equal(estimate.anchored, true);
    assert.equal(estimate.tokens, 5_000 + estimateRow(rows[2] as SessionEvent));
  });

  it('drops the anchor when the envelope changed or its row was folded away', () => {
    const anchor = anchorFrom({ input: 900, output: 100, cacheRead: 0, cacheWrite: 0 }, envelope, 2);
    const other = envelopeOf({ model: 'other', system: 's', tools: [] });
    assert.equal(estimateContext({ rows, envelope: other, prefixTokens: 10, anchor }).anchored, false);
    assert.equal(estimateContext({ rows: [rows[2] as SessionEvent], envelope, prefixTokens: 10, anchor }).anchored, false);
  });

  it('folds at T when anchored, but an unanchored estimate fires alone only near W - O', () => {
    const budget = computeBudget({ window: 200_000, modelMaxOutput: 32_000 });
    assert.deepEqual(shouldFold({ tokens: budget.trigger, anchored: true }, budget, 'full'), { fold: true, estimated: false });
    assert.equal(shouldFold({ tokens: budget.trigger, anchored: false }, budget, 'full').fold, false);
    assert.equal(shouldFold({ tokens: 160_000, anchored: false }, budget, 'full').fold, true);
  });

  it('uses the estimate at T on a model that never reports usage, and says so', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_096 });
    assert.deepEqual(shouldFold({ tokens: budget.trigger, anchored: false }, budget, 'none'), {
      fold: true,
      estimated: true,
    });
  });
});

const OLLAMA = 'http://127.0.0.1:11434';

async function ollamaModel(): Promise<string | null> {
  try {
    const response = await fetch(`${OLLAMA}/api/tags`, { signal: AbortSignal.timeout(1_500) });
    const body = (await response.json()) as { models?: { name: string }[] };
    return body.models?.find((entry) => entry.name.startsWith('qwen3'))?.name ?? null;
  } catch {
    return null;
  }
}

async function ollamaCount(model: string, prompt: string): Promise<number> {
  const response = await fetch(`${OLLAMA}/api/generate`, {
    method: 'POST',
    body: JSON.stringify({ model, prompt, raw: true, stream: false, options: { num_predict: 1, num_ctx: 4_096 } }),
    signal: AbortSignal.timeout(120_000),
  });
  const body = (await response.json()) as { prompt_eval_count?: number; error?: string };
  if (typeof body.prompt_eval_count !== 'number') throw new Error(body.error ?? 'no prompt_eval_count');
  return body.prompt_eval_count;
}

async function unload(model: string): Promise<void> {
  await fetch(`${OLLAMA}/api/generate`, { method: 'POST', body: JSON.stringify({ model, keep_alive: 0 }) }).catch(() => undefined);
}
