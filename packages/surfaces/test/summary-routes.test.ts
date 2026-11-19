import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { resolveCaps, type ModelProvider } from '@hn/provider';
import { summaryRoutes } from '../src/session.ts';

const provider = (route: string): ModelProvider => ({ route, complete: () => Promise.reject(new Error('unused')) });

describe('summary routes (Phase 3 decision 1)', () => {
  it('tries the cheap tier first on Anthropic, then the main model', () => {
    const routes = summaryRoutes(provider('anthropic'), 'claude-opus-5-5', resolveCaps('claude-opus-5-5'));
    assert.deepEqual(
      routes.map((route) => [route.source, route.model]),
      [
        ['summary', 'claude-haiku-5-5'],
        ['main', 'claude-opus-5-5'],
      ],
    );
  });

  it('uses the main model alone on a local route, or when the main model is already the cheap one', () => {
    const local = summaryRoutes(provider('ollama'), 'qwen3:14b', resolveCaps('qwen3:14b', { window: 32_000 }));
    assert.deepEqual(local.map((route) => route.source), ['main']);
    assert.equal(local[0]?.window, 32_000);
    const cheap = summaryRoutes(provider('anthropic'), 'claude-haiku-5-5', resolveCaps('claude-haiku-5-5'));
    assert.deepEqual(cheap.map((route) => route.model), ['claude-haiku-5-5']);
  });
});
