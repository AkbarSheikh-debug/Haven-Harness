import { DEFAULTS } from '@hn/config';
import type { SummaryRoute } from '@hn/loop';
import {
  createAnthropicProvider,
  createOllamaProvider,
  createOpenAICompatibleProvider,
  resolveCaps,
  type KeyStore,
  type ModelCaps,
  type ModelProvider,
} from '@hn/provider';
import type { CliOptions } from './session.ts';
import { teamProvider } from './team.ts';

/**
 * Where summaries come from: on Anthropic the cheap tier first, then the main model; elsewhere the main
 * model alone. The static summary always follows, so a fold never depends on any of them.
 */
export function summaryRoutes(provider: ModelProvider, model: string, caps: ModelCaps): SummaryRoute[] {
  const main: SummaryRoute = { source: 'main', provider, model, window: caps.window };
  if (provider.route !== 'anthropic' || model === DEFAULTS.summaryModel) return [main];
  const cheap = resolveCaps(DEFAULTS.summaryModel);
  return [{ source: 'summary', provider, model: DEFAULTS.summaryModel, window: cheap.window }, main];
}

export function chooseProvider(options: CliOptions, keys: KeyStore, session = 'none'): { provider: ModelProvider; model: string; caps: ModelCaps } {
  // Team mode: the laptop holds no model key; every call goes to the broker, which decides and holds the key.
  if (options.team !== undefined) {
    const caps = options.window === undefined ? resolveCaps(options.model) : resolveCaps(options.model, { window: options.window });
    return { model: options.model, caps, provider: teamProvider(options.team, session) };
  }
  const local = options.model.startsWith('ollama/');
  if (!local && options.baseUrl === undefined) {
    return {
      model: options.model,
      caps: resolveCaps(options.model),
      provider: createAnthropicProvider({ apiKey: () => keys.get('ANTHROPIC_API_KEY'), caps: resolveCaps }),
    };
  }
  const model = options.model.replace(/^ollama\//, '');
  const window = options.window ?? 32_000;
  const caps = resolveCaps(model, { window, maxOutput: Math.min(8_192, Math.floor(window / 2)), usage: 'final', caching: 'auto' });
  if (local) {
    return {
      model,
      caps,
      provider: createOllamaProvider({
        baseUrl: options.baseUrl ?? 'http://127.0.0.1:11434',
        caps: () => caps,
        numCtx: options.numCtx ?? window,
      }),
    };
  }
  return {
    model,
    caps,
    provider: createOpenAICompatibleProvider({
      route: 'openai-compatible',
      baseUrl: options.baseUrl as string,
      caps: () => caps,
      ...(keys.has('OPENAI_API_KEY') ? { apiKey: () => keys.get('OPENAI_API_KEY') } : {}),
    }),
  };
}
