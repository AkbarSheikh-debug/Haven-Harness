export interface ModelCaps {
  readonly window: number;
  readonly windowIncludesOutput: boolean;
  readonly maxOutput: number;
  readonly caching: 'explicit' | 'auto' | 'none';
  readonly usage: 'full' | 'final' | 'none';
  readonly vision: boolean;
  readonly visionInToolResult: boolean;
  readonly parallelTools: boolean;
  readonly strictSchema: boolean;
  readonly reasoningReplay: boolean;
  readonly nativeTools: boolean;
  readonly structuredOutput: boolean;
  readonly prefill: boolean;
  readonly midConversationSystem: boolean;
  readonly thinkingBinding: boolean;
  readonly adaptiveThinking: boolean;
  readonly effort: boolean;
  readonly serverFallback: boolean;
}

/** What an unknown model gets. Every field assumes the least, so nothing is sent that could be refused. */
export const CONSERVATIVE_CAPS: ModelCaps = {
  window: 32_000,
  windowIncludesOutput: true,
  maxOutput: 4_096,
  caching: 'none',
  usage: 'none',
  vision: false,
  visionInToolResult: false,
  parallelTools: false,
  strictSchema: false,
  reasoningReplay: false,
  nativeTools: true,
  structuredOutput: false,
  prefill: false,
  midConversationSystem: false,
  thinkingBinding: false,
  adaptiveThinking: false,
  effort: false,
  serverFallback: false,
};

const CURRENT_CLAUDE: ModelCaps = {
  window: 1_000_000,
  windowIncludesOutput: false,
  maxOutput: 128_000,
  caching: 'explicit',
  usage: 'full',
  vision: true,
  visionInToolResult: true,
  parallelTools: true,
  strictSchema: true,
  reasoningReplay: true,
  nativeTools: true,
  structuredOutput: true,
  prefill: false,
  midConversationSystem: true,
  thinkingBinding: true,
  adaptiveThinking: true,
  effort: true,
  serverFallback: true,
};

const REGISTRY: ReadonlyMap<string, ModelCaps> = new Map([
  ['claude-fable-5-1', CURRENT_CLAUDE],
  ['claude-opus-5-5', CURRENT_CLAUDE],
  ['claude-sonnet-5-5', CURRENT_CLAUDE],
  ['claude-haiku-5-5', { ...CURRENT_CLAUDE, serverFallback: false }],
]);

/** Order: registry, then what the provider reported, then the user's override. */
export function resolveCaps(
  model: string,
  discovered: Partial<ModelCaps> = {},
  override: Partial<ModelCaps> = {},
): ModelCaps {
  return { ...(REGISTRY.get(model) ?? CONSERVATIVE_CAPS), ...discovered, ...override };
}
