import type { Agent } from '@hn/loop';

/** `/compact`: one fold now, between turns, ignoring the cooldown. */
export async function compactCommand(agent: Agent, out: (text: string) => void): Promise<void> {
  const outcome = await agent.compact();
  const said: Record<string, string> = {
    folded: 'Older turns were replaced by a summary.',
    pruned: 'Old tool output was trimmed; no summary was needed.',
    noop: 'Nothing could be folded yet.',
    failed: 'Compaction failed. The session continues unchanged.',
    aborted: 'Compaction was stopped.',
  };
  out(`${said[outcome] ?? outcome}\n`);
}

/** `/micro` folds one exchange now; `/micro on|off` sets the rhythm for the turns that follow. */
export async function microCommand(agent: Agent, line: string, out: (text: string) => void): Promise<void> {
  if (line !== '/micro') {
    agent.setMicro(line === '/micro on');
    const on = 'on: one exchange is folded after each turn, so the window stays flat. Each pass costs one cache miss';
    const off = 'off: the window grows and is folded when it fills (sawtooth)';
    out(`Micro-compaction is ${agent.microOn ? on : off}.\n`);
    return;
  }
  const said: Record<string, string> = {
    folded: 'The oldest exchange was replaced by a short summary.',
    failed: 'The micro fold failed; the exchange is unchanged.',
    skipped: 'That exchange failed three times and was skipped.',
    none: 'There is no earlier exchange to fold yet.',
  };
  out(`${said[await agent.micro()] ?? ''}\n`);
}
