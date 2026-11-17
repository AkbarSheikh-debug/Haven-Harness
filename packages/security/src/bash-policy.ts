import type { Effect } from './gate.ts';
import { SHELLS, WRITE_OPS, type BashParser, type ParsedCommand } from './bash.ts';
import { deniedCommandReason, hardlineReason, isSecretPath } from './rules.ts';

/** Turns the parser's command list into an effect class, a requiresHuman flag and a list of things that may never run. */

const EFFECT_ORDER: readonly Effect[] = ['observe', 'reversible', 'execution', 'external', 'irreversible'];
const worst = (a: Effect, b: Effect): Effect => (EFFECT_ORDER.indexOf(a) >= EFFECT_ORDER.indexOf(b) ? a : b);

const READ_ONLY = new Set(['ls', 'cat', 'head', 'tail', 'wc', 'pwd', 'echo', 'printf', 'true', 'false', 'date', 'whoami', 'id', 'uname', 'which', 'type', 'stat', 'file', 'diff', 'grep', 'rg', 'egrep', 'fgrep', 'sort', 'uniq', 'cut', 'tr', 'basename', 'dirname', 'realpath', 'readlink', 'du', 'df', 'tree', 'less', 'more', 'nl', 'tac', 'sleep', 'test', '[']);
const READ_ONLY_GIT = new Set(['status', 'diff', 'log', 'show', 'branch', 'rev-parse', 'ls-files', 'blame', 'describe', 'shortlog', 'rev-list', 'cat-file', 'ls-tree', 'grep']);
const NETWORK = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'sftp', 'rsync', 'ftp', 'telnet', 'gh', 'aws', 'gcloud', 'az', 'kubectl', 'invoke-webrequest', 'iwr']);
const NETWORK_GIT = new Set(['push', 'fetch', 'pull', 'clone', 'ls-remote', 'remote', 'submodule']);
/** Launching these from inside a session can reset taint, escape the box or open credentials, so a human always decides. */
const HUMAN_ONLY = new Set(['hn', 'claude', 'codex', 'docker', 'podman', 'security', 'secret-tool', 'cmdkey', 'sudo', 'doas', 'su']);
const NO_PARSER = new Set(['pwsh', 'powershell', 'cmd']);
const LOADER_VARIABLES = /^(LD_[A-Z_]+|DYLD_[A-Z_]+|PATH|NODE_OPTIONS|BASH_ENV|ENV|PROMPT_COMMAND|PYTHONPATH|PYTHONSTARTUP|RUBYOPT|PERL5OPT|GIT_[A-Z_]+|SHELLOPTS|IFS)=/;
const FORCE_FLAGS = /^(--force(-with-lease|-if-includes)?(=.*)?|-[a-z]*f[a-z]*)$/;

function gitSubcommand(args: readonly string[]): string | undefined {
  // Skip global options such as `-C dir` and `-c key=val` to find the verb.
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] as string;
    if (arg === '-C' || arg === '-c' || arg === '--git-dir' || arg === '--work-tree') i += 1;
    else if (!arg.startsWith('-')) return arg;
  }
  return undefined;
}

export interface BashAnalysis {
  readonly ok: boolean;
  readonly reason: string | null;
  readonly commands: readonly ParsedCommand[];
  /** The worst effect among the commands. Unparseable input is `execution`. */
  readonly effect: Effect;
  readonly requiresHuman: boolean;
  readonly reasons: readonly string[];
  /** Every literal argument and redirect target, for the path and secret checks. */
  readonly tokens: readonly string[];
  readonly writes: readonly string[];
  /** Set when this command may never run, in any mode. */
  readonly blocked: string | null;
  /** The part of `blocked` that comes from the hardline floor, kept apart so the audit can name the step. */
  readonly hardline: string | null;
}

/** Parses and classifies a bash command line. Any doubt makes it `execution`, never `observe`. */
export function analyzeBash(parser: BashParser, command: string): BashAnalysis {
  const parsed = parser.parse(command);
  const reasons: string[] = [];
  const tokens: string[] = [];
  const writes: string[] = [];
  let effect: Effect = 'observe';
  let requiresHuman = false;
  let blocked: string | null = null;
  let hardlineHit: string | null = null;
  const block = (why: string): void => {
    blocked ??= why;
  };

  if (!parsed.ok) {
    effect = 'execution';
    reasons.push(parsed.reason ?? 'The command could not be analysed, so it is treated as execution.');
  }

  for (const entry of parsed.commands) {
    const text = [entry.name, ...entry.args].join(' ');
    const hardline = hardlineReason(text);
    if (hardline !== null) {
      hardlineHit ??= hardline;
      block(hardline);
    }
    const denied = deniedCommandReason(text);
    if (denied !== null) block(denied);

    for (const token of [...entry.args, ...entry.redirects.map((redirect) => redirect.target)]) {
      tokens.push(token);
      if (isSecretPath(token)) block(`reading or writing ${token} is not allowed`);
    }
    for (const redirect of entry.redirects) {
      if (WRITE_OPS.has(redirect.op) && redirect.target !== '/dev/null') {
        writes.push(redirect.target);
        effect = worst(effect, 'reversible');
      }
      if (redirect.dynamic) {
        reasons.push('A redirect target is computed at run time.');
        effect = worst(effect, 'execution');
      }
    }
    for (const assignment of entry.assignments) {
      if (LOADER_VARIABLES.test(assignment)) {
        requiresHuman = true;
        reasons.push(`${assignment.split('=')[0]} changes how programs start.`);
      }
    }

    effect = worst(effect, classify(entry, reasons, (human) => (requiresHuman ||= human)));
    if (entry.name === 'git' && gitSubcommand(entry.args) === 'push' && entry.args.some((arg) => FORCE_FLAGS.test(arg) || arg.startsWith('+'))) block('force push is not allowed');
  }

  for (const names of parsed.pipelines) {
    const shellAt = names.findIndex((name, index) => index > 0 && SHELLS.has(name));
    if (shellAt > 0 && names.slice(0, shellAt).some((name) => name === 'curl' || name === 'wget')) block('piping a download into a shell is not allowed');
  }

  return { ok: parsed.ok, reason: parsed.reason, commands: parsed.commands, effect, requiresHuman, reasons, tokens, writes, blocked, hardline: hardlineHit };
}

function classify(entry: ParsedCommand, reasons: string[], setHuman: (value: boolean) => void): Effect {
  if (entry.dynamic && entry.name === '') {
    reasons.push('A command name is computed at run time.');
    return 'execution';
  }
  if (HUMAN_ONLY.has(entry.name)) {
    setHuman(true);
    reasons.push(`${entry.name} can change what the session may do, so a person decides.`);
    return 'execution';
  }
  if (NO_PARSER.has(entry.name)) {
    reasons.push(`${entry.name} cannot be parsed yet, so it is treated as execution.`);
    return 'execution';
  }
  if (entry.name === 'git') {
    const verb = gitSubcommand(entry.args);
    if (verb !== undefined && NETWORK_GIT.has(verb)) return verb === 'push' ? 'irreversible' : 'external';
    return verb !== undefined && READ_ONLY_GIT.has(verb) && !entry.dynamic ? 'observe' : 'execution';
  }
  if (['npm', 'pnpm', 'yarn', 'cargo', 'twine'].includes(entry.name) && entry.args.includes('publish')) return 'irreversible';
  if (NETWORK.has(entry.name)) return 'external';
  if (entry.name === 'find') {
    const risky = entry.args.some((arg) => ['-exec', '-execdir', '-ok', '-okdir', '-delete', '-fprint', '-fprintf', '-fls'].includes(arg));
    return risky ? 'execution' : 'observe';
  }
  if (READ_ONLY.has(entry.name) && !entry.dynamic) return 'observe';
  return 'execution';
}
