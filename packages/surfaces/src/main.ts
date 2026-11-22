import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { DEFAULTS, resolvePaths } from '@hn/config';
import { ParentChannel, nonceStore, verifyGrant, type GrantBody } from '@hn/delegate';
import { createMemberTools } from '@hn/orchestrate';
import { loadOrCreateLogKey } from '@hn/session';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { KeyStore } from '@hn/provider';
import { doctorExitCode, formatDoctor, runDoctor } from './doctor.ts';
import { runDreamCommand } from './dream.ts';
import { EXIT_FAILED, EXIT_REFUSED, formatFatal, runPrint } from './print.ts';
import { runRepl } from './repl.ts';
import { runTui } from './tui.ts';
import { runControlCommand, runFleetCommand, runRalphCommand } from './commands.ts';
import { serveRpc } from './rpc.ts';
import { serveAcp } from './acp.ts';
import { runReportCommand } from './report.ts';
import { startReplayServe, startServe } from './serve.ts';
import { runScheduleCommand } from './schedules.ts';
import { runSupervisorCommand } from './supervisor.ts';
import { recipeContext, resolveRecipeImage, runSandboxCommand } from './recipes.ts';
import { runPrepareCommand } from './prepare-door.ts';
import { loadTasks, runBench } from './bench.ts';
import { latestSession, type CliOptions } from './session.ts';
import { auditDoor, serveAuditDoor } from './audit-main.ts';
import { loadTeamLogin, runApprovalsCommand, runLoginCommand } from './team.ts';
import { loadBrokerConfig, runPolicyTool, startBroker } from '@hn/broker';
import { runUpdateCommand } from './update-door.ts';
import { runSetupCommand } from './setup-door.ts';
import { runTrustCommand } from './trust-cmd.ts';
import { loadPriceFile } from './cost-summary.ts';

/** The installed release's version, or where this copy runs from. */
async function releaseVersion(): Promise<string> {
  const root = process.env['HN_RELEASE_ROOT'];
  if (root === undefined || root === '') return 'from source';
  try {
    return (JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8')) as { version: string }).version;
  } catch {
    return 'unknown';
  }
}

function protoDisabled(): boolean {
  const probe: Record<string, unknown> = {};
  try {
    return probe['__proto__'] === undefined;
  } catch {
    return true;
  }
}

if (!protoDisabled()) {
  process.stderr.write('hn must be started through its launcher, which disables __proto__.\n');
  process.exit(EXIT_REFUSED);
}

// Before anything else runs, so nothing spawned later can inherit a key.
let keys = KeyStore.capture();
// Nothing this process starts may find the parent's channel through its environment.
delete process.env['NODE_CHANNEL_FD'];
delete process.env['NODE_CHANNEL_SERIALIZATION_MODE'];

/** What a parent passes on standard input: the keys, and for a granted child the signed grant and the channel token. */
interface Handoff {
  readonly keys: KeyStore;
  readonly grant: string | null;
  readonly channel: string | null;
}

/** The hand-off is either the plain key object (a read-only child) or `{"hn-handoff": 1, keys, grant, channel}`. */
function parseHandoff(text: string): Handoff {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { keys: KeyStore.fromHandoff('{}'), grant: null, channel: null };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || (parsed as Record<string, unknown>)['hn-handoff'] !== 1) {
    return { keys: KeyStore.fromHandoff(text), grant: null, channel: null };
  }
  const record = parsed as Record<string, unknown>;
  const text_ = (value: unknown): string | null => (typeof value === 'string' && value !== '' ? value : null);
  return { keys: KeyStore.fromHandoff(JSON.stringify(record['keys'] ?? {})), grant: text_(record['grant']), channel: text_(record['channel']) };
}

/** The parent's key hand-off: all of standard input, read once. */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

/** What a verified grant sets. It replaces the read-only default of a nested hn and nothing else. */
function grantOptions(grant: GrantBody): Partial<CliOptions> {
  return {
    mode: grant.mode,
    ...(grant.mode === 'dont-ask' ? { allow: grant.allow } : {}),
    maxIterations: grant.maxIterations,
    tokenBudget: grant.tokenBudget,
    rolePrompt: grant.role.body,
    ...(grant.tools === null ? {} : { tools: grant.tools }),
    sessionId: grant.child,
    ...(grant.team === undefined ? {} : { teamMember: grant.team.name }),
    ...(grant.project === undefined ? {} : { childProject: grant.project }),
    descriptor: { role: grant.role.name, roleHash: grant.role.hash, tools: grant.tools, maxIterations: grant.maxIterations, budget: grant.tokenBudget, channel: grant.channel },
  };
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      print: { type: 'string', short: 'p' },
      mode: { type: 'string' },
      'after-plan': { type: 'string' },
      verify: { type: 'string' },
      'keys-stdin': { type: 'boolean' },
      'inherit-taint': { type: 'string' },
      'max-iterations': { type: 'string' },
      model: { type: 'string' },
      'base-url': { type: 'string' },
      window: { type: 'string' },
      'num-ctx': { type: 'string' },
      allow: { type: 'string' },
      sandbox: { type: 'string' },
      image: { type: 'string' },
      'external-sandbox': { type: 'boolean' },
      'benchmark-container': { type: 'boolean' },
      resume: { type: 'string' },
      continue: { type: 'boolean' },
      json: { type: 'boolean' },
      replay: { type: 'boolean' },
      follow: { type: 'boolean' },
      audit: { type: 'boolean' },
      'dry-run': { type: 'boolean' },
      teams: { type: 'boolean' },
      results: { type: 'string' },
      workers: { type: 'string' },
      check: { type: 'string' },
      until: { type: 'string' },
      max: { type: 'string' },
      name: { type: 'string' },
      rrule: { type: 'string' },
      start: { type: 'string' },
      version: { type: 'boolean' },
      oracle: { type: 'boolean' },
      team: { type: 'boolean' },
      sig: { type: 'string' },
      from: { type: 'string' },
      'prompt-origin': { type: 'string' },
      user: { type: 'string' },
      session: { type: 'string' },
      type: { type: 'string' },
      since: { type: 'string' },
      after: { type: 'string' },
      limit: { type: 'string' },
      to: { type: 'string' },
      out: { type: 'string' },
      pub: { type: 'string' },
      pins: { type: 'string' },
      'key-file': { type: 'string' },
      state: { type: 'string' },
      purpose: { type: 'string' },
      root: { type: 'string' },
      trust: { type: 'string' },
      roster: { type: 'string' },
    },
  });
  if (values.version === true) {
    process.stdout.write(`hn ${await releaseVersion()}\n`);
    return 0;
  }

  if (positionals[0] === 'doctor' && values.print === undefined) {
    const checks = await runDoctor({ repoRoot: fileURLToPath(new URL('../../../', import.meta.url)), ...(values.image === undefined ? {} : { image: values.image }) });
    process.stdout.write(sanitizeForDisplay(formatDoctor(checks)));
    return doctorExitCode(checks);
  }

  // The person's own prices, if they gave a file: every cost report below uses them.
  await loadPriceFile(resolvePaths().home, (text) => process.stderr.write(text));

  const nestedCommand = process.env['HN_PARENT_SESSION'] !== undefined && process.env['HN_PARENT_SESSION'] !== '';
  if (values.print === undefined) {
    const handled = await runControlCommand({ positionals, nested: nestedCommand, out: (text) => process.stdout.write(text) });
    if (handled !== null) return handled;
  }
  if (values.print === undefined) {
    const defaults = { model: values.model ?? DEFAULTS.mainModel, ...(values['base-url'] === undefined ? {} : { baseUrl: values['base-url'] }), ...(values.window === undefined ? {} : { window: Number(values.window) }) };
    const context = { positionals, nested: nestedCommand, out: (text: string) => process.stdout.write(text), keys, defaults, flags: values };
    // Instances of a supervisor get the same model flags this hn was given.
    const args = [...(values.model === undefined ? [] : ['--model', values.model]), ...(values['base-url'] === undefined ? [] : ['--base-url', values['base-url']]), ...(values.window === undefined ? [] : ['--window', values.window])];
    const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
    const handled = (await runFleetCommand(context)) ?? (await runRalphCommand(context)) ?? (await runScheduleCommand(context)) ?? (await runSupervisorCommand({ ...context, args })) ?? (await runSandboxCommand({ positionals, nested: nestedCommand, out: context.out, repoRoot })) ?? (await runPrepareCommand({ positionals, nested: nestedCommand, out: context.out, ...(values.image === undefined ? {} : { image: values.image }), dryRun: values['dry-run'] === true }));
    if (handled !== null) return handled;
  }
  // Terminal-Bench-format tasks in the Windows box (decision 14). The model flags are passed to each agent run.
  if (positionals[0] === 'bench' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn bench cannot be run from inside an hn session.');
    if (positionals[1] === undefined) throw new HnError('BAD_COMMAND', 'hn bench <tasks folder> [--oracle] [--results file]');
    const tasks = await loadTasks(positionals[1]);
    const flags = [...(values.model === undefined ? [] : ['--model', values.model]), ...(values['base-url'] === undefined ? [] : ['--base-url', values['base-url']]), ...(values.window === undefined ? [] : ['--window', values.window]), ...(values['num-ctx'] === undefined ? [] : ['--num-ctx', values['num-ctx']])];
    const results = await runBench({ tasks, mode: values.oracle === true ? 'oracle' : 'hn', args: flags, env: process.env, repoRoot: fileURLToPath(new URL('../../../', import.meta.url)), ...(values.results === undefined ? {} : { results: values.results }), out: (text) => process.stdout.write(text) });
    return results.every((result) => result.passed) ? 0 : 1;
  }
  // The web door (decision 12): loopback only. The token is shown here, on the terminal, and never put in a URL.
  if (positionals[0] === 'serve' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn serve cannot be started from inside an hn session.');
    // The team's audit in a browser (Phase 14).
    if (values.audit === true) return serveAuditDoor(values, resolvePaths().home, false);
    // The replay and audit screen on its own: no model session, no key, read-only. It lists this folder's recorded sessions.
    if (values.replay === true) {
      const replayServed = await startReplayServe({ cwd: process.cwd(), ...(values.follow === true ? { follow: true } : {}) });
      process.stdout.write(`hn is showing the sessions recorded for this folder at ${replayServed.url}replay
This page can only read logs: it starts no session and runs nothing.
Open it and paste this token (it is not in the address, on purpose):
${replayServed.token}
Ctrl+C to stop.
`);
      await new Promise<void>((resolve) => process.once('SIGINT', () => resolve()));
      await replayServed.close();
      return 0;
    }
    const served = await startServe({ keys, cwd: process.cwd(), defaults: { model: values.model ?? DEFAULTS.mainModel, ...(values['base-url'] === undefined ? {} : { baseUrl: values['base-url'] }), ...(values.window === undefined ? {} : { window: Number(values.window) }) } });
    process.stdout.write(`hn is serving ${served.url}
Open it and paste this token (it is not in the address, on purpose):
${served.token}
Ctrl+C to stop.
`);
    await new Promise<void>((resolve) => process.once('SIGINT', () => resolve()));
    await served.close();
    return 0;
  }
  // The ACP door for editors (decision 11). Refused inside a session for the same reason as hn rpc.
  if (positionals[0] === 'acp' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn acp cannot be started from inside an hn session.');
    await serveAcp(process.stdin, process.stdout, { keys, defaults: { model: values.model ?? DEFAULTS.mainModel, ...(values['base-url'] === undefined ? {} : { baseUrl: values['base-url'] }), ...(values.window === undefined ? {} : { window: Number(values.window) }), ...(values['num-ctx'] === undefined ? {} : { numCtx: Number(values['num-ctx']) }) } });
    return 0;
  }
  // A session's report (Phase 12): what it did, from its tamper-evident log, for a pull request. Read-only, and not from inside a session.
  if (positionals[0] === 'report' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn report cannot be run from inside an hn session.');
    if (positionals[1] === undefined) throw new HnError('BAD_COMMAND', 'hn report <session id> [--json]');
    return runReportCommand({ sessionId: positionals[1], workdir: process.cwd(), json: values.json === true, out: (text) => process.stdout.write(text) });
  }
  // Updates (Phase 8, decision 12): only from a person's command line, never from inside a session or from project files.
  if (positionals[0] === 'update' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn update cannot be run from inside an hn session.');
    const paths = resolvePaths();
    return (await runUpdateCommand({ positionals, ...(values.sig === undefined ? {} : { sig: values.sig }), ...(values.roster === undefined ? {} : { roster: values.roster }), home: paths.home, logKey: paths.logKey, env: process.env, out: (text) => process.stdout.write(text) })) ?? 1;
  }
  // Which signing keys this machine trusts (Phase 15): only from a person's command line.
  if (positionals[0] === 'trust' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn trust cannot be run from inside an hn session.');
    return (await runTrustCommand({ positionals, ...(values.purpose === undefined ? {} : { purpose: values.purpose }), env: process.env, out: (text) => process.stdout.write(text) })) ?? 1;
  }
  // Fetching or installing the sandbox helper (Phase 9): only from a person's command line.
  if (positionals[0] === 'setup' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn setup cannot be run from inside an hn session.');
    return (await runSetupCommand({ positionals, ...(values.from === undefined ? {} : { from: values.from }), home: resolvePaths().home, env: process.env, out: (text) => process.stdout.write(text) })) ?? 1;
  }
  // The team's audit (Phase 14): searching and checking what the broker recorded.
  if (positionals[0] === 'audit' && values.print === undefined) return auditDoor(positionals, values, resolvePaths().home, nestedCommand);
  // Team mode (Phase 8): logging in to a broker, and running one. Never from inside a session.
  if ((positionals[0] === 'login' || positionals[0] === 'logout' || positionals[0] === 'broker' || positionals[0] === 'approvals') && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', `hn ${positionals[0]} cannot be run from inside an hn session.`);
    if (positionals[0] === 'approvals') return (await runApprovalsCommand({ positionals, home: resolvePaths().home, out: (text) => process.stdout.write(text) })) ?? 1;
    if (positionals[0] !== 'broker') return (await runLoginCommand({ positionals, home: resolvePaths().home, out: (text) => process.stdout.write(text) })) ?? 1;
    const tool = await runPolicyTool(positionals, (text) => process.stdout.write(text));
    if (tool !== null) return tool;
    if (positionals[1] === undefined) throw new HnError('BAD_COMMAND', 'hn broker <config.json> | keygen <folder> | sign <tree.json> <key.pem> <key id> <bundle.json> | audit-key <state> <folder> | rotate-audit-key <state> <folder>');
    const broker = await startBroker({ config: await loadBrokerConfig(positionals[1]), keys });
    process.stdout.write(`hn broker is listening on ${broker.url}. Ctrl+C to stop.\n`);
    await new Promise<void>((resolve) => process.once('SIGINT', () => resolve()));
    await broker.close();
    return 0;
  }
  // The JSON-RPC door (decision 4). A session's tool could otherwise start one to open looser sessions.
  if (positionals[0] === 'rpc' && values.print === undefined) {
    if (nestedCommand) throw new HnError('NESTED_HN', 'hn rpc cannot be started from inside an hn session.');
    const defaults = {
      model: values.model ?? DEFAULTS.mainModel,
      ...(values['base-url'] === undefined ? {} : { baseUrl: values['base-url'] }),
      ...(values.window === undefined ? {} : { window: Number(values.window) }),
      ...(values['num-ctx'] === undefined ? {} : { numCtx: Number(values['num-ctx']) }),
    };
    await serveRpc(process.stdin, process.stdout, { keys, cwd: process.cwd(), defaults });
    return 0;
  }

  const workdir = process.cwd();
  const sessionId = values.resume ?? (values.continue === true ? await latestSession(workdir) : undefined);
  const prompt = values.print ?? (positionals.length > 0 ? positionals.join(' ') : undefined);
  const headless = values.print !== undefined;
  // A harness started by a tool of another harness could otherwise begin with clean taint and a looser mode, so it may only look.
  const nested = process.env['HN_PARENT_SESSION'] !== undefined && process.env['HN_PARENT_SESSION'] !== '';
  if (nested && values.mode !== undefined && values.mode !== 'read-only' && values.mode !== 'plan') {
    throw new HnError('NESTED_HN', `This hn was started from inside another hn session, so it may only run in read-only or plan mode, not ${values.mode}. Otherwise a tool could start a fresh harness to escape the first one's limits.`);
  }
  // Flags only a parent harness passes to its child. From anyone else they would be a way to forge a child.
  const childFlags = values['keys-stdin'] === true || values['inherit-taint'] !== undefined || values['max-iterations'] !== undefined;
  if (childFlags && !nested) throw new HnError('NOT_A_CHILD', '--keys-stdin, --inherit-taint and --max-iterations are only for a child session started by hn.');
  if (values['inherit-taint'] !== undefined && values['inherit-taint'] !== 'untrusted') throw new HnError('BAD_TAINT', '--inherit-taint takes only: untrusted.');
  const handoff = values['keys-stdin'] === true ? parseHandoff(await readStdin()) : null;
  if (handoff !== null) keys = handoff.keys;
  // The parent's id becomes part of the child's log path, so only a plain session id is accepted.
  if (nested && !/^[A-Za-z0-9-]{1,64}$/.test(process.env['HN_PARENT_SESSION'] as string)) {
    throw new HnError('BAD_PARENT', 'HN_PARENT_SESSION is not a session id, so this nested hn will not start.');
  }
  // A grant is the only way a nested hn runs above read-only, and only if it verifies with the log key (decision 1).
  let grant: GrantBody | null = null;
  if (handoff?.grant !== null && handoff?.grant !== undefined) {
    if (values.mode !== undefined) throw new HnError('BAD_GRANT', 'A granted child takes its mode from the grant, never from --mode.');
    const paths = resolvePaths();
    const check = await verifyGrant(handoff.grant, {
      key: await loadOrCreateLogKey(paths.logKey),
      parent: process.env['HN_PARENT_SESSION'] as string,
      useNonce: nonceStore(join(paths.home, 'grants', 'used')),
    });
    if (!check.ok) throw new HnError('BAD_GRANT', `This child's grant was refused: ${check.why}. It does not start.`);
    grant = check.grant;
  }
  if (values.sandbox !== undefined && values.sandbox !== 'container' && values.sandbox !== 'native') throw new HnError('BAD_SANDBOX', `--sandbox ${values.sandbox} is not available. The kinds are: container, native.`);
  // Without --image the image comes from the project's recipe, only as a person approved it; this is checked on every
  // start, a resume included, so a recipe edited between sessions is never used without a person (decision 9).
  const image = values.sandbox === 'container' && values.image === undefined ? await resolveRecipeImage(await recipeContext(workdir, process.env, fileURLToPath(new URL('../../../', import.meta.url)))) : values.image;
  const options: CliOptions = {
    workdir,
    // A run with nobody watching is yolo inside a verified sandbox (slide 14), and can only look anywhere else.
    mode: values.mode ?? (nested ? 'read-only' : headless ? (values.sandbox !== undefined ? 'yolo' : 'read-only') : 'safe'),
    // A nested hn may only look, so leaving plan mode cannot be its way out of that limit.
    ...(nested ? { afterPlan: 'read-only' } : values['after-plan'] === undefined ? {} : { afterPlan: values['after-plan'] }),
    ...(values.verify === undefined ? {} : { verify: values.verify }),
    ...(values.sandbox === 'container' && image !== undefined ? { sandbox: { kind: 'container' as const, image } } : values.sandbox === 'native' ? { sandbox: { kind: 'native' as const } } : {}),
    ...(values['external-sandbox'] === true ? { externalSandbox: true } : {}),
    ...(values['benchmark-container'] === true ? { benchmarkContainer: true } : {}),
    model: values.model ?? DEFAULTS.mainModel,
    ...(values['base-url'] === undefined ? {} : { baseUrl: values['base-url'] }),
    ...(values.team === true ? { team: await loadTeamLogin(resolvePaths().home) } : {}),
    ...(values.window === undefined ? {} : { window: Number(values.window) }),
    ...(values['num-ctx'] === undefined ? {} : { numCtx: Number(values['num-ctx']) }),
    ...(values.allow === undefined ? {} : { allow: values.allow.split(',') }),
    ...(sessionId === undefined ? {} : { sessionId }),
    ...(nested ? { childOf: process.env['HN_PARENT_SESSION'] as string } : {}),
    ...(values['inherit-taint'] === 'untrusted' ? { inheritTaint: true } : {}),
    ...(values['max-iterations'] === undefined ? {} : { maxIterations: Math.max(1, Math.min(500, Number(values['max-iterations']) || 1)) }),
    ...(grant === null ? {} : grantOptions(grant)),
    // Agent teams are experimental (11.5): on with --teams or HN_TEAMS=1, for a root session only.
    ...(!nested && (values.teams === true || process.env['HN_TEAMS'] === '1') ? { teams: true } : {}),
  };

  if (positionals[0] === 'dream' && positionals.length === 1 && !headless && !nested) return runDreamCommand({ ...options, dryRun: values['dry-run'] === true }, keys);
  // A granted child with a channel asks its parent's person, through the parent's gate, and shares the parent's rate limit.
  const channel =
    grant?.channel === true && handoff?.channel !== null && handoff?.channel !== undefined && typeof process.send === 'function'
      ? new ParentChannel(handoff.channel, {
          // A parent that died leaves a broken pipe: sending then must fail quietly, never crash the child.
          send: (message) => {
            if (process.connected !== true) throw new Error('The parent is gone.');
            process.send?.(message, undefined, {}, (error: Error | null) => void error);
          },
          onMessage: (listener) => process.on('message', listener),
          onClose: (listener) => process.on('disconnect', listener),
        })
      : null;
  if (grant?.channel === true && channel === null) throw new HnError('BAD_GRANT', 'This child was granted a channel to its parent but has none, so it does not start.');
  if (headless && prompt !== undefined) {
    // Only ever a way to say the prompt is less trusted than a person's own words. No value raises trust.
    if (values['prompt-origin'] !== undefined && values['prompt-origin'] !== 'event') throw new HnError('BAD_ORIGIN', '--prompt-origin can only be "event": a prompt read from outside is never more trusted than that.');
    try {
      // A team member gets its team tools and its inbox over the same channel (11.5).
      const member = channel !== null && grant?.team !== undefined ? { memberTools: createMemberTools((request) => channel.team(request)), inbox: (deliver: (text: string, origin: string) => void) => channel.onInbox(deliver) } : {};
      return await runPrint({ ...options, prompt, json: values.json === true, ...(values['prompt-origin'] === 'event' ? { promptOrigin: 'event' as const } : {}), ...(channel === null ? {} : { routed: channel.approve, rateGate: channel.rate }), ...member }, keys);
    } finally {
      // The pipe keeps a child alive; it is closed once the report is written.
      if (channel !== null) process.disconnect?.();
    }
  }
  // The full-screen door (decision 13): the same session as the REPL.
  if (positionals[0] === 'tui' && positionals.length === 1 && !nested) return runTui(options, keys);
  return runRepl(options, keys);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(formatFatal(error, (text) => keys.redact(text)));
    process.exitCode = error instanceof HnError || error instanceof TypeError ? EXIT_REFUSED : EXIT_FAILED;
  },
);
