import { isSecretPath } from '@hn/security';
import { describeOutput } from './job-tools.ts';
import { waitFor, type JobManager } from './jobs.ts';
import { ToolProblem, stringArg, type ToolContext, type ToolDefinition, type ToolResult } from './types.ts';

export const DEFAULT_BASH_TIMEOUT_MS = 120_000;
export const MAX_BASH_TIMEOUT_MS = 600_000;
export const MAX_STREAM_BYTES = 64_000;
export const MAX_GREP_MATCHES = 250;
export const MAX_LIST_FILES = 500;

/** Enforced inside rg and again on its results, so a walk of the tree cannot return a secret. */
export const SECRET_GLOBS = [
  '.env',
  '.env.*',
  '.ssh',
  '.aws',
  '.gnupg',
  '.npmrc',
  '.netrc',
  '.git-credentials',
  '*.pem',
  '*.key',
  '*.p12',
  '*.pfx',
  'id_rsa*',
  'id_ed25519*',
  'id_ecdsa*',
  'terraform.tfstate*',
];

function clip(bytes: Buffer): { text: string; clipped: boolean } {
  if (bytes.length <= MAX_STREAM_BYTES) return { text: bytes.toString('utf8'), clipped: false };
  const half = MAX_STREAM_BYTES / 2;
  const omitted = bytes.length - MAX_STREAM_BYTES;
  const head = bytes.subarray(0, half).toString('utf8');
  const tail = bytes.subarray(-half).toString('utf8');
  return { text: `${head}\n... ${omitted} bytes omitted ...\n${tail}`, clipped: true };
}

async function bashResult(args: Readonly<Record<string, unknown>>, context: ToolContext) {
  const timeoutMs = Math.min(MAX_BASH_TIMEOUT_MS, (args['timeout_ms'] as number | undefined) ?? DEFAULT_BASH_TIMEOUT_MS);
  const result = await context.ops.bash.exec(stringArg(args, 'command'), {
    cwd: context.workdir,
    timeoutMs,
    signal: context.signal,
  });
  const stdout = clip(result.stdout);
  const stderr = clip(result.stderr);
  const sections = [
    stdout.text.trimEnd(),
    stderr.text.trim() === '' ? '' : `[stderr]\n${stderr.text.trimEnd()}`,
    stdout.clipped ? `[full stdout: ${await context.ops.spill.spill(`${context.callId}.stdout.txt`, result.stdout)}]` : '',
    stderr.clipped ? `[full stderr: ${await context.ops.spill.spill(`${context.callId}.stderr.txt`, result.stderr)}]` : '',
    result.clipped ? '[output passed the 64 MiB capture limit and was cut]' : '',
  ].filter((section) => section !== '');
  return { result, body: sections.join('\n'), timeoutMs };
}

/**
 * bash through the job manager: a command that outlives its timeout is not killed, it becomes a background
 * job the model can read and stop. A command that ends in time leaves no job behind.
 */
async function bashAsJob(args: Readonly<Record<string, unknown>>, context: ToolContext, jobs: JobManager): Promise<ToolResult> {
  const command = stringArg(args, 'command');
  const timeoutMs = Math.min(MAX_BASH_TIMEOUT_MS, (args['timeout_ms'] as number | undefined) ?? DEFAULT_BASH_TIMEOUT_MS);
  const job = jobs.start('bash', command, context.workdir);
  if (typeof job === 'string') return { content: job, isError: true, origin: 'harness' };
  if (args['run_in_background'] === true) {
    jobs.register(job);
    return { content: `Started background job ${job.id}. Read it with job_output and stop it with job_kill.`, origin: 'harness' };
  }
  const outcome = await waitFor(job, timeoutMs, context.signal);
  if (outcome === 'cancelled') {
    jobs.signal(job, 'kill');
    jobs.forget(job.id);
    return { content: 'CANCELLED: the user stopped this command.', isError: true, cancelled: true };
  }
  if (outcome === 'timeout') {
    jobs.register(job);
    const soFar = describeOutput(job, jobs.take(job));
    const note = `Still running after ${timeoutMs} ms, so it was kept as background job ${job.id} rather than killed. Read it with job_output, stop it with job_kill.`;
    return { content: `${soFar}\n\n${note}`, origin: 'tool-output' };
  }
  jobs.forget(job.id);
  const out = job.process.stdout.bytes;
  const err = job.process.stderr.bytes;
  const stdout = clip(out);
  const stderr = clip(err);
  const sections = [
    stdout.text.trimEnd(),
    stderr.text.trim() === '' ? '' : `[stderr]\n${stderr.text.trimEnd()}`,
    stdout.clipped ? `[full stdout: ${await context.ops.spill.spill(`${context.callId}.stdout.txt`, out)}]` : '',
    stderr.clipped ? `[full stderr: ${await context.ops.spill.spill(`${context.callId}.stderr.txt`, err)}]` : '',
    job.process.stdout.clipped || job.process.stderr.clipped ? '[output passed the capture limit and was cut]' : '',
  ].filter((section) => section !== '');
  const output = sections.length === 0 ? '(no output)' : sections.join('\n');
  if (job.code !== 0) return { content: `${output}\n\nExit code ${job.code}.`, isError: true, origin: 'tool-output' };
  return { content: output, origin: 'tool-output' };
}

function bashTool(shell?: string): ToolDefinition {
  return {
    name: 'bash',
    description: `Run a shell command in the project folder. Returns stdout, stderr and the exit code.${shell === undefined ? '' : ` ${shell}`}`,
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        description: { type: 'string', description: 'What this command does, in a few words.' },
        timeout_ms: { type: 'integer', description: `Default ${DEFAULT_BASH_TIMEOUT_MS}, at most ${MAX_BASH_TIMEOUT_MS}.` },
        run_in_background: { type: 'boolean', description: 'Start it as a background job and return at once, for servers and watchers.' },
      },
      required: ['command'],
      additionalProperties: false,
    },
    effect: 'execution',
    concurrencySafe: false,
    paths: () => [],
    command: (args) => stringArg(args, 'command'),
    summary: (args) => stringArg(args, 'command'),
    async execute(args, context) {
      if (context.jobs !== undefined) return bashAsJob(args, context, context.jobs);
      const { result, body, timeoutMs } = await bashResult(args, context);
      if (result.cancelled) return { content: 'CANCELLED: the user stopped this command.', isError: true, cancelled: true };
      const output = body === '' ? '(no output)' : body;
      if (result.timedOut) {
        return { content: `${output}\n\nThe command was stopped after ${timeoutMs} ms. Raise timeout_ms, or run something smaller.`, isError: true, origin: 'tool-output' };
      }
      if (result.code !== 0) return { content: `${output}\n\nExit code ${result.code}.`, isError: true, origin: 'tool-output' };
      return { content: output, origin: 'tool-output' };
    },
  };
}

function checkSearchArg(value: string, name: string): void {
  if (value.startsWith('-')) throw new ToolProblem('BAD_ARGUMENT', `${name} cannot start with a dash.`);
}

function grepTool(): ToolDefinition {
  return {
    name: 'grep',
    description: 'Search file contents with a regular expression. Respects .gitignore.',
    parameters: {
      type: 'object',
      properties: {
        pattern: { type: 'string' },
        path: { type: 'string', description: 'Folder to search, relative to the project.' },
        glob: { type: 'string', description: 'Only search matching files, such as *.ts.' },
        ignore_case: { type: 'boolean' },
      },
      required: ['pattern'],
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: (args) => [{ path: (args['path'] as string | undefined) ?? '.', write: false }],
    summary: (args) => `grep ${stringArg(args, 'pattern')}`,
    async execute(args, { workdir, ops }) {
      const glob = args['glob'] as string | undefined;
      if (glob !== undefined) checkSearchArg(glob, 'glob');
      const lines = await ops.search.grep({
        pattern: stringArg(args, 'pattern'),
        root: join(workdir, (args['path'] as string | undefined) ?? '.'),
        limit: MAX_GREP_MATCHES,
        ignoreCase: args['ignore_case'] === true,
        excludeGlobs: SECRET_GLOBS,
        ...(glob === undefined ? {} : { glob }),
      });
      const safe = lines.filter((line) => !isSecretPath(line.split(':', 1)[0] ?? ''));
      if (safe.length === 0) return { content: 'No matches.', origin: 'workspace' };
      const shown = safe.slice(0, MAX_GREP_MATCHES).join('\n');
      const note = lines.length > MAX_GREP_MATCHES ? `\n\n(Showing the first ${MAX_GREP_MATCHES}. Narrow the pattern.)` : '';
      return { content: shown + note, origin: 'workspace' };
    },
  };
}

function join(root: string, path: string): string {
  return path === '.' ? root : `${root}/${path}`;
}

function listTool(): ToolDefinition {
  return {
    name: 'list_files',
    description: 'List files under a folder. Respects .gitignore.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Folder to list, relative to the project.' },
        glob: { type: 'string' },
      },
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: (args) => [{ path: (args['path'] as string | undefined) ?? '.', write: false }],
    summary: (args) => `list ${(args['path'] as string | undefined) ?? '.'}`,
    async execute(args, { workdir, ops }) {
      const glob = args['glob'] as string | undefined;
      if (glob !== undefined) checkSearchArg(glob, 'glob');
      const files = await ops.search.listFiles({
        root: join(workdir, (args['path'] as string | undefined) ?? '.'),
        limit: MAX_LIST_FILES,
        excludeGlobs: SECRET_GLOBS,
        ...(glob === undefined ? {} : { glob }),
      });
      const safe = files.filter((file) => !isSecretPath(file)).sort();
      if (safe.length === 0) return { content: 'No files.', origin: 'workspace' };
      const note = files.length > MAX_LIST_FILES ? `\n\n(Showing the first ${MAX_LIST_FILES}. Narrow the path.)` : '';
      return { content: safe.slice(0, MAX_LIST_FILES).join('\n') + note, origin: 'workspace' };
    },
  };
}

/** `shell` describes the shell when it is not bash; it is fixed for the session, so the tools array never changes. */
export function createShellTools(shell?: string): ToolDefinition[] {
  return [bashTool(shell), grepTool(), listTool()];
}
