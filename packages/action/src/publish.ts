import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Task } from './event.ts';
import type { GitHubApi } from './github.ts';
import { inspectPatch, type PatchProblem } from './patch.ts';
import { git } from './proc.ts';

const MAX_REPORT_BYTES = 60_000;

export type Outcome =
  | { readonly kind: 'pull-request'; readonly number: number; readonly url: string; readonly files: readonly string[] }
  | { readonly kind: 'refused'; readonly problems: readonly PatchProblem[] }
  | { readonly kind: 'empty' }
  | { readonly kind: 'incomplete'; readonly end: string };

export interface PublishOptions {
  /** From the gate job, which ran no model. The only source of what the issue is. */
  readonly task: Task;
  /** The agent job's files: `hn.patch`, `report.md`, `result.json`. Treated as untrusted. */
  readonly resultDir: string;
  /** A clean checkout of the default branch, with a token that may push. */
  readonly repoDir: string;
  readonly api: GitHubApi;
  readonly runId: string;
  readonly remote?: string;
  readonly protectedPaths?: readonly string[];
}

/** Model- or file-written text, as inline code only. */
const code = (text: string): string => `\`${text.replace(/[\u0000-\u001f\u007f`|]/g, "'").slice(0, 120)}\``;

const read = (path: string): Promise<Buffer | null> => readFile(path).catch(() => null);

/**
 * Files the box held back or did not import, which are NOT in this pull request. Listing them is the point: a change the
 * agent made that a person has to decide about is never dropped quietly. Paths and reasons are shown as inert code.
 */
function heldBack(handback: unknown): string[] {
  const record = typeof handback === 'object' && handback !== null ? (handback as Record<string, unknown>) : {};
  const rows: string[] = [];
  for (const [label, list] of [['held back, needs a person', record['held']], ['not imported', record['notImported']]] as const) {
    if (!Array.isArray(list)) continue;
    for (const entry of list.slice(0, 20)) {
      const item = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>) : {};
      if (typeof item['path'] === 'string') rows.push(`- ${code(item['path'])}: ${label}${typeof item['why'] === 'string' ? ` (${code(item['why'])})` : ''}`);
    }
  }
  return rows.length === 0 ? [] : ['**Changes the agent made that are NOT in this pull request, because a person has to decide about them:**', '', ...rows, ''];
}

/**
 * The third job, and the only one with a write token. It runs no model and no command the model chose. It checks the
 * patch (what it touches, how big, what kind), applies it to a clean checkout, pushes a branch and opens a pull request
 * whose description is the session's report. A pull request opened with the workflow's own token does not start other
 * workflows, so nothing the agent wrote runs in CI until a person looks at it and decides.
 */
export async function runPublish(options: PublishOptions): Promise<Outcome> {
  const { task, api } = options;
  const resultBytes = await read(join(options.resultDir, 'result.json'));
  let result: Record<string, unknown> = {};
  try {
    result = JSON.parse(resultBytes?.toString('utf8') ?? '{}') as Record<string, unknown>;
  } catch {
    result = {};
  }
  if (result['complete'] !== true) {
    const end = typeof result['end'] === 'string' ? result['end'].replace(/[^A-Za-z_-]/g, '').slice(0, 30) : 'failed';
    await api.comment(task.repo, task.issueNumber, `hn did not finish this (it stopped: ${code(end || 'failed')}), so no pull request was opened. The session's own report is in the workflow run.`);
    return { kind: 'incomplete', end };
  }
  const patch = (await read(join(options.resultDir, 'hn.patch'))) ?? Buffer.alloc(0);
  if (patch.length === 0) {
    await api.comment(task.repo, task.issueNumber, 'hn finished without changing any file, so no pull request was opened.');
    return { kind: 'empty' };
  }
  const inspected = await inspectPatch(patch, { ...(options.protectedPaths === undefined ? {} : { protectedPaths: options.protectedPaths }) });
  if (!inspected.ok) {
    const lines = inspected.problems.slice(0, 20).map((problem) => `- ${code(problem.path)}: ${problem.rule}`);
    await api.comment(
      task.repo,
      task.issueNumber,
      ['hn made a change, but it was **not turned into a pull request**, because a person has to decide about this part:', '', ...lines, '', 'The patch is attached to the workflow run for a person to read and apply by hand if they agree.'].join('\n'),
    );
    return { kind: 'refused', problems: inspected.problems };
  }

  const remote = options.remote ?? 'origin';
  const safeRun = /^[0-9A-Za-z]{1,20}$/.test(options.runId) ? options.runId : 'x';
  const branch = `hn/issue-${task.issueNumber}-${safeRun}`;
  const here = { cwd: options.repoDir };
  const must = async (what: string, args: readonly string[], input?: Buffer): Promise<void> => {
    const ran = await git(args, { ...here, ...(input === undefined ? {} : { input }) });
    if (ran.status !== 0) throw new Error(`${what} failed: ${ran.stderr.trim().slice(0, 300)}`);
  };
  await must('Making the branch', ['switch', '-c', branch]);
  // `--index` stages as it applies; git itself refuses a path that goes through a symbolic link or out of the repository.
  await must('Applying the patch', ['apply', '--index', '--whitespace=nowarn', '-'], patch);
  await must('Committing', ['-c', 'user.name=hn', '-c', 'user.email=hn@users.noreply.github.com', 'commit', '-q', '-m', `hn: resolve #${task.issueNumber}`, '-m', 'Made by Haven Harness in a verified box, from an issue a maintainer labelled. See the pull request for the session report.']);
  await must('Pushing the branch', ['push', remote, `HEAD:refs/heads/${branch}`]);

  const reportBytes = (await read(join(options.resultDir, 'report.md'))) ?? Buffer.from('_No report was produced._');
  const report = reportBytes.subarray(0, MAX_REPORT_BYTES).toString('utf8');
  const body = [
    `Resolves #${task.issueNumber}.`,
    '',
    `Made by Haven Harness because ${code(task.labeler)} labelled the issue. Review it like any other pull request. **CI does not run on it automatically**: GitHub does not start workflows for a pull request opened with a workflow's own token, so nothing the agent wrote has run in CI. Push to the branch or re-run checks yourself once you have read the diff.`,
    '',
    `Changed ${inspected.files.length} file(s), +${inspected.additions} -${inspected.deletions}. Every change was checked first: no protected path (\`.github\`, hooks, package-manager config), no symbolic link, submodule or binary file, and within the size limits.`,
    '',
    ...heldBack(result['handback']),
    report,
  ].join('\n');
  const pr = await api.createPullRequest(task.repo, { title: `hn: resolve #${task.issueNumber}`, head: branch, base: task.defaultBranch, body: body.slice(0, 64_000) });
  await api.comment(task.repo, task.issueNumber, `hn opened ${pr.url} for this. Please review it before merging.`);
  return { kind: 'pull-request', number: pr.number, url: pr.url, files: inspected.files };
}
