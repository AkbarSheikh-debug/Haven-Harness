import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { MAX_EVENT_BYTES, readTrigger, type Task } from './event.ts';
import { WRITER_ROLES, type GitHubApi } from './github.ts';

export interface GateOptions {
  readonly eventPath: string;
  readonly eventName: string;
  /** The label that asks for a change, from the workflow's own file. */
  readonly label: string;
  readonly api: GitHubApi;
  /** Where `task.json` is written when the answer is yes. */
  readonly outDir: string;
}

export type GateResult = { readonly proceed: true; readonly task: Task } | { readonly proceed: false; readonly reason: string };

/**
 * The first job: should anything run at all? It runs no model and no code from the repository, so it can hold a token.
 * Yes only for a label, added by a person, with write access to this repository, on an open issue. The decision uses the
 * repository's own record of the labeler's role: the label's name proves nothing, since anyone with triage rights can
 * add one, and the issue's text and author are nobody's authority. An API failure is a refusal that fails the job loudly.
 */
export async function runGate(options: GateOptions): Promise<GateResult> {
  const info = await stat(options.eventPath);
  if (info.size > MAX_EVENT_BYTES) return { proceed: false, reason: 'The event payload is larger than this Action reads.' };
  const payload: unknown = JSON.parse(await readFile(options.eventPath, 'utf8'));
  const trigger = readTrigger(payload, options.eventName, options.label);
  if ('refused' in trigger) return { proceed: false, reason: trigger.refused };
  const role = await options.api.roleOf(trigger.task.repo, trigger.task.labeler);
  if (!WRITER_ROLES.has(role)) return { proceed: false, reason: `The label was added by ${trigger.task.labeler}, whose role here is "${role}". Only a person with write access can ask hn to make a change.` };
  await mkdir(options.outDir, { recursive: true });
  await writeFile(join(options.outDir, 'task.json'), `${JSON.stringify(trigger.task)}\n`);
  return { proceed: true, task: trigger.task };
}
