/**
 * The GitHub Action turns a labelled issue into a pull request. Everything about the issue is text from outside:
 * anyone can open one. Only the label is a decision, and only a person with write access can add it. This reads the
 * event GitHub wrote to disk (never an expression pasted into a shell command, the classic way an issue title becomes
 * code), checks it is the one event this Action is for, and caps what it carries on.
 */

export const MAX_TITLE_CHARS = 300;
export const MAX_BODY_CHARS = 20_000;
export const MAX_EVENT_BYTES = 5 * 1024 * 1024;

export interface Task {
  readonly repo: string;
  readonly defaultBranch: string;
  readonly issueNumber: number;
  /** Written by whoever opened the issue. Untrusted. */
  readonly title: string;
  /** Written by whoever opened the issue. Untrusted. */
  readonly body: string;
  /** The person who added the label: the one decision-maker here. */
  readonly labeler: string;
  readonly issueAuthor: string;
}

export type Trigger = { readonly task: Task } | { readonly refused: string };

// GitHub owners are letters, digits and hyphens. A repository may have dots and underscores, but is never "." or "..".
const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const BRANCH = /^[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$/;
/** A branch name that cannot be read as an option, a path escape or a lock file. */
const validBranch = (value: unknown): value is string => typeof value === 'string' && BRANCH.test(value) && !value.includes('..') && !value.includes('//') && !value.endsWith('/') && !value.endsWith('.lock');

const record = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});

/** Is this the event the Action is for, and what does it ask? A refusal says why, in words safe to print. */
export function readTrigger(payload: unknown, eventName: string, label: string): Trigger {
  if (eventName !== 'issues') return { refused: `This Action only runs for the "issues" event, not "${eventName.slice(0, 40)}".` };
  const event = record(payload);
  if (event['action'] !== 'labeled') return { refused: 'This Action only runs when a label is added.' };
  if (record(event['label'])['name'] !== label) return { refused: `The label added was not "${label}".` };
  const issue = record(event['issue']);
  const number = issue['number'];
  if (typeof number !== 'number' || !Number.isSafeInteger(number) || number < 1) return { refused: 'The event has no issue number.' };
  if (issue['pull_request'] !== undefined) return { refused: 'That is a pull request, not an issue.' };
  if (issue['state'] !== 'open') return { refused: 'The issue is not open.' };
  const repository = record(event['repository']);
  const repo = repository['full_name'];
  if (typeof repo !== 'string' || !REPO.test(repo)) return { refused: 'The event names no valid repository.' };
  const branch = repository['default_branch'];
  if (!validBranch(branch)) return { refused: 'The event names no valid default branch.' };
  const sender = record(event['sender']);
  const labeler = sender['login'];
  if (typeof labeler !== 'string' || !LOGIN.test(labeler) || sender['type'] !== 'User') return { refused: 'The label was not added by a person (a bot or an unknown account added it).' };
  const author = record(issue['user'])['login'];
  const title = typeof issue['title'] === 'string' ? issue['title'] : '';
  const body = typeof issue['body'] === 'string' ? issue['body'] : '';
  return {
    task: {
      repo,
      defaultBranch: branch,
      issueNumber: number,
      title: title.slice(0, MAX_TITLE_CHARS),
      body: body.slice(0, MAX_BODY_CHARS),
      labeler,
      issueAuthor: typeof author === 'string' && LOGIN.test(author) ? author : 'unknown',
    },
  };
}

/** What a task file must look like when a later step reads it back: written by the gate, but never believed blindly. */
export function readTask(value: unknown): Task | null {
  const task = record(value);
  const number = task['issueNumber'];
  if (typeof task['repo'] !== 'string' || !REPO.test(task['repo'])) return null;
  if (!validBranch(task['defaultBranch'])) return null;
  if (typeof number !== 'number' || !Number.isSafeInteger(number) || number < 1) return null;
  if (typeof task['labeler'] !== 'string' || !LOGIN.test(task['labeler'])) return null;
  if (typeof task['title'] !== 'string' || typeof task['body'] !== 'string' || typeof task['issueAuthor'] !== 'string') return null;
  return { repo: task['repo'], defaultBranch: task['defaultBranch'], issueNumber: number, title: task['title'].slice(0, MAX_TITLE_CHARS), body: task['body'].slice(0, MAX_BODY_CHARS), labeler: task['labeler'], issueAuthor: task['issueAuthor'].slice(0, 40) };
}
