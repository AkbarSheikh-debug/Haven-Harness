import { sanitizeForDisplay } from '@hn/core';
import type { TaskRequest } from '@hn/delegate';
import type { OpenSession } from './session-types.ts';

/** The presets: chains of the crew that a person starts by typing. */
export const PRESETS: Readonly<Record<string, readonly string[]>> = {
  implement: ['scout', 'planner', 'worker'],
  'scout-and-plan': ['scout', 'planner'],
  'implement-and-review': ['scout', 'planner', 'worker', 'reviewer'],
};

const BRIEFS: Readonly<Record<string, (task: string) => string>> = {
  scout: (task) => `Find everything needed for this task and report it with file paths and short quotes. Do not change anything.\n\nTask: ${task}`,
  planner: (task) => `Write a numbered plan for this task. Name each file to change, the change, and how to check it.\n\nTask: ${task}\n\nWhat the scout found:\n{previous}`,
  worker: (task) => `Carry out this plan for the task, then run the project's checks and report what changed and what you verified.\n\nTask: ${task}\n\nThe plan:\n{previous}`,
  reviewer: (task) => `Review the change made for this task against what was asked. List concrete problems with file and line, or say none were found.\n\nTask: ${task}\n\nWhat the worker reported:\n{previous}`,
};

/** The chain a preset runs for a task. The task is the person's own words; each later step gets the step before it as data. */
export function presetChain(name: string, task: string): TaskRequest[] | null {
  const roles = PRESETS[name];
  if (roles === undefined) return null;
  return roles.map((agent) => ({ agent, task: (BRIEFS[agent] ?? ((text: string) => text))(task) }));
}

/**
 * `/implement`, `/scout-and-plan`, `/implement-and-review`: runs the chain through the session's manager, so every
 * child is narrowed, budgeted and logged like one the model started, and a worker's edits are approved by the person
 * here through routing. Each step's report is shown, and the reports are added to the conversation as child data,
 * so the next thing the person types can build on them. Returns false when the line is not a preset.
 */
export async function runPreset(session: OpenSession, line: string, out: (text: string) => void, signal: AbortSignal = new AbortController().signal): Promise<boolean> {
  const match = /^\/([a-z-]+)(?:\s+([\s\S]*))?$/.exec(line.trim());
  const name = match?.[1] ?? '';
  if (PRESETS[name] === undefined) return false;
  const task = (match?.[2] ?? '').trim();
  if (task === '') {
    out(`Use: /${name} <what you want done>\n`);
    return true;
  }
  const chain = presetChain(name, task)!;
  out(`Running /${name}: ${chain.map((step) => step.agent).join(' -> ')}. Each child works in its own context; you approve any change a worker makes.\n`);
  let results;
  try {
    results = await session.subagents.chain(chain, { start: 'spawn' }, signal);
  } catch (error) {
    out(`${error instanceof Error ? error.message : String(error)}\n`);
    return true;
  }
  for (const [index, result] of results.entries()) {
    out(`\n--- step ${index + 1} of ${chain.length}: ${result.role} (${result.ok ? 'done' : 'did not finish'}) ---\n${sanitizeForDisplay(result.content)}\n`);
  }
  if (results.length < chain.length) out(`\nThe chain stopped after step ${results.length}, because that step did not finish.\n`);
  const summary = results.map((result, index) => `Step ${index + 1} (${result.role}):\n${result.content}`).join('\n\n');
  await session.agent.addContext(`The person ran /${name} for: ${task}\nThe children reported:\n${summary}`, 'child');
  return true;
}
