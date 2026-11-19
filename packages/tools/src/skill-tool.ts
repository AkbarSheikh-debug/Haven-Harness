import type { Origin } from '@hn/core';
import type { HarnessExecResult } from './harness-exec.ts';
import type { ToolDefinition } from './types.ts';

/** What the tool needs to know about one loaded skill. */
export interface SkillEntry {
  readonly name: string;
  readonly description: string;
  readonly body: string;
  readonly checklist: readonly string[];
  readonly validate: string | null;
  /** SKILL.md's path and SHA-256: an approval of `validate:` binds to both. */
  readonly path: string;
  readonly hash: string;
}

export interface SkillCatalog {
  find(name: string): SkillEntry | null;
  names(): readonly string[];
  /** A bundled file of the skill, through the safe reader, or null. */
  readFile(name: string, relativePath: string): Promise<string | null>;
}

/** Runs a project-written command the way every harness spawn runs: a gated `HarnessExec` call. */
export type ValidateRunner = (
  command: string,
  scripts: Readonly<Record<string, string>>,
  signal: AbortSignal,
) => Promise<HarnessExecResult>;

/** At most this many runs of one skill's `validate:` command before the loop gives up on it. */
export const MAX_VALIDATE_RUNS = 3;
/** Rounds that can change files. A round of reads only does not run `validate:` again. */
const CHANGING_TOOLS = new Set(['write_file', 'edit_file', 'apply_patch', 'bash', 'pwsh']);
const MAX_VALIDATE_OUTPUT = 4_000;

interface Active {
  readonly skill: SkillEntry;
  runs: number;
}

export interface ValidateMessage {
  readonly text: string;
  readonly origin: Origin;
}

/**
 * The feedback-loop body shape (slide 22): once a skill with `validate:` is loaded, its command runs after
 * every round that changed something, until it passes or three runs are spent. Each run is a gated
 * `HarnessExec` call bound to the command and to SKILL.md's hash, so below tier 3 a person approves each one,
 * and editing the skill voids any approval.
 */
export class SkillValidator {
  readonly #run: ValidateRunner;
  #active: Active | null = null;

  constructor(run: ValidateRunner) {
    this.#run = run;
  }

  activate(skill: SkillEntry): void {
    if (skill.validate !== null) this.#active = { skill, runs: 0 };
  }

  get active(): string | null {
    return this.#active?.skill.name ?? null;
  }

  /** After a tool round: a message for the model, or null when nothing ran. */
  async afterRound(toolNames: readonly string[], signal: AbortSignal): Promise<ValidateMessage | null> {
    const active = this.#active;
    if (active === null || !toolNames.some((name) => CHANGING_TOOLS.has(name))) return null;
    const { skill } = active;
    active.runs += 1;
    const command = skill.validate as string;
    const result = await this.#run(command, { [skill.path]: skill.hash }, signal);
    const output = result.output.length > MAX_VALIDATE_OUTPUT ? result.output.slice(-MAX_VALIDATE_OUTPUT) : result.output;
    if (result.ok) {
      this.#active = null;
      return { text: `validate passed for skill ${skill.name} (\`${command}\`).`, origin: 'tool-output' };
    }
    if (result.code === null) {
      this.#active = null;
      const why = result.reason ?? 'refused';
      return { text: `validate for skill ${skill.name} did not run: ${why}. Do not claim it passed.`, origin: 'harness' };
    }
    if (active.runs >= MAX_VALIDATE_RUNS) {
      this.#active = null;
      const text = `validate for skill ${skill.name} failed ${active.runs} times and will not run again. Tell the user it is still failing.\n${output}`;
      return { text, origin: 'tool-output' };
    }
    const text = `validate for skill ${skill.name} failed (run ${active.runs} of ${MAX_VALIDATE_RUNS}): ${result.reason ?? ''}\n${output}\nFix it; it runs again after your next change.`;
    return { text, origin: 'tool-output' };
  }
}

function describeBody(skill: SkillEntry): string {
  const parts = [`<skill name="${skill.name}">`, skill.body.trim(), '</skill>'];
  if (skill.checklist.length > 0) {
    parts.push(
      `This skill is a checklist of ${skill.checklist.length} steps. Track them with todo_write and do them in order:`,
      ...skill.checklist.map((item, index) => `${index + 1}. ${item}`),
    );
  }
  if (skill.validate !== null) {
    parts.push(
      `This skill has a check: \`${skill.validate}\`. The harness runs it after each round that changes files, up to ${MAX_VALIDATE_RUNS} times, until it passes. Below tier 3 a person approves each run.`,
    );
  }
  return parts.join('\n');
}

const fail = (content: string) => ({ content, isError: true, origin: 'harness' as const });

/**
 * `skill` (deferred): level 2 is the body, level 3 is one bundled file named by `file`. Level 1, the name and
 * description, is already in the catalogue row. Reading a skill never runs anything.
 */
export function createSkillTool(catalog: SkillCatalog, validator: SkillValidator): ToolDefinition {
  return {
    name: 'skill',
    deferred: true,
    description:
      'Load a skill from the catalogue: its instructions, or with `file` one of its bundled reference files. Use it when a skill description fits the task.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The skill name from the catalogue.' },
        file: { type: 'string', description: 'A file the skill links to, such as reference.md.' },
      },
      required: ['name'],
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: (args) => `skill ${String(args['name'])}${typeof args['file'] === 'string' ? ` ${args['file']}` : ''}`,
    async execute(args) {
      const name = typeof args['name'] === 'string' ? args['name'] : '';
      const skill = catalog.find(name);
      if (skill === null) {
        const known = catalog.names();
        return fail(`No skill is named ${JSON.stringify(name.slice(0, 64))}. Loaded skills: ${known.length === 0 ? 'none' : known.join(', ')}.`);
      }
      const file = args['file'];
      if (typeof file === 'string' && file !== '') {
        const text = await catalog.readFile(skill.name, file);
        if (text === null) return fail(`Skill ${skill.name} has no readable file ${JSON.stringify(file.slice(0, 200))}.`);
        const label = file.replace(/["<>\r\n]/g, '_');
        return { content: `<skill-file skill="${skill.name}" file="${label}">\n${text}\n</skill-file>`, origin: 'workspace' };
      }
      validator.activate(skill);
      return { content: describeBody(skill), origin: 'workspace' };
    },
  };
}
