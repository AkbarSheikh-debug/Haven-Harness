import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { catalogueText, loadSkills, skillFileReader, type InstructionChain, type Skill, type SkillSet } from '@hn/context';
import type { InstructionFrameLike, InstructionHooks } from '@hn/loop';
import type { SafeFiles } from '@hn/operations';
import { recordSkillUse } from '@hn/memory';
import type { TrustStore } from '@hn/security';
import { createSkillTool, SkillValidator, type HarnessExec, type SkillCatalog, type ToolDefinition } from '@hn/tools';
import { safeInstructionReader, type InstructionApprover } from './instructions.ts';

export interface SkillSetup {
  readonly set: SkillSet;
  readonly tool: ToolDefinition;
  readonly validator: SkillValidator;
  readonly notes: readonly string[];
}

function catalogOf(set: SkillSet, files: SafeFiles): SkillCatalog {
  const byName = new Map<string, Skill>(set.skills.map((skill) => [skill.name, skill]));
  const reader = safeInstructionReader(files);
  return {
    find: (name) => byName.get(name) ?? null,
    names: () => [...byName.keys()],
    readFile: async (name, relativePath) => {
      const skill = byName.get(name);
      return skill === undefined ? null : skillFileReader(reader, skill.root, skill.folder)(relativePath);
    },
  };
}

/**
 * Skills from `~/.hn/skills` and the project's `.hn/skills`. A project SKILL.md nobody approved is offered on
 * the same card as an instruction file; without a person it stays out. Every `validate:` run is a gated
 * `HarnessExec` call.
 */
export async function openSkills(options: {
  readonly files: SafeFiles;
  readonly hnHome: string;
  readonly projectRoot: string;
  readonly trust: TrustStore;
  readonly exec: HarnessExec;
  readonly approve?: InstructionApprover;
}): Promise<SkillSetup> {
  const roots = {
    user: join(options.hnHome, 'skills'),
    project: join(options.projectRoot, '.hn', 'skills'),
    projectRoot: options.projectRoot,
    reader: safeInstructionReader(options.files),
    trust: options.trust,
  };
  let set = await loadSkills(roots);
  const notes: string[] = [];
  let approved = false;
  for (const file of set.pending) {
    if (options.approve !== undefined && (await options.approve(file))) {
      await options.trust.approve(file.path, file.content);
      approved = true;
    } else {
      notes.push(`Skill not loaded until approved (${file.state}): ${file.display}`);
    }
  }
  if (approved) set = await loadSkills(roots);
  const validator = new SkillValidator((command, scripts, signal) =>
    options.exec.run({ purpose: 'validate', command, scripts }, signal),
  );
  const tool = createSkillTool(catalogOf(set, options.files), validator);
  // Each use of a user skill is telemetry for the curator (10.7), written beside those skills.
  const counted: ToolDefinition = {
    ...tool,
    async execute(args, context) {
      const result = await tool.execute(args, context);
      const skill = set.skills.find((candidate) => candidate.name === args['name']);
      if (result.isError !== true && skill?.scope === 'user') await recordSkillUse(roots.user, skill.name, new Date()).catch(() => undefined);
      return result;
    },
  };
  return { set, tool: counted, validator, notes };
}

/** One pinned row for both: the instruction chain, then the skill catalogue. Re-sent together after every fold. */
export function withCatalogue(chain: InstructionChain | null, set: SkillSet, deferredTools: readonly string[] = []): InstructionHooks {
  // A small model told to use a tool it cannot see in its list gives up (seen live), so the names are listed here,
  // after the cached prefix, and re-sent with the catalogue after every fold.
  const tools =
    deferredTools.length === 0
      ? ''
      : `\n<system-reminder>\nMore tools exist than your list shows. Find one with tool_search, then run it with call_tool: ${deferredTools.join(', ')}.\n</system-reminder>`;
  const catalogue = `${catalogueText(set)}${tools}`;
  const combine = (frame: InstructionFrameLike | null): InstructionFrameLike => {
    const text = frame === null ? catalogue : `${frame.text}\n${catalogue}`;
    const digest = createHash('sha256').update(text).digest('hex').slice(0, 16);
    return { text, origin: frame?.origin ?? 'harness', digest };
  };
  return {
    snapshot: async () => combine(chain === null ? null : await chain.snapshot()),
    touched: async (paths) => (chain === null ? null : chain.touched(paths)),
  };
}
