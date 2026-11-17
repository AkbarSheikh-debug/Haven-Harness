/**
 * `/skill-test`: a fresh child that never saw the skill being written uses it on a real task and
 * reports harshly. It knows only the skill's name and the task, so it reads the skill the way a stranger would.
 */
export function skillTestBrief(skill: string, task: string): string {
  return [
    `You are testing the skill "${skill}". You did not write it and know nothing about it beyond what it says.`,
    `1. Load it: call_tool({"name":"skill","args":{"name":"${skill}"}}), and read any file it links to that you need.`,
    `2. Follow it to do this task, as far as you can in read-only mode: ${task}`,
    '3. Report harshly, as a reviewer who wants it fixed. Say where it was unclear, what it assumed you knew, what was missing,',
    '   what was wrong, where you had to guess, and whether its description would have made you pick it for this task.',
    'End with the three changes that would help most. Do not praise it.',
  ].join('\n');
}

/** `/skill-test <skill> <task>`: the skill name is one word, the task is the rest. */
export function parseSkillTest(line: string): { skill: string; task: string } | null {
  const match = /^\/skill-test\s+([a-z0-9][a-z0-9-]{0,63})\s+(\S[\s\S]*)$/.exec(line.trim());
  return match === null ? null : { skill: match[1] as string, task: (match[2] as string).trim() };
}
