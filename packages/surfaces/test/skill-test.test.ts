import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseSkillTest, skillTestBrief } from '../src/skill-test.ts';

describe('/skill-test', () => {
  it('reads the skill name and the task from the command', () => {
    assert.deepEqual(parseSkillTest('/skill-test release cut a 1.2.0 release'), { skill: 'release', task: 'cut a 1.2.0 release' });
    assert.equal(parseSkillTest('/skill-test'), null);
    assert.equal(parseSkillTest('/skill-test ../x do it'), null, 'a skill name is a plain name');
  });

  it('briefs a fresh child to use the skill on the task and review it harshly, knowing nothing else', () => {
    const brief = skillTestBrief('release', 'cut a 1.2.0 release');
    assert.match(brief, /You did not write it and know nothing about it/);
    assert.match(brief, /call_tool\(\{"name":"skill","args":\{"name":"release"\}\}\)/);
    assert.match(brief, /cut a 1\.2\.0 release/);
    assert.match(brief, /Report harshly/);
    assert.match(brief, /Do not praise it\./);
  });
});
