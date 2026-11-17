import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { EMPTY_SNAPSHOT, LEAD, MAX_TEAM_TASKS, applyAction, describeTasks, releaseAll, type TeamSnapshot } from '@hn/orchestrate';

function make(titles: string[]): TeamSnapshot {
  let snapshot = EMPTY_SNAPSHOT;
  for (const title of titles) {
    const result = applyAction(snapshot, { kind: 'create', title }, LEAD, 'model-derived');
    assert.ok(result.ok);
    snapshot = result.snapshot;
  }
  return snapshot;
}

const ok = (result: ReturnType<typeof applyAction>): TeamSnapshot => {
  assert.ok(result.ok, result.ok ? '' : result.message);
  return result.snapshot;
};

describe('the team task graph', () => {
  it('refuses a stale revision, so two members cannot both win one claim', () => {
    const start = make(['a']);
    const first = ok(applyAction(start, { kind: 'claim', id: 't1', revision: 1 }, 'ann', 'child'));
    const second = applyAction(first, { kind: 'claim', id: 't1', revision: 1 }, 'bob', 'child');
    assert.equal(second.ok, false);
    assert.equal(second.ok ? '' : second.code, 'TEAM_TASK_STALE_REVISION');
    assert.equal(first.tasks[0]?.owner, 'ann');
    assert.equal(first.revision, start.revision + 1, 'every write is a whole new snapshot');
  });

  it('refuses a cycle, checking the whole graph', () => {
    let snapshot = make(['a', 'b', 'c']);
    snapshot = ok(applyAction(snapshot, { kind: 'set_dependencies', id: 't2', revision: 1, deps: ['t1'] }, LEAD, 'model-derived'));
    snapshot = ok(applyAction(snapshot, { kind: 'set_dependencies', id: 't3', revision: 1, deps: ['t2'] }, LEAD, 'model-derived'));
    const loop = applyAction(snapshot, { kind: 'set_dependencies', id: 't1', revision: 1, deps: ['t3'] }, LEAD, 'model-derived');
    assert.equal(loop.ok ? '' : loop.code, 'TEAM_TASK_CYCLE');
    const self = applyAction(snapshot, { kind: 'set_dependencies', id: 't1', revision: 1, deps: ['t1'] }, LEAD, 'model-derived');
    assert.equal(self.ok ? '' : self.code, 'TEAM_TASK_CYCLE');
    const waiting = applyAction(snapshot, { kind: 'claim', id: 't3', revision: 2 }, 'ann', 'child');
    assert.match(waiting.ok ? '' : waiting.message, /waits for t2/);
  });

  it('lets only the owner complete or release, and only the lead reassign, reopen or delete', () => {
    let snapshot = ok(applyAction(make(['a']), { kind: 'claim', id: 't1', revision: 1 }, 'ann', 'child'));
    for (const [action, actor] of [[{ kind: 'complete', id: 't1', revision: 2 } as const, 'bob'], [{ kind: 'release', id: 't1', revision: 2 } as const, 'bob'], [{ kind: 'reassign', id: 't1', revision: 2, to: 'bob' } as const, 'ann'], [{ kind: 'delete', id: 't1', revision: 2 } as const, 'ann']] as const) {
      const refused = applyAction(snapshot, action, actor, 'child');
      assert.equal(refused.ok ? '' : refused.code, 'TEAM_TASK_FORBIDDEN', `${action.kind} by ${actor}`);
    }
    const done = applyAction(snapshot, { kind: 'complete', id: 't1', revision: 2, changed: ['src/a.ts', 'docs/x.md'] }, 'ann', 'child');
    assert.ok(done.ok);
    snapshot = done.snapshot;
    assert.equal(snapshot.tasks[0]?.status, 'done');
    snapshot = ok(applyAction(snapshot, { kind: 'reopen', id: 't1', revision: 3 }, LEAD, 'model-derived'));
    assert.equal(snapshot.tasks[0]?.status, 'open');
  });

  it('warns when a task changed files outside its scope', () => {
    let snapshot = ok(applyAction(EMPTY_SNAPSHOT, { kind: 'create', title: 'docs', scope: ['docs'] }, LEAD, 'model-derived'));
    snapshot = ok(applyAction(snapshot, { kind: 'claim', id: 't1', revision: 1 }, 'ann', 'child'));
    const done = applyAction(snapshot, { kind: 'complete', id: 't1', revision: 2, changed: ['docs/a.md', 'src/evil.ts'] }, 'ann', 'child');
    assert.deepEqual(done.ok ? done.warnings : [], ['Task t1 changed files outside its scope: src/evil.ts.']);
  });

  it('carries the worst origin of whoever wrote a task, so a reader joins the writer taint', () => {
    let snapshot = make(['a']);
    snapshot = ok(applyAction(snapshot, { kind: 'edit', id: 't1', revision: 1, detail: 'from a member who read the web' }, LEAD, 'web'));
    assert.equal(snapshot.tasks[0]?.origin, 'web');
  });

  it('caps the graph at 256 tasks and releases a dead member claims', () => {
    const full = make(Array.from({ length: MAX_TEAM_TASKS }, (_, i) => `task ${i}`));
    const over = applyAction(full, { kind: 'create', title: 'one more' }, LEAD, 'model-derived');
    assert.equal(over.ok ? '' : over.code, 'TEAM_TASK_LIMIT');
    let snapshot = make(['a', 'b']);
    snapshot = ok(applyAction(snapshot, { kind: 'claim', id: 't1', revision: 1 }, 'ann', 'child'));
    snapshot = ok(applyAction(snapshot, { kind: 'claim', id: 't2', revision: 1 }, 'bob', 'child'));
    const after = releaseAll(snapshot, 'ann');
    assert.deepEqual(after.tasks.map((task) => `${task.id}:${task.status}:${task.owner ?? '-'}`), ['t1:open:-', 't2:claimed:bob']);
    assert.equal(releaseAll(after, 'ann'), after, 'nothing to release is no new snapshot');
    assert.match(describeTasks(after), /t1 r3 \[open\] a\nt2 r2 \[claimed bob\] b/);
  });
});
