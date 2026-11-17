import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { localOperations } from '@hn/operations';
import { Gate, Jail, ModeRefusedError, TaintTracker, type ApprovalCard, type GateOptions } from '@hn/security';
import { createDispatcher, createPlanningTools, type Answer, type GoalView, type PlanningOptions, type Question } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

interface Kit {
  run(name: string, args: unknown): Promise<{ content: string; isError: boolean; origin?: string; records?: readonly unknown[] }>;
  gate: Gate;
  cards: ApprovalCard[];
  audits: { type: string; data: Record<string, unknown> }[];
}

async function kit(dir: string, gateOptions: Partial<GateOptions>, planning: Partial<PlanningOptions> = {}, human = true): Promise<Kit> {
  const root = await realpath(dir);
  const ops = localOperations(join(root, '..', 'spill-plan'));
  const cards: ApprovalCard[] = [];
  const audits: { type: string; data: Record<string, unknown> }[] = [];
  const approver = async (card: ApprovalCard) => {
    cards.push(card);
    return 'session' as const;
  };
  const gate = new Gate({
    mode: 'plan',
    workdir: root,
    audit: (type, data) => audits.push({ type, data }),
    jail: new Jail({ root, realpath: ops.read.realpath }),
    ...(human ? { approver } : {}),
    ...gateOptions,
  });
  const tools = createPlanningTools({ leavePlan: () => gate.leavePlan(), goal: () => null, tainted: () => false, ...planning });
  const dispatcher = createDispatcher({ gate, ops, workdir: root, extraTools: tools });
  return {
    gate,
    cards,
    audits,
    run: async (name, args) => {
      const request = { id: `c-${name}-${Math.random()}`, name, args };
      const check = dispatcher.check(request);
      if (check.kind !== 'ok') return { content: check.message, isError: true };
      return dispatcher.run({ ...request, name: check.name, args: check.args }, new AbortController().signal);
    },
  };
}

describe('todo_write', () => {
  it('saves a valid list as a todo/write record, and refuses two items in progress', async () => {
    await withTempDir(async (dir) => {
      const { run } = await kit(dir, { mode: 'safe' });
      const todos = [
        { content: 'read the parser', status: 'completed' },
        { content: 'fix the bug', status: 'in_progress' },
      ];
      const saved = await run('todo_write', { todos });
      assert.equal(saved.isError, false);
      assert.deepEqual(saved.records, [{ type: 'todo/write', data: { todos } }]);
      const both = [
        { content: 'a', status: 'in_progress' },
        { content: 'b', status: 'in_progress' },
      ];
      assert.equal((await run('todo_write', { todos: both })).isError, true);
      assert.match((await run('todo_write', { todos: [{ content: '', status: 'pending' }] })).content, /content of 1 to 500/);
    });
  });

  it('works in plan mode, because writing a plan is not changing the project', async () => {
    await withTempDir(async (dir) => {
      const { run, cards } = await kit(dir, {});
      assert.equal((await run('todo_write', { todos: [{ content: 'plan it', status: 'pending' }] })).isError, false);
      assert.equal(cards.length, 0);
    });
  });
});

describe('plan mode', () => {
  it('attack: exit_plan_mode_requires_human', async () => {
    await withTempDir(async (dir) => {
      // With a person: they see the plan on a card, and only their yes leaves plan mode.
      const attended = await kit(dir, {});
      const left = await attended.run('exit_plan_mode', { plan: '1. Fix the parser.\n2. Add a test.' });
      assert.equal(left.isError, false, left.content);
      assert.equal(attended.cards.length, 1);
      assert.match(attended.cards[0]?.summary ?? '', /1\. Fix the parser\./);
      assert.equal(attended.cards[0]?.canRememberForSession, false, 'a plan approval is never remembered');
      assert.equal(attended.gate.mode, 'safe');
      assert.ok(attended.audits.some((entry) => entry.type === 'mode/change' && entry.data['to'] === 'safe'));

      // With nobody there, even a guardian cannot approve it, and the session stays in plan mode.
      const alone = await kit(dir, { guardian: async () => 'allow' }, {}, false);
      const refused = await alone.run('exit_plan_mode', { plan: 'Do everything.' });
      assert.equal(refused.isError, true);
      assert.equal(alone.gate.mode, 'plan');
    });
  });

  it('refuses changes in plan mode without asking, and points at exit_plan_mode', async () => {
    await withTempDir(async (dir) => {
      const { run, cards } = await kit(dir, {});
      const write = await run('write_file', { path: 'a.txt', content: 'x' });
      assert.equal(write.isError, true);
      assert.match(write.content, /plan mode\. Read, plan, and call exit_plan_mode/);
      assert.equal(cards.length, 0, 'plan mode is a rule, not a prompt');
    });
  });

  it('only leaves plan mode for the mode chosen at launch, never one the model names', async () => {
    await withTempDir(async (dir) => {
      const { run, gate } = await kit(dir, { afterPlan: 'read-only' });
      await run('exit_plan_mode', { plan: 'Look around.', mode: 'yolo' });
      assert.equal(gate.mode, 'plan', 'an extra argument is refused before anything runs');
      await run('exit_plan_mode', { plan: 'Look around.' });
      assert.equal(gate.mode, 'read-only');
      const jail = new Jail({ root: dir, realpath: async (path) => path });
      assert.throws(() => new Gate({ mode: 'plan', workdir: dir, audit: () => undefined, jail, afterPlan: 'yolo', tier: 2 }), ModeRefusedError);
    });
  });

  it('is refused outside plan mode', async () => {
    await withTempDir(async (dir) => {
      const { run, gate } = await kit(dir, { mode: 'safe' });
      assert.match((await run('exit_plan_mode', { plan: 'x' })).content, /only works in plan mode/);
      assert.equal(gate.mode, 'safe');
    });
  });
});

describe('goals', () => {
  it('needs a person to set or change a goal once the session is tainted, and shows it in full', async () => {
    await withTempDir(async (dir) => {
      const taint = new TaintTracker();
      let goal: GoalView | null = null;
      const planning = { tainted: () => taint.flags.untrusted, goal: () => goal };
      const { run, cards } = await kit(dir, { mode: 'accept-edits' }, planning);
      assert.equal((await run('create_goal', { objective: 'Ship 1.0' })).isError, false);
      assert.equal(cards.length, 0, 'an untainted goal in accept-edits needs no card');
      goal = { objective: 'Ship 1.0', criteria: null, status: 'active', progress: null };
      taint.observe('web');
      const update = await run('update_goal', { status: 'done', progress: 'all green' });
      assert.equal(update.isError, false);
      assert.equal(cards.length, 1);
      assert.match(cards[0]?.summary ?? '', /done all green/);
      const record = { type: 'goal/change', data: { action: 'update', goal: { status: 'done', progress: 'all green' } } };
      assert.deepEqual(update.records, [record]);
    });
  });

  it('allows one active goal at a time', async () => {
    await withTempDir(async (dir) => {
      const goal: GoalView = { objective: 'A', criteria: null, status: 'active', progress: null };
      const { run } = await kit(dir, { mode: 'accept-edits' }, { goal: () => goal });
      assert.match((await run('create_goal', { objective: 'B' })).content, /already active/);
      assert.match((await run('get_goal', {})).content, /Goal \(active\): A/);
    });
  });
});

describe('ask_user_question', () => {
  const options = [{ label: 'Rewrite it' }, { label: 'Patch it', description: 'smaller change' }];

  async function ask(dir: string, answer: Answer | null, seen: Question[] = []) {
    const asker = async (question: Question): Promise<Answer | null> => {
      seen.push(question);
      return answer;
    };
    const { run } = await kit(dir, { mode: 'safe' }, { ask: asker });
    return run('ask_user_question', { question: 'How?\u001b]52;c;aGk=\u0007', options });
  }

  it('attack: option_click_not_user_origin', async () => {
    await withTempDir(async (dir) => {
      const click = await ask(dir, { kind: 'options', picked: [1] });
      assert.equal(click.origin, 'human-selected', "the person chose, but the words are the model's");
      assert.match(click.content, /The user picked: 2\. Patch it/);
      const typed = await ask(dir, { kind: 'text', text: 'neither, revert it' });
      assert.equal(typed.origin, 'user', 'only words the person typed are user');
    });
  });

  it('cleans the question before a person sees it, and refuses when nobody is there', async () => {
    await withTempDir(async (dir) => {
      const seen: Question[] = [];
      await ask(dir, null, seen);
      assert.doesNotMatch(seen[0]?.question ?? '', /\u001b|\u0007/);
      const { run } = await kit(dir, { mode: 'safe' });
      const alone = await run('ask_user_question', { question: 'How?', options });
      assert.equal(alone.isError, true);
      assert.match(alone.content, /Nobody is here to answer/);
    });
  });
});
