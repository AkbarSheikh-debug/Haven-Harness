import assert from 'node:assert/strict';
import { mkdir, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { Origin } from '@hn/core';
import { MemoryFile, answerCard, appendProposal, bytesHash, memoryPaths, newProposalId, rememberRequested, storedBytes, writeMemory } from '@hn/memory';
import { localOperations } from '@hn/operations';
import { Gate, Jail, type ApprovalCard, type Mode } from '@hn/security';
import { createDispatcher, createMemoryTool } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

/** A small seeded generator, so a failing sequence can be replayed. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

const REQUESTS = ['Remember that the api is v2.', 'fix the build', 'From now on we ship on Mondays.', 'Note that staging is eu-west.', 'why is the test red?', 'keep in mind the db is postgres'];
const ORIGINS: Origin[] = ['harness', 'workspace', 'web', 'tool-output', 'mcp'];

/**
 * Exit gate, condition 2, as a property: whatever the sequence of tool calls, taint, people present or
 * absent, yeses, noes and tampered cards, every entry that ever lands in MEMORY.md or USER.md is one the
 * user asked for in that very turn (decision 3, clean session) or one a person said yes to after seeing it.
 */
describe('no path writes MEMORY.md or USER.md without the user asking or a recorded yes', () => {
  for (const seed of [1, 2, 3, 4, 5, 6]) {
    it(`holds for 60 random steps, seed ${seed}`, async () => {
      await withTempDir(async (dir) => {
        const random = rng(seed);
        const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
        const root = await realpath(dir);
        await mkdir(join(root, 'project'));
        const paths = memoryPaths(join(root, 'home'), join(root, 'project'));
        const ops = localOperations(join(root, 'spill'));
        const allowed = { memory: new Set<string>(), user: new Set<string>() };
        let tainted = false;
        let request = 'fix the build';
        let attended = true;
        let humanSays: 'once' | 'deny' = 'deny';
        let mode: Mode = 'safe';
        let lastCard: ApprovalCard | null = null;
        const tool = createMemoryTool({
          paths, sessionId: 's', attended: true, tainted: () => tainted, worst: () => (tainted ? 'web' : 'harness'), turnRequest: () => request, approver: 'tester',
        });
        const attendedTool = { ...tool, execute: (args: Parameters<typeof tool.execute>[0], context: Parameters<typeof tool.execute>[1]) => (attended ? tool.execute(args, context) : createMemoryTool({ paths, sessionId: 's', attended: false, tainted: () => tainted, worst: () => 'web', turnRequest: () => request, approver: 'tester' }).execute(args, context)) };
        let longTermWrites = 0;
        for (let step = 0; step < 60; step += 1) {
          const roll = random();
          if (roll < 0.15) {
            tainted = random() < 0.5;
            request = pick(REQUESTS);
            attended = random() < 0.7;
            mode = pick(['safe', 'dont-ask', 'yolo', 'accept-edits'] as const);
          }
          humanSays = random() < 0.5 ? 'once' : 'deny';
          if (roll < 0.6) {
            const target = pick(['memory', 'user', 'notes'] as const);
            const text = `fact ${seed}-${step}`;
            const gate = new Gate({
              mode, workdir: join(root, 'project'), audit: () => undefined, jail: new Jail({ root: join(root, 'project'), realpath: ops.read.realpath }), tier: 3,
              ...(attended ? { approver: async (card: ApprovalCard) => ((lastCard = card), humanSays) } : {}),
            });
            const dispatcher = createDispatcher({ gate, ops, workdir: join(root, 'project'), extraTools: [attendedTool] });
            lastCard = null;
            const asked = !tainted && rememberRequested(request) && attended;
            const result = await dispatcher.run({ id: `c${step}`, name: 'memory', args: { action: 'add', target, text } }, new AbortController().signal);
            if (target !== 'notes' && !result.isError) {
              longTermWrites += 1;
              const sawCard = (lastCard as ApprovalCard | null)?.summary.includes(text) === true && humanSays === 'once';
              assert.ok(asked || sawCard, `step ${step}: ${target} written without a request or a yes (${result.content})`);
              allowed[target].add(text);
            }
          } else if (roll < 0.85) {
            const kind = pick(['memory', 'user'] as const);
            const card = {
              v: 1 as const, id: newProposalId(), kind, text: `card ${seed}-${step}`, why: 'w', source: pick(['dream', 'review'] as const), origin: pick(ORIGINS), score: 0.8,
              evidence: [], created: new Date().toISOString(), expires: new Date(Date.now() + 86_400_000).toISOString(),
            };
            await appendProposal(paths, card);
            const answer = random();
            const shownHash = answer < 0.2 ? bytesHash('something else') : bytesHash(storedBytes(card));
            const outcome = await answerCard(paths, card.id, answer < 0.6 ? { kind: 'yes', by: 'tester', shownHash } : { kind: 'no', by: 'tester' }, new Date());
            if (outcome.ok && answer < 0.6) allowed[kind].add(card.text);
          } else {
            // Notes from anywhere, as review and flush write them. They must never reach a long-term file.
            await writeMemory({ paths, target: 'notes', ops: [{ op: 'add', text: `note ${seed}-${step}` }], who: pick(['review', 'agent'] as const), sourceSession: 's', origin: pick(ORIGINS), taint: 'untrusted', why: 'w', approvedBy: null });
          }
          for (const [target, path] of [['memory', paths.memory], ['user', paths.user]] as const) {
            const file = await MemoryFile.open({ path, scope: target === 'memory' ? 'project' : 'user', project: target === 'memory' ? paths.projectKey : null });
            for (const entry of file.entries) {
              assert.ok(allowed[target].has(entry.text), `step ${step}: ${target} holds "${entry.text}", which nobody allowed`);
              assert.ok(entry.approvedBy !== null && (entry.approvedBy === 'user-request' || entry.approvedBy.startsWith('human:')), entry.approvedBy ?? 'null');
            }
          }
        }
        assert.ok(longTermWrites + allowed.memory.size + allowed.user.size > 0, 'the run wrote something long-term, so the check was not empty');
      });
    });
  }
});
