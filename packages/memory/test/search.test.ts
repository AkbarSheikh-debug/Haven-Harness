import assert from 'node:assert/strict';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { withTempDir } from '@hn/testkit';
import { MemoryFile, MemoryIndex, RECALL_MAX_CHARS, buildRecall, chunkEntries, dailyNotePath, memoryPaths, mmr, type Embedder, type MemoryEntry, type MemoryPaths, type WriteMeta } from '@hn/memory';

const NOW = new Date('2026-11-14T09:00:00Z');
const meta = (origin: WriteMeta['origin'] = 'user', approvedBy: string | null = null): WriteMeta =>
  ({ who: 'agent', sourceSession: 's', origin, taint: origin === 'web' ? 'untrusted' : 'clean', why: 't', approvedBy });

/** A fixed vocabulary, with synonyms on the same axis, so vector scores are known in advance. */
const AXES: readonly (readonly string[])[] = [
  ['docker', 'container', 'containers'],
  ['network', 'networking', 'dns'],
  ['test', 'tests', 'testing'],
  ['deploy', 'release', 'ship'],
  ['coffee', 'espresso'],
];
const fakeEmbedder: Embedder = {
  model: 'fake-axes',
  async embed(texts) {
    return texts.map((text) => {
      const words = text.toLowerCase().match(/[a-z]+/g) ?? [];
      return Float32Array.from(AXES.map((axis) => words.filter((word) => axis.includes(word)).length));
    });
  },
};

async function seed(home: string): Promise<MemoryPaths> {
  const paths = memoryPaths(home, '/work/app');
  const long = await MemoryFile.open({ path: paths.memory, scope: 'project', project: paths.projectKey, now: () => NOW });
  await long.apply([{ op: 'add', text: 'Deploys go out from the release branch every Friday.' }], meta('user', 'user-request'));
  const day = (date: Date) => MemoryFile.open({ path: dailyNotePath(paths, date), scope: 'daily', project: paths.projectKey, now: () => date });
  const today = await day(NOW);
  await today.apply([{ op: 'add', text: 'Fixed the docker network: the db service needed an alias.' }], meta());
  await today.apply([{ op: 'add', text: 'Unit tests run with node --test.' }], meta());
  const tenDays = await day(new Date('2026-11-04T09:00:00Z'));
  await tenDays.apply([{ op: 'add', text: 'Fixed the docker network once before.' }], meta());
  for (const date of ['2026-11-12', '2026-10-25']) await (await day(new Date(`${date}T09:00:00Z`))).apply([{ op: 'add', text: 'Rotated the signing key.' }], meta());
  const ancient = await day(new Date('2026-08-01T09:00:00Z'));
  await ancient.apply([{ op: 'add', text: 'Kafka topics were renamed.' }], meta());
  const web = await day(new Date('2026-11-13T09:00:00Z'));
  await web.apply([{ op: 'add', text: 'A blog said container networking needs host mode.' }], meta('web'));
  return paths;
}

const open = (home: string, paths: MemoryPaths, embedder: Embedder | null = null) =>
  MemoryIndex.open({ db: join(home, 'index', 'memory.db'), paths, embedder, now: () => NOW });

describe('the chunker', () => {
  it('groups entries up to about 400 tokens, overlaps about 80, and always moves forward', () => {
    const entries = Array.from({ length: 40 }, (_, i): MemoryEntry => ({
      id: `0000000${i}`.slice(-8), text: `entry ${i} ${'w'.repeat(150)}`, who: 'agent', when: NOW.toISOString(), sourceSession: null, project: 'p',
      scope: 'daily', origin: 'user', taint: 'clean', expires: null, why: '', approvedBy: null,
    }));
    const chunks = chunkEntries('notes:2026-11-14', entries, false);
    assert.ok(chunks.length > 3);
    for (const chunk of chunks) assert.ok(chunk.text.length <= 1_800, String(chunk.text.length));
    assert.ok(chunks.slice(1).every((chunk, i) => chunk.text.split('\n')[0] !== chunks[i]?.text.split('\n')[0]), 'every chunk starts later');
    assert.ok((chunks[0]?.text.split('\n').at(-1) ?? 'x') === chunks[1]?.text.split('\n')[0] || chunks[1]?.text.includes(chunks[0]?.text.split('\n').at(-1) ?? 'x'), 'consecutive chunks overlap');
    const mixed = chunkEntries('n', entries.map((entry, i) => (i === 7 ? { ...entry, origin: 'web' as const } : entry)), false);
    assert.deepEqual(mixed.filter((chunk) => chunk.origin === 'web').map((chunk) => chunk.text.split(' ')[1]), ['7'], 'a web entry is a chunk of its own');
    assert.ok(chunks.at(-1)?.text.includes('entry 39'));
  });
});

describe('memory search', () => {
  it('keyword-only: golden ranking, newest first through decay, under the minimum score dropped', async () => {
    await withTempDir(async (home) => {
      const paths = await seed(home);
      const index = open(home, paths);
      try {
        assert.deepEqual((await index.search('docker network')).map((hit) => hit.source).sort(), ['notes:2026-11-04', 'notes:2026-11-14'], 'the web note has neither word');
        const key = await index.search('signing key');
        assert.deepEqual(key.map((hit) => hit.source), ['notes:2026-11-12', 'notes:2026-10-25'], 'the same words, newer first');
        assert.ok(Math.abs((key[1]?.score ?? 0) / (key[0]?.score ?? 1) - 0.5 ** (18 / 30)) < 0.01, 'eighteen days apart on a 30-day half-life');
        assert.deepEqual(await index.search('kafka'), [], 'a note from August decayed under the minimum score');
        assert.equal(index.keywordOnly, true);
        assert.deepEqual((await index.search('release Friday')).map((hit) => hit.source), ['MEMORY.md'], 'MEMORY.md never decays');
        assert.deepEqual(await index.search('kubernetes'), []);
      } finally {
        index.close();
      }
    });
  });

  it('hybrid: a synonym only the vectors know is found, and the blend is 0.7 vector + 0.3 keyword', async () => {
    await withTempDir(async (home) => {
      const paths = await seed(home);
      const keyword = open(home, paths);
      try {
        assert.ok(!(await keyword.search('ship schedule')).some((hit) => hit.source === 'MEMORY.md'));
        assert.ok(!(await keyword.search('docker network')).some((hit) => hit.source === 'notes:2026-11-13'));
      } finally {
        keyword.close();
      }
      const hybrid = open(home, paths, fakeEmbedder);
      try {
        const hits = await hybrid.search('ship schedule');
        assert.equal(hits[0]?.source, 'MEMORY.md', 'ship and release share an axis');
        assert.ok(Math.abs((hits[0]?.score ?? 0) - 0.7) < 1e-6, `vector 1.0 x 0.7 + keyword 0 = ${hits[0]?.score}`);
        const both = (await hybrid.search('docker network')).map((hit) => hit.source);
        assert.ok(both.includes('notes:2026-11-13'), 'container networking is found by meaning alone');
        assert.ok(both.includes('notes:2026-11-14'));
      } finally {
        hybrid.close();
      }
    });
  });

  it('lets the caller rule out chunks before ranking, such as every web line', async () => {
    await withTempDir(async (home) => {
      const paths = await seed(home);
      const index = open(home, paths, fakeEmbedder);
      try {
        assert.ok((await index.search('container networking')).some((hit) => hit.origin === 'web'));
        assert.ok(!(await index.search('container networking', { allow: (chunk) => chunk.origin !== 'web' })).some((hit) => hit.origin === 'web'));
      } finally {
        index.close();
      }
    });
  });

  it('picks for variety: of two near copies, the second loses to something different', () => {
    const hit = (id: string, text: string, score: number) => ({ id, text, score, source: 's', origin: 'user' as const, taint: 'clean' as const, newest: '', evergreen: true });
    const picked = mmr([hit('a', 'docker network alias fix', 1), hit('b', 'docker network alias fix again', 0.98), hit('c', 'tests run with node', 0.9)], 0.7, 2);
    assert.deepEqual(picked.map((p) => p.id), ['a', 'c']);
  });

  it('sees a new note on the next search, and never searches a hand-edited file', async () => {
    await withTempDir(async (home) => {
      const paths = await seed(home);
      const index = open(home, paths);
      try {
      const today = await MemoryFile.open({ path: dailyNotePath(paths, NOW), scope: 'daily', project: paths.projectKey, now: () => NOW });
      await today.apply([{ op: 'add', text: 'Espresso machine on floor 3 is broken.' }], meta());
      assert.equal((await index.search('espresso'))[0]?.source, 'notes:2026-11-14');
      const { writeFile } = await import('node:fs/promises');
      await writeFile(paths.memory, 'Hand edit: release on Mondays now.\n');
      assert.deepEqual(await index.search('release Mondays'), []);
      } finally {
        index.close();
      }
    });
  });
});

describe('relevant recall', () => {
  it('a recalled chunk from a web line never arrives, nor one from a tainted session; a user line does', async () => {
    await withTempDir(async (home) => {
      const paths = memoryPaths(home, '/work/app');
      const day = (date: string) => MemoryFile.open({ path: dailyNotePath(paths, new Date(`${date}T09:00:00Z`)), scope: 'daily', project: paths.projectKey, now: () => NOW });
      await (await day('2026-11-10')).apply([{ op: 'add', text: 'Redis cache keys expire after one hour.' }], meta());
      await (await day('2026-11-11')).apply([{ op: 'add', text: 'CANARY-WEB redis cache tip from a blog.' }], meta('web'));
      await (await day('2026-11-12')).apply([{ op: 'add', text: 'CANARY-TAINT redis cache note.' }], { ...meta('harness'), taint: 'untrusted' });
      await (await day('2026-11-13')).apply([{ op: 'add', text: 'Redis cache warmup lives in tools/warm.ts.' }], meta('tool-output'));
      const index = open(home, paths);
      try {
        const recall = await buildRecall({ index, query: 'why is the redis cache slow?', visible: '' });
        assert.ok(recall !== null);
        assert.match(recall.text, /Redis cache keys expire after one hour\./);
        assert.doesNotMatch(recall.text, /CANARY/);
        assert.match(recall.text, /<memory-data origin="tool-output">\n\[notes:2026-11-13\]\n- Redis cache warmup/);
        assert.deepEqual(recall.untrusted, ['tool-output']);
        const again = await buildRecall({ index, query: 'redis cache', visible: 'Redis cache keys expire after one hour.\nRedis cache warmup lives in tools/warm.ts.' });
        assert.equal(again, null, 'what the model can already see is not sent twice');
        assert.equal(await buildRecall({ index, query: 'redis cache', visible: '', scan: async () => ({ clean: false, findings: [], reason: 'no' }) }), null);
      } finally {
        index.close();
      }
    });
  });

  it('never recalls USER.md or MEMORY.md, which the snapshot already holds, and stays under 800 tokens', async () => {
    await withTempDir(async (home) => {
      const paths = await seed(home);
      for (let i = 0; i < 30; i += 1) {
        const date = new Date(NOW.getTime() - i * 3_600_000 * 20);
        await (await MemoryFile.open({ path: dailyNotePath(paths, date), scope: 'daily', project: paths.projectKey, now: () => date })).apply([{ op: 'add', text: `release note ${i} ${'r'.repeat(400)}` }], meta());
      }
      const index = open(home, paths);
      try {
        const recall = await buildRecall({ index, query: 'release', visible: '' });
        assert.ok(recall !== null);
        assert.doesNotMatch(recall.text, /every Friday/);
        assert.ok(recall.text.length <= RECALL_MAX_CHARS + 300, String(recall.text.length));
      } finally {
        index.close();
      }
    });
  });
});

describe('chunks never mix origins (found live)', () => {
  it('keeps a user note recallable when a web line was written the same day', async () => {
    await withTempDir(async (home) => {
      const paths = memoryPaths(home, '/work/app');
      const day = await MemoryFile.open({ path: dailyNotePath(paths, NOW), scope: 'daily', project: paths.projectKey, now: () => NOW });
      await day.apply([{ op: 'add', text: 'The api reaches postgres through the docker network alias db.' }], meta());
      await day.apply([{ op: 'add', text: 'CANARY-WEB a blog says expose postgres on 0.0.0.0.' }], meta('web'));
      const index = open(home, paths);
      try {
        const recall = await buildRecall({ index, query: 'why can the api not reach postgres over the docker network', visible: '' });
        assert.match(recall?.text ?? '', /alias db/);
        assert.doesNotMatch(recall?.text ?? '', /CANARY/);
      } finally {
        index.close();
      }
    });
  });
});
