import { createHmac, randomBytes } from 'node:crypto';
import { mkdir, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { KeyStore } from '@hn/provider';
import { FRAME_HEADER_BYTES, FRAME_MAGIC, MAC_BYTES } from '@hn/session';
import { Harness } from '@hn/surfaces';
import { startFakeOpenAI, type FakeOpenAI } from '@hn/testkit';

/** A command a model might write to attack the page that will show it: markup, a script, and characters that hide. */
export const HOSTILE = 'echo "<img src=x onerror=alert(1)><script>alert(2)</script>" # ‮evil​\u001b]52;c;AAAA\u0007';

const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] => request.messages.filter((message) => message.role === 'tool').map((message) => String(message.content));

/** The scripted model every replay test uses: a write, an edit, a command, a jail refusal, a person's refusal, a hostile command. */
export function startScriptedModel(): Promise<FakeOpenAI> {
  return startFakeOpenAI((request) => {
    const steps = [
      { id: 'w1', name: 'write_file', args: { path: 'new.txt', content: 'hello\n' } },
      { id: 'e1', name: 'edit_file', args: { path: 'new.txt', old_string: 'hello', new_string: 'hello world' } },
      { id: 'b1', name: 'bash', args: { command: 'node --version' } },
      { id: 'r1', name: 'read_file', args: { path: '../outside.txt' } },
      { id: 'b3', name: 'bash', args: { command: 'echo deny-me' } },
      { id: 'b4', name: 'bash', args: { command: HOSTILE } },
    ];
    const next = steps[toolResults(request).length];
    return next === undefined ? { text: 'finished' } : { calls: [next] };
  });
}

export interface Recorded {
  readonly project: string;
  readonly home: string;
  readonly sessionId: string;
  /** The log file, and the folder it is in. */
  readonly file: string;
  readonly folder: string;
}

/** Runs a real session against the scripted model, and says where its log is. */
export async function recordSession(top: string, model: FakeOpenAI): Promise<Recorded> {
  const project = join(top, 'project');
  const home = join(top, 'home');
  await mkdir(project, { recursive: true });
  const harness = new Harness({
    workdir: project,
    model: 'fake',
    baseUrl: model.url,
    window: 64_000,
    verify: 'off',
    mode: 'safe',
    keys: KeyStore.capture({}),
    env: { HN_HOME: home },
    approver: async (card) => (card.summary.includes('deny-me') ? 'deny' : 'once'),
  });
  try {
    const result = await harness.run('do the work');
    const folder = join(home, 'sessions', (await readdir(join(home, 'sessions')))[0] as string);
    return { project, home, sessionId: result.sessionId, file: join(folder, result.sessionId), folder };
  } finally {
    await harness.close();
  }
}

/** The byte ranges of the frames in a log file, so a test can cut, move, or add one. */
export function frameRanges(bytes: Buffer): { start: number; end: number }[] {
  const out: { start: number; end: number }[] = [];
  let offset = 0;
  while (offset + FRAME_HEADER_BYTES <= bytes.length && bytes.subarray(offset, offset + 4).equals(FRAME_MAGIC)) {
    const end = offset + FRAME_HEADER_BYTES + bytes.readUInt32LE(offset + 4);
    out.push({ start: offset, end });
    offset = end;
  }
  return out;
}

/** A frame with a made-up MAC, as someone without the key would have to write it. */
export function forgedFrame(payload: Buffer): Buffer {
  const lengths = Buffer.alloc(8);
  lengths.writeUInt32LE(payload.length, 0);
  lengths.writeUInt32LE(payload.length, 4);
  return Buffer.concat([FRAME_MAGIC, lengths, randomBytes(MAC_BYTES), payload]);
}

export const readKey = (home: string): Promise<Buffer> => readFile(join(home, 'log.key'));

/** Not the key: a guess, to show a log is only trusted with the right one. */
export const wrongKey = (key: Buffer): Buffer => createHmac('sha256', key).update('another key').digest();
