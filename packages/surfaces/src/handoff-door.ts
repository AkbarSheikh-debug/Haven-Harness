import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sanitizeForDisplay } from '@hn/core';
import type { KeyStore } from '@hn/provider';
import { HANDOFF_MAX_CHARS, handoffOrigin, validDraft } from './handoff.ts';
import { openSession } from './session.ts';
import type { CliOptions, OpenSession } from './session-types.ts';

export interface HandoffDoor {
  /** One line from the person. */
  readonly ask: (prompt: string) => Promise<string>;
  readonly out: (text: string) => void;
  /** The hn home, where the draft is written for the person to edit. */
  readonly home: string;
  readonly signal?: AbortSignal;
}

/**
 * `/handoff`: typed by the person, never decided by the agent. A draft is written to a file the person
 * may edit; on a plain yes the current session ends and a new one opens with the note as context, linked to this one
 * and carrying its taint. Returns the new session, or null when the person stayed.
 */
export async function runHandoff(session: OpenSession, options: CliOptions, keys: KeyStore, door: HandoffDoor): Promise<OpenSession | null> {
  const draft = await session.draftHandoff(door.signal ?? new AbortController().signal);
  const folder = join(door.home, 'handoffs');
  await mkdir(folder, { recursive: true });
  const path = join(folder, `${session.sessionId}.md`);
  await writeFile(path, `${draft.text}\n`);
  door.out(`\n${sanitizeForDisplay(draft.text)}\n\n${draft.by === 'model' ? 'Drafted by the model.' : 'The model draft could not be used, so this one is built from what you typed.'} You may edit ${path} first.\n`);
  const answer = (await door.ask('Open a new session with this note? (y/N) ')).trim().toLowerCase();
  if (answer !== 'y' && answer !== 'yes') {
    door.out('Staying in this session.\n');
    return null;
  }
  const edited = (await readFile(path, 'utf8')).trim();
  if (!validDraft(edited)) {
    door.out(`The note must keep its ## Context and ## Task headings and stay under ${HANDOFF_MAX_CHARS} characters. Staying in this session.\n`);
    return null;
  }
  const origin = handoffOrigin(session.worst());
  const parent = session.sessionId;
  const { sessionId: _old, ...rest } = options;
  const next = await openSession({ ...rest, handoff: { parent, draft: edited, origin } }, keys);
  session.agent.record('session/link', { kind: 'handoff-to', child: next.sessionId });
  await session.agent.close();
  await session.close();
  door.out(`New session ${next.sessionId}, started from the note. The previous one is ${parent}; resume it with hn --resume ${parent}.\n`);
  return next;
}
