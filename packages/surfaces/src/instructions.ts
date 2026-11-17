import { homedir } from 'node:os';
import { join } from 'node:path';
import { findProjectRoot, InstructionChain, type InstructionReader, type Quarantined } from '@hn/context';
import { SafeFileError, type SafeFiles } from '@hn/operations';
import type { TrustStore } from '@hn/security';

/** A person's yes or no for one instruction file whose exact content nobody has approved yet. */
export type InstructionApprover = (file: Quarantined) => Promise<boolean>;

/** Every instruction file is read through the native helper: regular file, no links, inside its root. */
export function safeInstructionReader(files: SafeFiles): InstructionReader {
  return {
    async read(root, absolute, maxBytes) {
      try {
        return { kind: 'ok', bytes: await files.read(root, absolute, maxBytes) };
      } catch (error) {
        if (error instanceof SafeFileError && error.reason === 'not_found') return { kind: 'absent' };
        return { kind: 'refused', reason: error instanceof SafeFileError ? error.reason : 'unreadable' };
      }
    },
  };
}

/** What a door holds: the chain, and the one way to record a person's yes for a file. */
export interface InstructionAccess {
  readonly chain: InstructionChain;
  /** Call only with a file a person approved on a card. */
  trust(file: Quarantined): Promise<void>;
}

export interface InstructionSetup {
  readonly access: InstructionAccess | null;
  readonly notes: readonly string[];
  /** Where `.git` is, or the box's copy; project skills live under it. */
  readonly projectRoot: string;
}

/**
 * Builds the chain and asks about files nobody approved yet. Without the helper nothing is loaded, because
 * a plain read could follow a link. Without a person here, unapproved files stay unloaded and are named.
 */
export async function openInstructions(options: {
  readonly files: SafeFiles | null;
  /** The folder tools work in: the project, or the box's copy of it. */
  readonly root: string;
  readonly sandboxed: boolean;
  readonly hnHome: string;
  readonly window: number;
  readonly trust: TrustStore;
  readonly approve?: InstructionApprover;
}): Promise<InstructionSetup> {
  if (options.files === null) {
    const notes = ['Instruction files and skills were not loaded: the safe-file helper is not available.'];
    return { access: null, notes, projectRoot: options.root };
  }
  // In a box the copy is the whole project; above it is the host, which the chain never reads.
  const projectRoot = options.sandboxed ? options.root : await findProjectRoot(options.root);
  const chain = new InstructionChain({
    userFiles: [join(options.hnHome, 'AGENTS.md'), join(homedir(), '.agents', 'AGENTS.md')],
    root: projectRoot,
    cwd: options.root,
    window: options.window,
    reader: safeInstructionReader(options.files),
    trust: options.trust,
  });
  await chain.snapshot();
  const notes: string[] = [];
  for (const file of chain.pending) {
    const yes = options.approve === undefined ? false : await options.approve(file);
    if (yes) await options.trust.approve(file.path, file.content);
    else notes.push(`Instruction file not loaded until approved (${file.state}): ${file.display}`);
  }
  const access = { chain, trust: (file: Quarantined) => options.trust.approve(file.path, file.content) };
  return { access, notes, projectRoot };
}
