import { join } from 'node:path';
import { SafeFileError, type SafeFiles } from '@hn/operations';
import { detectCheck, StopVerifier, type CheckCommand, type HarnessExec, type ProjectReader } from '@hn/tools';

const MAX_PROJECT_FILE = 1024 * 1024;

/** Project files for detection, through the native helper only. A missing or refused file is just absent. */
function projectReader(files: SafeFiles, root: string): ProjectReader {
  return async (relativePath) => {
    try {
      return await files.read(root, join(root, relativePath), MAX_PROJECT_FILE);
    } catch (error) {
      if (error instanceof SafeFileError) return null;
      throw error;
    }
  };
}

/**
 * Verify-on-stop for a session. On by default whenever a check is known: `--verify "<command>"` names one,
 * `--verify off` turns it off, and otherwise the project's own test command is found. Every run is a gated
 * `HarnessExec` call, so below tier 3 a person approves it, bound to the hash of the file that defines it.
 */
export function createVerifier(options: {
  readonly setting: string | undefined;
  readonly files: SafeFiles | null;
  readonly root: string;
  readonly exec: HarnessExec;
}): StopVerifier | null {
  const { setting, files, root, exec } = options;
  if (setting === 'off') return null;
  let find: () => Promise<CheckCommand | null>;
  if (setting !== undefined && setting.trim() !== '') {
    const fixed: CheckCommand = { command: setting.trim(), scripts: {}, source: '--verify' };
    find = async () => fixed;
  } else if (files !== null) {
    const read = projectReader(files, root);
    find = () => detectCheck(read);
  } else {
    return null;
  }
  return new StopVerifier({
    find,
    run: (check, signal) => exec.run({ purpose: 'verify', command: check.command, scripts: check.scripts }, signal),
  });
}
