import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { ProcessOperations, RunningProcess } from '@hn/operations';
import type { RunnerChannel } from './workflow.ts';

/** The runner's own file, for a runner on this machine. */
export const RUNNER_PATH = fileURLToPath(new URL('./runner.mjs', import.meta.url));
/** Where a box gets its copy of the runner: never the project folder, whose files come back to the host. */
export const BOX_RUNNER_PATH = '/tmp/hn-workflow/runner.mjs';

const POLL_MS = 15;

function quote(text: string): string {
  return `'${text.replaceAll("'", "'\\''")}'`;
}

export interface LauncherOptions {
  readonly processes: ProcessOperations;
  /** Where the runner runs: the project folder, or the box's copy of it. */
  readonly cwd: string;
  /**
   * `local`: node and the runner file on this machine (tests, and only with the test-only switch below tier 3).
   * `box`: the runner's source is first written into the box's /tmp through standard input, then run with the box's node.
   */
  readonly where: 'local' | 'box';
}

/**
 * Starts runners through the session's process starter, so a runner in a box runs in the box, under its policy, with
 * no route to the tool channel but its own standard streams. Messages are lines of JSON on stdout; a line that is not
 * JSON is ignored.
 */
export function processLauncher(options: LauncherOptions): () => RunnerChannel {
  return () => {
    const listeners: ((message: unknown) => void)[] = [];
    const queued: string[] = [];
    let proc: RunningProcess | null = null;
    let killed = false;
    let offset = 0;
    let partial = '';
    const drain = (): void => {
      if (proc === null) return;
      const bytes = proc.stdout.since(offset);
      offset += bytes.length;
      partial += bytes.toString('utf8');
      let newline = partial.indexOf('\n');
      while (newline !== -1) {
        const line = partial.slice(0, newline);
        partial = partial.slice(newline + 1);
        newline = partial.indexOf('\n');
        let message: unknown;
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        for (const listener of listeners) listener(message);
      }
    };
    const start = async (): Promise<{ code: number | null }> => {
      if (options.where === 'box') {
        const install = options.processes.start(`mkdir -p /tmp/hn-workflow && cat > ${BOX_RUNNER_PATH}`, { cwd: options.cwd, input: true });
        install.write(readFileSync(RUNNER_PATH, 'utf8'));
        install.closeInput();
        const installed = await install.exited;
        if (installed.code !== 0) return { code: installed.code };
      }
      if (killed) return { code: null };
      const command = options.where === 'box' ? `node ${BOX_RUNNER_PATH}` : `${quote(process.execPath.replaceAll('\\', '/'))} ${quote(RUNNER_PATH.replaceAll('\\', '/'))}`;
      proc = options.processes.start(command, { cwd: options.cwd, input: true });
      for (const line of queued.splice(0)) proc.write(line);
      const timer = setInterval(drain, POLL_MS);
      const exit = await proc.exited;
      clearInterval(timer);
      drain();
      return exit;
    };
    const exited = start();
    return {
      send: (message) => {
        const line = `${JSON.stringify(message)}\n`;
        if (proc === null) queued.push(line);
        else proc.write(line);
      },
      onMessage: (listener) => {
        listeners.push(listener);
      },
      exited,
      kill: () => {
        killed = true;
        proc?.closeInput();
        proc?.signal('kill');
      },
    };
  };
}
