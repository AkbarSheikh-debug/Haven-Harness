import { dirname } from 'node:path';
import { CheckpointPolicy, CheckpointStore, type CheckpointInfo, type RestoreReport } from '@hn/operations';

/**
 * Undo for the session. A snapshot is taken before the first mutating step in each directory, bash
 * included, then at most once per 50 steps or 10 minutes. If a snapshot cannot be taken the change is
 * not made, because "yolo has undo" must never be quietly false.
 */

export interface MutationCall {
  readonly tool: string;
  readonly writes: readonly string[];
}

export interface SessionCheckpoints {
  /** Called by the dispatcher before a tool that changes things runs. Throws when no snapshot could be saved. */
  before(call: MutationCall): Promise<void>;
  list(): Promise<CheckpointInfo[]>;
  /**
   * Restores the latest checkpoint of this session. By default only the files the agent wrote are put back,
   * so a person's own edits survive; `all` restores everything the checkpoint holds and deletes what was added.
   */
  /** `/rewind`: restores one checkpoint, either only `paths` (the agent's own writes) or, with null, everything. */
  restoreTo(seq: number, options: { readonly paths: readonly string[] | null }): Promise<RestoreReport>;
  rollback(options: { all: boolean; whileStopped?: <T>(work: () => Promise<T>) => Promise<T>; boxAlive?: () => boolean }): Promise<RestoreReport & { checkpoint: CheckpointInfo }>;
}

export interface CheckpointingOptions {
  readonly store: CheckpointStore;
  readonly sessionId: string;
  /** The folder the box or the agent changes: the host tree for a direct run, the copy for a box. */
  readonly root: string;
  /** Records `checkpoint/create {seq, treeHash, ref}` in the log. */
  readonly record: (info: CheckpointInfo) => void;
  readonly policy?: CheckpointPolicy;
}

export function createCheckpointing(options: CheckpointingOptions): SessionCheckpoints {
  const policy = options.policy ?? new CheckpointPolicy();
  const touched = new Set<string>();
  let step = 0;
  /**
   * Calls are handled one at a time. The dispatcher can run several tool calls from one message at once, and a
   * call that finds a snapshot already under way must wait for it, or it could start changing files while they
   * are being saved and the "before" snapshot would not be before.
   */
  let queue: Promise<unknown> = Promise.resolve();

  const handle = async (call: MutationCall): Promise<void> => {
    step += 1;
    for (const path of call.writes) touched.add(path.replaceAll('\\', '/'));
    const directory = call.writes[0] === undefined ? '.' : dirname(call.writes[0].replaceAll('\\', '/'));
    if (!policy.shouldSnapshot(directory, step)) return;
    let info: CheckpointInfo;
    try {
      info = await options.store.create(options.root, { session: options.sessionId, reason: `before ${call.tool}` });
    } catch (error) {
      throw new Error(`A checkpoint could not be saved, so ${call.tool} did not run: ${error instanceof Error ? error.message : String(error)}`);
    }
    options.record(info);
  };

  return {
    before(call) {
      const run = queue.then(() => handle(call));
      queue = run.catch(() => undefined);
      return run;
    },

    list: () => options.store.list(),

    async rollback({ all, whileStopped, boxAlive }) {
      const mine = (await options.store.list()).filter((info) => info.session === options.sessionId);
      const checkpoint = mine.at(-1);
      if (checkpoint === undefined) throw new Error('This session has no checkpoint to go back to.');
      const run = () =>
        options.store.restore(options.root, checkpoint.seq, {
          boxAlive: boxAlive ?? (() => false),
          ...(all ? { deleteNew: true } : { paths: [...touched] }),
        });
      const report = await (whileStopped === undefined ? run() : whileStopped(run));
      return { ...report, checkpoint };
    },

    async restoreTo(seq, { paths }) {
      return options.store.restore(options.root, seq, { boxAlive: () => false, ...(paths === null ? { deleteNew: true } : { paths: [...paths] }) });
    },
  };
}
