// A writer that runs until it is killed. crash.test.ts launches it and kills it mid-work.
import { acquireSessionLock, SessionWriter } from '@hn/session';

const { HN_LOG_PATH, HN_LOCK_DIR, HN_SESSION_ID, HN_KEY } = process.env;
if (!HN_LOG_PATH || !HN_LOCK_DIR || !HN_SESSION_ID || !HN_KEY) throw new Error('Missing crash-writer env.');

await acquireSessionLock({ sessionId: HN_SESSION_ID, lockDir: HN_LOCK_DIR });
const writer = await SessionWriter.open({
  path: HN_LOG_PATH,
  sessionId: HN_SESSION_ID,
  key: Buffer.from(HN_KEY, 'hex'),
});
process.stdout.write('READY\n');

for (let index = 0; ; index += 1) {
  writer.append('step/start', { stepId: String(index) });
  const event = writer.append('assistant/message', { text: 'x'.repeat(index % 700) });
  if (index % 3 === 0) {
    await writer.flush();
    // Only acknowledged after the fsync, so the parent may rely on this seq surviving.
    process.stdout.write(`DURABLE ${event.seq}\n`);
  }
  await new Promise((resolve) => setImmediate(resolve));
}
