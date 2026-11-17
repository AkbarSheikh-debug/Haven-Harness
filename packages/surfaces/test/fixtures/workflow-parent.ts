// A parent session in its own process, for the workflow crash test: it opens a session and runs one turn whose
// model starts a workflow. The test kills this process partway through and resumes the session itself.
import { KeyStore } from '@hn/provider';
import { openSession } from '@hn/surfaces';

const [root, home, url, sessionId] = process.argv.slice(2) as [string, string, string, string];
const session = await openSession(
  { workdir: root, mode: 'safe', model: 'fake', baseUrl: url, window: 64_000, env: { HN_HOME: home }, verify: 'off', unsafeWorkflowsBelowTier3: true, sessionId, approver: async () => 'once' },
  KeyStore.capture({}),
);
await session.agent.run('Run the five-step workflow.');
await session.agent.close();
await session.close();
