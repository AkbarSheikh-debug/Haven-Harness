import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { projectKey, resolvePaths } from '@hn/config';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { copyManifests, detectManager, dockerIsUp, findDocker, preparePlan, runDockerStep, scriptPackages } from '@hn/operations';

/**
 * `hn prepare [--dry-run] --image name@sha256:<digest>`. The image must hold Node and the project's package
 * manager; it runs both the package proxy and the install. The installed tree stays under `~/.hn/prepared`, outside the
 * project, as box output does. Install scripts run only after a person at a terminal saw the list and typed yes.
 */
export async function runPrepareCommand(input: { positionals: readonly string[]; nested: boolean; out: (text: string) => void; image?: string; dryRun: boolean }): Promise<number | null> {
  if (input.positionals[0] !== 'prepare') return null;
  if (input.nested) throw new HnError('NESTED_HN', 'hn prepare cannot be run from inside an hn session.');
  if (input.image === undefined) throw new HnError('BAD_PREPARE', 'hn prepare needs --image name@sha256:<digest>, an image with Node and the package manager.');
  const root = process.cwd();
  const manager = await detectManager(root);
  if (manager === null) throw new HnError('BAD_PREPARE', 'No lockfile was found (pnpm-lock.yaml, package-lock.json, yarn.lock or requirements.txt). prepare installs only from a lockfile.');
  const id = randomBytes(6).toString('hex');
  const workDir = join(resolvePaths().home, 'prepared', projectKey(root), id);
  const scripts = await scriptPackages(root, manager);
  let runScripts = false;
  if (scripts.length > 0) {
    input.out(sanitizeForDisplay(`These packages want to run install scripts:\n${scripts.map((name) => `  ${name}`).join('\n')}\n`));
    if (!input.dryRun && process.stdin.isTTY === true) {
      input.out('Run their scripts, in a separate step with no network? Type yes to allow: ');
      const reader = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
      runScripts = /^\s*yes\s*$/i.test(await reader.question(''));
      reader.close();
    }
    if (!runScripts) input.out('Their scripts will not run.\n');
  }
  const steps = preparePlan({ id, manager, workDir, proxyImage: input.image, installImage: input.image, runScripts });
  if (input.dryRun) {
    input.out(`prepare would run (${manager}, manifests only, into ${workDir}):\n${steps.map((step) => `  # ${step.why}\n  docker ${step.args.join(' ')}`).join('\n')}\n`);
    return 0;
  }
  const docker = await findDocker();
  if (docker === null || !(await dockerIsUp(docker))) throw new HnError('NO_DOCKER', 'Docker is not running, so prepare cannot run. Try --dry-run to see what it would do.');
  const copied = await copyManifests(root, manager, workDir);
  input.out(`Copied ${copied.join(', ')} (and nothing else) to ${workDir}.\n`);
  let failed = false;
  for (const step of steps) {
    const isCleanup = step.args[0] === 'stop' || (step.args[0] === 'network' && step.args[1] === 'rm');
    if (failed && !isCleanup) continue;
    input.out(`- ${step.why}\n`);
    const result = await runDockerStep(docker, step);
    if (result.code !== 0 && !isCleanup) {
      failed = true;
      input.out(sanitizeForDisplay(`  failed:\n${result.output.slice(-3_000)}\n`));
    }
  }
  input.out(failed ? 'prepare failed; the closed network and proxy were removed.\n' : `Installed into ${workDir}.\n`);
  return failed ? 1 : 0;
}
