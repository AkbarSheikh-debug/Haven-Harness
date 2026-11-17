import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { parsePolicyTree, signPolicyTree } from '@hn/security';

/**
 * The operator's policy tools: `hn broker keygen <folder>` makes an ed25519 signing key (the private half stays with
 * whoever writes policy, never on the broker), and `hn broker sign <tree.json> <key.pem> <key id> <bundle.json>`
 * checks a tree and writes the signed bundle the broker loads. Returns null for anything else.
 */
export async function runPolicyTool(positionals: readonly string[], out: (text: string) => void): Promise<number | null> {
  const [command, verb, ...rest] = positionals;
  if (command !== 'broker') return null;
  if (verb === 'keygen') {
    const [folder] = rest;
    if (folder === undefined) throw new HnError('BAD_COMMAND', 'hn broker keygen <folder>');
    const pair = generateKeyPairSync('ed25519');
    await mkdir(folder, { recursive: true });
    await writeFile(join(folder, 'policy-key.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    await writeFile(join(folder, 'policy-key.pub.pem'), pair.publicKey.export({ type: 'spki', format: 'pem' }), { flag: 'wx' });
    out(`Wrote ${join(folder, 'policy-key.pem')} (keep it with whoever writes policy, not on the broker) and policy-key.pub.pem (pin it in broker.json under policy.keys).\n`);
    return 0;
  }
  if (verb === 'sign') {
    const [treePath, keyPath, keyId, bundlePath] = rest;
    if (treePath === undefined || keyPath === undefined || keyId === undefined || bundlePath === undefined) throw new HnError('BAD_COMMAND', 'hn broker sign <tree.json> <key.pem> <key id> <bundle.json>');
    const tree: unknown = JSON.parse(await readFile(treePath, 'utf8'));
    const parsed = parsePolicyTree(tree);
    await writeFile(bundlePath, `${JSON.stringify(signPolicyTree(tree, keyId, createPrivateKey(await readFile(keyPath))), null, 2)}\n`);
    out(`Signed serial ${parsed.serial} into ${bundlePath}. The broker refuses any bundle with a lower serial from now on.\n`);
    return 0;
  }
  return null;
}
