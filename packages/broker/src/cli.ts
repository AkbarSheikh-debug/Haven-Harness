import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { auditKeyId, parsePolicyTree, signPolicyTree } from '@hn/security';
import { rotateAuditKey } from './audit-rotate.ts';

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
  if (verb === 'audit-key') {
    const [state, folder] = rest;
    if (state === undefined || folder === undefined) throw new HnError('BAD_COMMAND', 'hn broker audit-key <broker state folder> <folder to write to>');
    let signing: Buffer;
    let hmac: Buffer;
    try {
      signing = await readFile(join(state, 'audit-sign.key'));
      hmac = await readFile(join(state, 'audit.key'));
    } catch {
      throw new HnError('BAD_COMMAND', `${state} has no audit keys yet. Start the broker once, then run this again.`);
    }
    const publicKey = createPublicKey(createPrivateKey(signing));
    await mkdir(folder, { recursive: true });
    await writeFile(join(folder, 'audit-public.pem'), publicKey.export({ type: 'spki', format: 'pem' }), { flag: 'wx' });
    await writeFile(join(folder, 'audit.key'), hmac, { mode: 0o600, flag: 'wx' });
    out(`Wrote ${join(folder, 'audit-public.pem')} (key id ${auditKeyId(publicKey)}: tell the auditor this id some other way than by this file) and ${join(folder, 'audit.key')}.
audit.key lets whoever holds it check the audit's rows and also write rows that look genuine, so hand it only to the auditor, and only for the checking. The signed checkpoints are what stop a holder from passing off rows the broker never had.
`);
    return 0;
  }
  if (verb === 'rotate-audit-key') {
    const [state, folder] = rest;
    if (state === undefined || folder === undefined) throw new HnError('BAD_COMMAND', 'hn broker rotate-audit-key <broker state folder> <folder to write the draft roster to>  (stop the broker first)');
    await rotateAuditKey(state, folder, out);
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
