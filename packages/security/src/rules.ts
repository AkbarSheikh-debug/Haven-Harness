/**
 * These rules match strings, so they are a seatbelt and not a boundary: `python -c`,
 * base64 and `find -delete` all get past them. The command parser does better, and the sandbox is
 * the actual boundary.
 */

const RM_COMMAND = /\brm\s+((?:-\S+\s+)+)(?:--\s+)?(\S+)/gi;
const SYSTEM_TARGET = /^["']?(\/|\/\*|~|~\/|~\/\*|\$home|\$\{home\}|\/home|\/usr|\/etc|\/var|\/bin|\/boot|\/lib|[a-z]:[\\/]?)\/?\*?["']?$/i;

function isRecursiveSystemDelete(command: string): boolean {
  for (const [, flags = '', target = ''] of command.matchAll(RM_COMMAND)) {
    const recursive = /(^|\s)-[a-z]*r|--recursive/i.test(flags);
    if (recursive && SYSTEM_TARGET.test(target)) return true;
  }
  return false;
}

const HARDLINE: readonly [RegExp, string][] = [
  [/\bmkfs(\.\w+)?\b/i, 'formatting a disk'],
  [/\bdd\b.*\bof=\/dev\//i, 'writing to a raw disk'],
  [/>\s*\/dev\/(sd|nvme|hd|disk)/i, 'writing to a raw disk'],
  [/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, 'a fork bomb'],
  [/\b(shutdown|reboot|poweroff|halt)\b/i, 'shutting the machine down'],
  [/\b(systemctl\s+(poweroff|reboot|halt)|init\s+[06]|telinit\s+[06])\b/i, 'shutting the machine down'],
  [/\bkill\s+(-\w+\s+)*-1\b/i, 'killing every process'],
  [/\bsudo\s+-S\b/i, 'guessing a sudo password'],
  [/\bformat\s+[a-z]:/i, 'formatting a disk'],
  [/\b(rd|rmdir)\s+\/s\s+(\/q\s+)?[a-z]:\\?\s*$/i, 'recursive delete of a drive'],
];

const DENIED_COMMANDS: readonly [RegExp, string][] = [
  [/\bsudo\b/i, 'sudo is not allowed'],
  [/\bgit\b.*\bpush\b.*(\s--force\b|\s--force-with-lease\b|\s-[a-z]*f[a-z]*(\s|$)|\s\+\S+)/i, 'force push is not allowed'],
  [/\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/i, 'piping a download into a shell is not allowed'],
];

const SECRET_NAMES: readonly RegExp[] = [
  /^\.env(\.(?!example$|sample$|template$)[^/]+)?$/,
  /^\.(npmrc|netrc|pypirc|pgpass|git-credentials|dockercfg)$/,
  /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/,
  /\.(pem|key|p12|pfx|keystore|jks)$/,
  /^terraform\.tfstate(\.backup)?$/,
  /^credentials(\.json)?$/,
  /^\.(htpasswd|vault-token|boto|s3cfg|pypirc)$/,
  /^kubeconfig$/,
  /^secrets?\.(ya?ml|json|toml)$/,
  /\.(kdbx|tfvars)$|\.tfvars\.json$/,
  /^application_default_credentials\.json$/,
  /^service[-_]?account.*\.json$/,
];

const SECRET_FOLDERS = new Set(['.ssh', '.aws', '.gnupg', '.kube', '.azure', '.docker']);
/** Folders that are only secret under a parent, such as `~/.config/gcloud`. */
const SECRET_FOLDER_PAIRS: readonly (readonly [string, string])[] = [
  ['.config', 'gcloud'],
  ['.config', 'gh'],
  ['.config', 'doctl'],
];

function underSecretPair(segments: readonly string[]): boolean {
  return segments.some((segment, index) => SECRET_FOLDER_PAIRS.some(([parent, child]) => segment === parent && segments[index + 1] === child));
}

/** Reduces a path to the form an attacker's spelling cannot change: slashes, case, NTFS tricks. */
export function canonicalForRules(path: string): string[] {
  return path
    .replaceAll('\\', '/')
    .toLowerCase()
    .replace(/::\$[a-z]+$/, '')
    .split('/')
    .filter((segment) => segment !== '' && segment !== '.')
    .map((segment) => segment.replace(/[. ]+$/, '') || segment);
}

export function isSecretPath(path: string): boolean {
  const segments = canonicalForRules(path);
  const name = segments.at(-1) ?? '';
  if (segments.slice(0, -1).some((segment) => SECRET_FOLDERS.has(segment))) return true;
  if (SECRET_FOLDERS.has(name)) return true;
  if (underSecretPair(segments)) return true;
  return SECRET_NAMES.some((pattern) => pattern.test(name));
}

/** Git internals run code on the host, so the model never writes them. */
export function isGitInternal(path: string): boolean {
  return canonicalForRules(path).includes('.git');
}

export function hardlineReason(command: string): string | null {
  const flat = command.replace(/\s+/g, ' ');
  if (isRecursiveSystemDelete(flat)) return 'recursive delete of a system or home directory';
  return HARDLINE.find(([pattern]) => pattern.test(flat))?.[1] ?? null;
}

export function deniedCommandReason(command: string): string | null {
  const flat = command.replace(/\s+/g, ' ');
  const denied = DENIED_COMMANDS.find(([pattern]) => pattern.test(flat))?.[1];
  if (denied !== undefined) return denied;
  const word = flat.split(/[\s"'`=;|&<>()]+/).find((token) => token !== '' && isSecretPath(token));
  return word === undefined ? null : `reading or writing ${word} is not allowed`;
}
