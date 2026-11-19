import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, posix } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { projectKey, resolvePaths } from '@hn/config';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { resolveHelper } from './helper.ts';
import { analyzeDockerfile, assertPinned, buildArgs, buildContext, createSafeFiles, dockerBuild, findDocker, imageId, type SafeFiles } from '@hn/operations';
import { TrustStore, hashContent } from '@hn/security';
import { loadOrCreateLogKey } from '@hn/session';

/**
 * Project image recipes (decision 9, section 8.1). A recipe is attacker-controlled code, so it is proposed, never used
 * by itself: `hn sandbox propose` shows all of it and a person pins its hash; any change, on resume too, needs a person
 * again. Devcontainer lifecycle commands and the other host-reaching keys are ignored and listed, never run. A build
 * copies only the files the Dockerfile names into a context the harness makes, and runs with no network.
 */

export type RecipeKind = 'hn' | 'devcontainer' | 'dockerfile';

export interface Recipe {
  readonly kind: RecipeKind;
  /** Project-relative path of the recipe file. */
  readonly source: string;
  readonly image?: string;
  readonly dockerfile?: { readonly path: string; readonly text: string };
  /** Files the build context will hold, as the Dockerfile names them. */
  readonly sources: readonly string[];
  /** Keys present in the recipe that are never used or run. */
  readonly ignored: readonly string[];
  readonly problems: readonly string[];
  /** Everything a person approves, as one text. Its hash is what is trusted. */
  readonly text: string;
  readonly hash: string;
}

const HN_FIELDS = new Set(['image', 'dockerfile']);
const DEVCONTAINER_USED = new Set(['image', 'build', 'dockerFile', 'name']);
const MAX_RECIPE_BYTES = 256 * 1024;

/** Removes JSONC comments and trailing commas outside strings. */
export function stripJsonc(text: string): string {
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      i = text.indexOf('*/', i + 2);
      if (i < 0) break;
      i += 1;
    } else {
      out += c;
    }
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

async function readText(files: SafeFiles, root: string, path: string): Promise<string | null> {
  return files.read(root, join(root, path), MAX_RECIPE_BYTES).then((bytes) => bytes.toString('utf8'), () => null);
}

function finish(recipe: Omit<Recipe, 'text' | 'hash'>): Recipe {
  const text = [
    `recipe: ${recipe.source} (${recipe.kind})`,
    ...(recipe.image === undefined ? [] : [`image: ${recipe.image}`]),
    ...(recipe.dockerfile === undefined ? [] : [`--- ${recipe.dockerfile.path} ---`, recipe.dockerfile.text.trimEnd()]),
    '--- build context: the only project files the harness copies in ---',
    ...(recipe.sources.length === 0 ? ['(none)'] : recipe.sources),
    '--- ignored, never used or run ---',
    ...(recipe.ignored.length === 0 ? ['(none)'] : recipe.ignored),
  ].join('\n');
  return { ...recipe, text, hash: hashContent(text) };
}

async function withDockerfile(files: SafeFiles, root: string, base: Omit<Recipe, 'text' | 'hash' | 'sources' | 'problems' | 'dockerfile'>, path: string, problems: string[]): Promise<Recipe> {
  const text = await readText(files, root, path);
  if (text === null) return finish({ ...base, sources: [], problems: [...problems, `The Dockerfile ${path} could not be read.`] });
  const report = analyzeDockerfile(text);
  return finish({ ...base, dockerfile: { path, text }, sources: report.sources, problems: [...problems, ...report.problems] });
}

/** The project's recipe: `.hn/sandbox.json`, then a devcontainer, then a root Dockerfile. Null when there is none. */
export async function findRecipe(root: string, files: SafeFiles): Promise<Recipe | null> {
  const hn = await readText(files, root, '.hn/sandbox.json');
  if (hn !== null) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(hn) as Record<string, unknown>;
    } catch {
      return finish({ kind: 'hn', source: '.hn/sandbox.json', sources: [], ignored: [], problems: ['.hn/sandbox.json is not valid JSON.'] });
    }
    const problems = Object.keys(parsed).filter((key) => !HN_FIELDS.has(key)).map((key) => `.hn/sandbox.json has an unknown field "${key}".`);
    if (typeof parsed['image'] === 'string') {
      const image = parsed['image'];
      try {
        assertPinned(image);
      } catch (error) {
        problems.push(error instanceof Error ? error.message : String(error));
      }
      return finish({ kind: 'hn', source: '.hn/sandbox.json', image, sources: [], ignored: [], problems });
    }
    if (typeof parsed['dockerfile'] === 'string') return withDockerfile(files, root, { kind: 'hn', source: '.hn/sandbox.json', ignored: [] }, posix.normalize(parsed['dockerfile']), problems);
    return finish({ kind: 'hn', source: '.hn/sandbox.json', sources: [], ignored: [], problems: [...problems, '.hn/sandbox.json needs "image" or "dockerfile".'] });
  }
  for (const source of ['.devcontainer/devcontainer.json', '.devcontainer.json']) {
    const text = await readText(files, root, source);
    if (text === null) continue;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(stripJsonc(text)) as Record<string, unknown>;
    } catch {
      return finish({ kind: 'devcontainer', source, sources: [], ignored: [], problems: [`${source} is not valid JSON.`] });
    }
    // Lifecycle commands run on the host or in the container at times hn does not choose; none of them ever runs.
    const ignored = Object.keys(parsed).filter((key) => !DEVCONTAINER_USED.has(key)).sort();
    const build = (typeof parsed['build'] === 'object' && parsed['build'] !== null ? parsed['build'] : {}) as Record<string, unknown>;
    for (const key of Object.keys(build)) if (key !== 'dockerfile') ignored.push(`build.${key}`);
    const folder = source.includes('/') ? '.devcontainer' : '.';
    const dockerfile = typeof build['dockerfile'] === 'string' ? build['dockerfile'] : typeof parsed['dockerFile'] === 'string' ? parsed['dockerFile'] : null;
    if (dockerfile !== null) return withDockerfile(files, root, { kind: 'devcontainer', source, ignored }, posix.normalize(posix.join(folder, dockerfile)), []);
    const image = typeof parsed['image'] === 'string' ? parsed['image'] : '';
    const problems: string[] = [];
    try {
      assertPinned(image);
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
    return finish({ kind: 'devcontainer', source, image, sources: [], ignored, problems });
  }
  if ((await readText(files, root, 'Dockerfile')) !== null) return withDockerfile(files, root, { kind: 'dockerfile', source: 'Dockerfile', ignored: [] }, 'Dockerfile', []);
  return null;
}

const recipeKey = (root: string): string => `recipe:${root}`;
const builtKey = (root: string): string => `recipe-built:${root}`;
const builtFile = (home: string, root: string): string => join(home, 'recipes', `${projectKey(root)}.json`);

export interface RecipeContext {
  readonly home: string;
  readonly root: string;
  readonly files: SafeFiles;
  readonly trust: TrustStore;
}

/** The image a session may use, from a recipe a person approved. Throws, saying what to do, in every other case. */
export async function resolveRecipeImage(context: RecipeContext): Promise<string> {
  const recipe = await findRecipe(context.root, context.files);
  if (recipe === null) throw new HnError('RECIPE_NONE', 'This project has no image recipe (.hn/sandbox.json, a devcontainer or a Dockerfile). Give --image name@sha256:<digest>.');
  if (recipe.problems.length > 0) throw new HnError('RECIPE_REFUSED', `The image recipe is refused:\n- ${recipe.problems.join('\n- ')}`);
  const check = context.trust.check(recipeKey(context.root), recipe.text);
  if (check.state === 'new') throw new HnError('RECIPE_NOT_TRUSTED', `The image recipe ${recipe.source} has not been approved. Run: hn sandbox propose`);
  if (check.state === 'changed') throw new HnError('RECIPE_CHANGED', `The image recipe changed since a person approved it, so it is not used until a person approves the change (hn sandbox propose):\n${check.diff ?? ''}`);
  if (recipe.image !== undefined) return recipe.image;
  const binding = await readFile(builtFile(context.home, context.root), 'utf8').catch(() => null);
  const parsed = binding === null ? null : (JSON.parse(binding) as { recipeHash?: string; image?: string });
  if (binding === null || parsed === null || context.trust.check(builtKey(context.root), binding).state !== 'trusted' || parsed.recipeHash !== recipe.hash || typeof parsed.image !== 'string') {
    throw new HnError('RECIPE_NOT_BUILT', 'The approved recipe has not been built yet (or was built from another version). Run: hn sandbox build');
  }
  return parsed.image;
}

/** Shows the whole recipe (or what changed) and pins it on a yes. */
export async function proposeRecipe(context: RecipeContext, ask: (text: string) => Promise<boolean>): Promise<'trusted' | 'approved' | 'declined'> {
  const recipe = await findRecipe(context.root, context.files);
  if (recipe === null) throw new HnError('RECIPE_NONE', 'This project has no image recipe.');
  if (recipe.problems.length > 0) throw new HnError('RECIPE_REFUSED', `The image recipe is refused:\n- ${recipe.problems.join('\n- ')}`);
  const check = context.trust.check(recipeKey(context.root), recipe.text);
  if (check.state === 'trusted') return 'trusted';
  const shown = check.state === 'changed' ? `The recipe changed. What changed:\n${check.diff ?? ''}\n\nThe whole recipe:\n${recipe.text}` : recipe.text;
  if (!(await ask(sanitizeForDisplay(shown)))) return 'declined';
  await context.trust.approve(recipeKey(context.root), recipe.text);
  return 'approved';
}

/** Builds an approved Dockerfile recipe with no network, from a context the harness made, and pins the image it made. */
export async function buildRecipe(context: RecipeContext, docker: string, out: (text: string) => void): Promise<string> {
  const recipe = await findRecipe(context.root, context.files);
  if (recipe === null || recipe.dockerfile === undefined) throw new HnError('RECIPE_NONE', 'There is no Dockerfile recipe to build.');
  if (recipe.problems.length > 0) throw new HnError('RECIPE_REFUSED', `The image recipe is refused:\n- ${recipe.problems.join('\n- ')}`);
  if (context.trust.check(recipeKey(context.root), recipe.text).state !== 'trusted') throw new HnError('RECIPE_NOT_TRUSTED', 'The recipe is not approved as it is now. Run: hn sandbox propose');
  await mkdir(join(context.home, 'recipes'), { recursive: true });
  const dir = await mkdtemp(join(context.home, 'recipes', 'context-'));
  try {
    const report = await buildContext(context.root, recipe.sources, dir);
    for (const skip of report.skipped) out(`not copied: ${skip.path} (${skip.reason})\n`);
    await writeFile(join(dir, '.hn.Dockerfile'), recipe.dockerfile.text);
    const tag = `hn-recipe:${recipe.hash.slice(0, 16)}`;
    const built = await dockerBuild(docker, buildArgs(dir, join(dir, '.hn.Dockerfile'), tag));
    if (built.code !== 0) throw new HnError('RECIPE_BUILD_FAILED', `The build failed:\n${built.output.slice(-4_000)}`);
    const image = await imageId(docker, tag);
    if (image === null) throw new HnError('RECIPE_BUILD_FAILED', 'The built image could not be found.');
    const binding = JSON.stringify({ recipeHash: recipe.hash, image });
    await writeFile(builtFile(context.home, context.root), binding, { mode: 0o600 });
    await context.trust.approve(builtKey(context.root), binding);
    return image;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** What the door and `main` need: the safe file helper and the trust store for this user. */
export async function recipeContext(root: string, env: NodeJS.ProcessEnv = process.env, repoRoot?: string): Promise<RecipeContext> {
  const paths = resolvePaths(env);
  const helper = await resolveHelper({ env, ...(repoRoot === undefined ? {} : { repoRoot }), home: paths.home });
  if (helper === null) throw new HnError('SANDBOX_HELPER_MISSING', 'hn-sandbox is not built. Build it with: pnpm build:sandbox');
  const trust = new TrustStore(join(paths.home, 'trust'), await loadOrCreateLogKey(paths.logKey), { keepText: true });
  await trust.load();
  return { home: paths.home, root, files: createSafeFiles(helper), trust };
}

/** `hn sandbox show | propose | build`. */
export async function runSandboxCommand(input: { positionals: readonly string[]; nested: boolean; out: (text: string) => void; repoRoot: string }): Promise<number | null> {
  if (input.positionals[0] !== 'sandbox') return null;
  if (input.nested) throw new HnError('NESTED_HN', 'hn sandbox cannot be run from inside an hn session.');
  const action = input.positionals[1] ?? 'show';
  const context = await recipeContext(process.cwd(), process.env, input.repoRoot);
  if (action === 'show') {
    const recipe = await findRecipe(context.root, context.files);
    if (recipe === null) return input.out('No image recipe in this project.\n'), 0;
    const state = context.trust.check(recipeKey(context.root), recipe.text).state;
    input.out(sanitizeForDisplay(`${recipe.text}\n\nstate: ${state}${recipe.problems.length > 0 ? `\nrefused:\n- ${recipe.problems.join('\n- ')}` : ''}\n`));
    return 0;
  }
  if (action === 'propose') {
    const outcome = await proposeRecipe(context, async (text) => {
      input.out(`${text}\n\nTrust this image recipe? Type yes to approve: `);
      const reader = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
      const answer = await reader.question('');
      reader.close();
      return /^\s*yes\s*$/i.test(answer);
    });
    input.out(outcome === 'trusted' ? 'The recipe is already approved as it is.\n' : outcome === 'approved' ? 'Approved. Its hash is pinned; any change will need you again.\n' : 'Not approved. Nothing was pinned.\n');
    return outcome === 'declined' ? 2 : 0;
  }
  if (action === 'build') {
    const docker = await findDocker();
    if (docker === null) throw new HnError('NO_DOCKER', 'Docker was not found.');
    const image = await buildRecipe(context, docker, input.out);
    input.out(`Built and pinned: ${image}\n`);
    return 0;
  }
  throw new HnError('BAD_COMMAND', 'hn sandbox takes: show, propose or build.');
}
