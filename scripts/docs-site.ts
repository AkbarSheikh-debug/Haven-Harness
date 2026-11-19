// Builds the documentation site. A developer tool, not part of hn. No dependencies.
//
//   node --disable-proto=throw scripts/docs-site.ts --out <folder>
//
// README.md becomes the home page and every docs/guide/*.md a page. The build FAILS, and writes nothing, when a link
// does not resolve (a page, an anchor, a file in the repository, an image) or when any page carries internal planning
// text, so a broken or leaky site is never deployed. Text is escaped before it is marked up, and only http(s), mailto,
// repository-relative and in-page links are kept, so a page cannot carry a script or a `javascript:` link.

import { existsSync, realpathSync } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { basename, dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const REPO = 'https://github.com/AkbarSheikh-debug/Haven-Harness';
const FORBIDDEN = /\bphase \d|\bdecision \d|master plan|section \d+\.\d|\bslide \d|\binvariant \d/i;

const escapeHtml = (text: string): string => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
export const slug = (text: string): string => text.toLowerCase().replace(/<[^>]*>/g, '').replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-');

interface Page {
  readonly source: string;
  readonly file: string;
  readonly title: string;
  readonly markdown: string;
  readonly anchors: Set<string>;
}

class SiteError extends Error {}

/** A link as written in a page at `from` (a repository path), turned into where it goes on the site, or an error. */
function resolveLink(target: string, from: string, pages: Map<string, Page>, assets: Set<string>): string {
  if (/^(https?:|mailto:)/i.test(target)) return target;
  if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('//')) throw new SiteError(`${from}: the link "${target}" uses a scheme that is not allowed.`);
  if (target.startsWith('#')) return target;
  const [path = '', hash] = target.split('#');
  const repoPath = posix.normalize(posix.join(posix.dirname(from), path));
  if (repoPath.startsWith('..')) throw new SiteError(`${from}: the link "${target}" leaves the repository.`);
  const page = pages.get(repoPath);
  if (page !== undefined) {
    if (hash !== undefined && !page.anchors.has(hash)) throw new SiteError(`${from}: "${target}" names a heading that does not exist in ${repoPath}.`);
    return `${page.file}${hash === undefined ? '' : `#${hash}`}`;
  }
  if (!existsSync(join(ROOT, ...repoPath.split('/')))) throw new SiteError(`${from}: the link "${target}" points at ${repoPath}, which does not exist.`);
  if (/\.(gif|png|jpe?g|svg|webp)$/i.test(repoPath)) {
    assets.add(repoPath);
    return `assets/${basename(repoPath)}`;
  }
  return `${REPO}/blob/main/${repoPath}`;
}

function inline(text: string, from: string, pages: Map<string, Page>, assets: Set<string>): string {
  const codes: string[] = [];
  let out = text.replace(/`([^`]+)`/g, (_, code: string) => `\u0000${codes.push(`<code>${escapeHtml(code)}</code>`) - 1}\u0000`);
  out = escapeHtml(out);
  out = out.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, (_, alt: string, target: string) => `<img src="${escapeHtml(resolveLink(target.replace(/&amp;/g, '&'), from, pages, assets))}" alt="${alt}">`);
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label: string, target: string) => `<a href="${escapeHtml(resolveLink(target.replace(/&amp;/g, '&'), from, pages, assets))}">${label}</a>`);
  out = out.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/(^|[\s(])\*([^*\s][^*]*)\*(?=[\s).,;:]|$)/g, '$1<em>$2</em>');
  return out.replace(/\u0000(\d+)\u0000/g, (_, index: string) => codes[Number(index)] as string);
}

function render(page: Page, pages: Map<string, Page>, assets: Set<string>): string {
  const lines = page.markdown.split('\n');
  const html: string[] = [];
  const inl = (text: string): string => inline(text, page.source, pages, assets);
  let index = 0;
  while (index < lines.length) {
    const line = lines[index] as string;
    if (/^```\w*\s*$/.test(line)) {
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !/^```\s*$/.test(lines[index] as string)) body.push(lines[index++] as string);
      index += 1;
      html.push(`<pre><code>${escapeHtml(body.join('\n'))}</code></pre>`);
      continue;
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading !== null) {
      const level = (heading[1] as string).length;
      const text = heading[2] as string;
      html.push(`<h${level} id="${slug(text)}">${inl(text)}</h${level}>`);
      index += 1;
      continue;
    }
    if (/^---+\s*$/.test(line)) {
      html.push('<hr>');
      index += 1;
      continue;
    }
    if (/^>\s?/.test(line)) {
      const quote: string[] = [];
      while (index < lines.length && /^>\s?/.test(lines[index] as string)) quote.push((lines[index++] as string).replace(/^>\s?/, ''));
      html.push(`<blockquote>${inl(quote.join(' '))}</blockquote>`);
      continue;
    }
    if (/^\|.*\|\s*$/.test(line) && /^\|[\s:|-]+\|\s*$/.test(lines[index + 1] ?? '')) {
      const cells = (row: string): string[] => row.trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map((cell) => cell.trim().replace(/\\\|/g, '|'));
      const head = cells(line);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && /^\|.*\|\s*$/.test(lines[index] as string)) rows.push(cells(lines[index++] as string));
      html.push(`<div class="table"><table><thead><tr>${head.map((cell) => `<th>${inl(cell)}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${inl(cell)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    const bullet = /^(\s*)([-*]|\d+\.)\s+(.*)$/.exec(line);
    if (bullet !== null) {
      const ordered = /\d/.test(bullet[2] as string);
      const items: string[] = [];
      while (index < lines.length) {
        const current = lines[index] as string;
        const item = /^(\s*)([-*]|\d+\.)\s+(.*)$/.exec(current);
        if (item !== null && (item[1] as string).length === 0) {
          items.push(item[3] as string);
        } else if (items.length > 0 && (item !== null || /^\s{2,}\S/.test(current))) {
          // A continuation line, or a nested item, is folded into the item it sits under.
          items[items.length - 1] += ` ${(item === null ? current : (item[3] as string)).trim()}`;
        } else break;
        index += 1;
      }
      html.push(`<${ordered ? 'ol' : 'ul'}>${items.map((item) => `<li>${inl(item)}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`);
      continue;
    }
    if (line.trim() === '') {
      index += 1;
      continue;
    }
    const paragraph: string[] = [];
    while (index < lines.length && (lines[index] as string).trim() !== '' && !/^(#{1,4}\s|```|>|\||\s*([-*]|\d+\.)\s|---)/.test(lines[index] as string)) paragraph.push((lines[index++] as string).trim());
    if (paragraph.length === 0) {
      paragraph.push(line.trim());
      index += 1;
    }
    html.push(`<p>${inl(paragraph.join(' '))}</p>`);
  }
  return html.join('\n');
}

const STYLE = `:root{--bg:#fff;--fg:#1b1f24;--muted:#59636e;--line:#d8dee4;--accent:#0b5fff;--code:#f4f6f8}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--fg:#e6edf3;--muted:#9198a1;--line:#2b323b;--accent:#6ea8ff;--code:#171c23}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
header{border-bottom:1px solid var(--line);padding:.75rem 1rem}header nav{max-width:60rem;margin:0 auto;display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;align-items:center}
header a{color:var(--muted);text-decoration:none;font-size:.95rem}header a:hover,header a[aria-current]{color:var(--fg)}header .brand{color:var(--fg);font-weight:650;margin-right:auto}
main{max-width:60rem;margin:0 auto;padding:1.5rem 1rem 4rem}h1,h2,h3{line-height:1.25}h2{margin-top:2.25rem;padding-bottom:.3rem;border-bottom:1px solid var(--line)}
a{color:var(--accent)}img{max-width:100%;height:auto;border:1px solid var(--line);border-radius:8px}code{background:var(--code);padding:.12em .35em;border-radius:4px;font-size:.9em}
pre{background:var(--code);padding:1rem;border-radius:8px;overflow-x:auto}pre code{background:none;padding:0}blockquote{margin:1rem 0;padding:.25rem 1rem;border-left:3px solid var(--line);color:var(--muted)}
.table{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--line);padding:.45rem .7rem;text-align:left;vertical-align:top}th{background:var(--code)}`;

function wrap(page: Page, body: string, nav: readonly Page[]): string {
  const links = nav.map((item) => `<a href="${item.file}"${item.file === page.file ? ' aria-current="page"' : ''}>${escapeHtml(item.file === 'index.html' ? 'Home' : item.title)}</a>`).join('');
  return `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(page.title)} · Haven Harness</title><style>${STYLE}</style></head><body><header><nav><a class="brand" href="index.html">Haven Harness</a>${links}<a href="${REPO}">GitHub</a></nav></header><main>\n${body}\n</main></body></html>\n`;
}

export async function buildSite(out: string): Promise<string[]> {
  const guides = (await readdir(join(ROOT, 'docs', 'guide'))).filter((name) => name.endsWith('.md')).sort();
  const sources = [{ source: 'README.md', file: 'index.html' }, ...guides.map((name) => ({ source: `docs/guide/${name}`, file: `${name.replace(/\.md$/, '')}.html` }))];
  const pages = new Map<string, Page>();
  for (const { source, file } of sources) {
    const markdown = (await readFile(join(ROOT, ...source.split('/')), 'utf8')).replace(/\r\n/g, '\n');
    const found = FORBIDDEN.exec(markdown);
    if (found !== null) throw new SiteError(`${source} carries internal planning text ("${found[0]}"), so the site is not built.`);
    const title = /^#\s+(.*)$/m.exec(markdown)?.[1]?.replace(/[`*]/g, '') ?? basename(source, '.md');
    const anchors = new Set([...markdown.matchAll(/^#{1,4}\s+(.*)$/gm)].map((match) => slug(match[1] as string)));
    pages.set(source, { source, file, title, markdown, anchors });
  }
  const assets = new Set<string>();
  const rendered = new Map<string, string>();
  for (const page of pages.values()) rendered.set(page.file, render(page, pages, assets));
  const nav = [...pages.values()];
  await mkdir(join(out, 'assets'), { recursive: true });
  for (const page of pages.values()) await writeFile(join(out, page.file), wrap(page, rendered.get(page.file) as string, nav));
  for (const asset of assets) await copyFile(join(ROOT, ...asset.split('/')), join(out, 'assets', basename(asset)));
  await writeFile(join(out, '.nojekyll'), '');
  return [...pages.values()].map((page) => page.file);
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { out: { type: 'string' } } });
  if (values.out === undefined) throw new Error('docs-site.ts --out <folder>');
  const target = resolve(values.out);
  if (resolve(ROOT) === target || dirname(target) === target) throw new Error('Refusing to write the site over the repository or a drive root.');
  process.stdout.write(`Built ${(await buildSite(target)).join(', ')} in ${target}\n`);
}

// Compared by real path: through a symlinked folder (a macOS temp folder is one) the two names differ and the script would silently do nothing.
if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
