import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';

const run = promisify(execFile);
const REAL = fileURLToPath(new URL('../../../', import.meta.url));
const script = join(REAL, 'scripts', 'docs-site.ts');

/** A throwaway repository: the real script beside fixture pages, so its checks can be driven. */
async function fixture(dir: string, pages: Record<string, string>): Promise<{ build: () => Promise<{ stdout: string; stderr: string }>; out: string }> {
  await mkdir(join(dir, 'scripts'), { recursive: true });
  await mkdir(join(dir, 'docs', 'guide'), { recursive: true });
  await copyFile(script, join(dir, 'scripts', 'docs-site.ts'));
  for (const [path, text] of Object.entries(pages)) {
    await mkdir(join(dir, path, '..'), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  const out = join(dir, 'site');
  return { out, build: () => run(process.execPath, ['--disable-proto=throw', join(dir, 'scripts', 'docs-site.ts'), '--out', out]) };
}

const refused = (pattern: RegExp) => (error: { stderr: string }): boolean => pattern.test(error.stderr);

describe('the documentation site builder', () => {
  it('builds the real README and guides, with every local link resolving and no script in any page', async () => {
    await withTempDir(async (dir) => {
      const out = join(dir, 'site');
      const result = await run(process.execPath, ['--disable-proto=throw', script, '--out', out]);
      assert.match(result.stdout, /Built index\.html, .*security-model\.html/);
      const files = (await readdir(out)).filter((name) => name.endsWith('.html'));
      assert.ok(files.includes('index.html') && files.includes('team-mode.html') && files.includes('attacks.html'));
      for (const name of files) {
        const html = await readFile(join(out, name), 'utf8');
        assert.doesNotMatch(html, /<script|javascript:|onerror=|onclick=/i, name);
        assert.doesNotMatch(html, /\*\*|\]\(/, `${name} has unrendered markdown`);
        for (const [, href] of html.matchAll(/<a href="([^"#:]+\.html)(?:#[^"]*)?"/g)) assert.ok(existsSync(join(out, href as string)), `${name} links to a missing ${href}`);
        for (const [, src] of html.matchAll(/<img src="(assets\/[^"]+)"/g)) assert.ok(existsSync(join(out, src as string)), `${name} uses a missing ${src}`);
      }
      assert.match(await readFile(join(out, 'index.html'), 'utf8'), /<title>[^<]*Haven Harness/);
    });
  });

  it('fails, and writes nothing, on a link to a page, an anchor or a file that does not exist', async () => {
    for (const [link, pattern] of [
      ['docs/guide/missing.md', /does not exist/],
      ['docs/guide/one.md#nowhere', /heading that does not exist/],
      ['../outside.md', /leaves the repository/],
    ] as const) {
      await withTempDir(async (dir) => {
        const site = await fixture(dir, { 'README.md': `# Home\n\n[go](${link})\n`, 'docs/guide/one.md': '# One\n\ntext\n' });
        const outcome = await site.build().then(
          (done) => ({ done }),
          (error: { stderr: string }) => ({ error }),
        );
        // If the build wrongly succeeds, say what it printed and what was on disk, so a failure on another OS is readable.
        if ('done' in outcome) assert.fail(`${link}: the build succeeded but should have refused it. stdout: ${outcome.done.stdout.slice(0, 300)} stderr: ${outcome.done.stderr.slice(0, 300)} guide folder: ${(await readdir(join(dir, 'docs', 'guide'))).join(',')} root: ${(await readdir(dir)).join(',')}`);
        assert.match(outcome.error.stderr, pattern, link);
        assert.equal(existsSync(site.out), false, 'a failed build must write nothing');
      });
    }
  });

  it('refuses links that could run script or reach elsewhere: javascript, data, file and scheme-relative addresses', async () => {
    for (const link of ['javascript:alert(1)', 'data:text/html,hi', 'file:///etc/passwd', '//evil.example/x', 'vbscript:x']) {
      await withTempDir(async (dir) => {
        const site = await fixture(dir, { 'README.md': `# Home\n\n[go](${link})\n`, 'docs/guide/one.md': '# One\n' });
        await assert.rejects(site.build(), refused(/scheme that is not allowed/), link);
      });
    }
  });

  it('refuses a page that carries internal planning text, and says which', async () => {
    for (const leak of ['This is Phase 9 work.', 'See decision 4.', 'the master plan says', 'in section 8.6', 'on slide 37']) {
      await withTempDir(async (dir) => {
        const site = await fixture(dir, { 'README.md': '# Home\n', 'docs/guide/one.md': `# One\n\n${leak}\n` });
        await assert.rejects(site.build(), refused(/docs\/guide\/one\.md carries internal planning text/), leak);
        assert.equal(existsSync(site.out), false);
      });
    }
  });

  it('escapes what a page contains, so markup in text, tables, code and link labels is shown and never run', async () => {
    await withTempDir(async (dir) => {
      const site = await fixture(dir, {
        'README.md': '# Home <b>x</b>\n\n<script>alert(1)</script> and `<img src=x onerror=alert(1)>`\n\n| a | <i>b</i> |\n|---|---|\n| <script>x</script> | [<u>l</u>](docs/guide/one.md) |\n',
        'docs/guide/one.md': '# One\n',
      });
      await site.build();
      const html = await readFile(join(site.out, 'index.html'), 'utf8');
      assert.doesNotMatch(html, /<script>alert|<i>b<\/i>|<img src=x|<u>l<\/u>|<b>x<\/b>/);
      assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
      assert.match(html, /<code>&lt;img src=x onerror=alert\(1\)&gt;<\/code>/);
      assert.match(html, /<a href="one\.html">&lt;u&gt;l&lt;\/u&gt;<\/a>/);
    });
  });

  it('renders headings with anchors, tables, lists, bold around italic, code blocks, and copies a linked image', async () => {
    await withTempDir(async (dir) => {
      await mkdir(join(dir, 'docs'), { recursive: true });
      await writeFile(join(dir, 'docs', 'demo.gif'), Buffer.from('GIF89a'));
      const site = await fixture(dir, {
        'README.md': '# Home\n\n**Bold with *italic* inside.**\n\n![demo](docs/demo.gif)\n\n## Steps here\n\n1. one\n2. two\n\n- a\n  more of a\n- b\n\n```\n<not html> & code\n```\n\n| x | y |\n|---|---|\n| 1 | 2 |\n\n[jump](docs/guide/one.md#second-part)\n',
        'docs/guide/one.md': '# One\n\n## Second part\n',
      });
      await site.build();
      const html = await readFile(join(site.out, 'index.html'), 'utf8');
      assert.match(html, /<h2 id="steps-here">Steps here<\/h2>/);
      assert.match(html, /<strong>Bold with <em>italic<\/em> inside\.<\/strong>/);
      assert.match(html, /<ol><li>one<\/li><li>two<\/li><\/ol>/);
      assert.match(html, /<li>a more of a<\/li><li>b<\/li>/);
      assert.match(html, /<pre><code>&lt;not html&gt; &amp; code<\/code><\/pre>/);
      assert.match(html, /<table>.*<td>1<\/td><td>2<\/td>/s);
      assert.match(html, /<img src="assets\/demo\.gif" alt="demo">/);
      assert.match(html, /<a href="one\.html#second-part">jump<\/a>/);
      assert.deepEqual(await readFile(join(site.out, 'assets', 'demo.gif')), Buffer.from('GIF89a'));
    });
  });

  it('refuses to write the site over the repository itself', async () => {
    await assert.rejects(run(process.execPath, ['--disable-proto=throw', script, '--out', REAL]), refused(/over the repository/));
  });
});
