import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkSyntax, introducedProblems, languageOf, loadBashParser, syntaxNote, unusableGrammars } from '@hn/security';

const problems = async (path: string, text: string): Promise<number> => (await checkSyntax(path, text))?.problems.length ?? -1;

describe('which files are checked', () => {
  it('knows the languages by extension, in any case', () => {
    for (const [path, language] of [['a.ts', 'typescript'], ['a.MTS', 'typescript'], ['a.tsx', 'tsx'], ['a.js', 'javascript'], ['a.jsx', 'javascript'], ['a.py', 'python'], ['a.go', 'go'], ['a.rs', 'rust'], ['a.java', 'java'], ['a.rb', 'ruby'], ['a.php', 'php'], ['a.cs', 'c-sharp'], ['a.cpp', 'cpp'], ['a.css', 'css'], ['a.sh', 'bash']] as const) {
      assert.equal(languageOf(path), language, path);
    }
    for (const path of ['a.txt', 'a.json', 'Makefile', 'a', 'README.md', 'a.h', 'a.ps1']) assert.equal(languageOf(path), null, path);
  });

  it('says nothing about a file it cannot check', async () => {
    assert.equal(await checkSyntax('notes.txt', 'anything {{{'), null);
    assert.equal(await checkSyntax('big.ts', `${'const a = 1;\n'.repeat(100_000)}`), null, 'a file over a million characters is not parsed');
  });
});

describe('finding syntax errors', () => {
  const good: Record<string, string> = {
    'a.ts': 'export const add = (a: number, b: number): number => a + b;\ninterface X { y: string }\n',
    'a.tsx': 'export const A = () => <div className="x">{1 + 1}</div>;\n',
    'a.js': 'const f = (x) => { return x * 2; };\nmodule.exports = { f };\n',
    'a.py': 'def f(x):\n    return x * 2\n\nclass A:\n    pass\n',
    'a.go': 'package main\n\nfunc main() {\n\tprintln("hi")\n}\n',
    'a.rs': 'fn main() {\n    let x = 5;\n    println!("{}", x);\n}\n',
    'a.java': 'public class A { public static void main(String[] a) { System.out.println(1); } }\n',
    'a.rb': 'def f(x)\n  x * 2\nend\n',
    'a.php': '<?php\nfunction f($x) { return $x * 2; }\n',
    'a.cs': 'class A { static void Main() { System.Console.WriteLine(1); } }\n',
    'a.cpp': '#include <iostream>\nint main() { std::cout << 1; return 0; }\n',
    'a.css': 'a { color: red; }\n.b > .c { margin: 0 auto; }\n',
    'a.sh': 'set -e\nfor f in a b; do echo "$f"; done\n',
  };
  const broken: Record<string, string> = {
    'a.ts': 'export const add = (a: number, b: number): number => {\n  return a +;\n};\n',
    'a.tsx': 'export const A = () => <div className="x">{1 + }</div>;\n',
    'a.js': 'const f = (x) => { return x * ;\n',
    'a.py': 'def f(x)\n    return x * 2\n',
    'a.go': 'package main\n\nfunc main( {\n}\n',
    'a.rs': 'fn main() {\n    let x = ;\n}\n',
    'a.java': 'public class A { void f( { } }\n',
    'a.rb': 'def f(x\n  x * 2\nend\n',
    'a.php': '<?php\nfunction f($x { return; }\n',
    'a.cs': 'class A { void F( { } }\n',
    'a.cpp': 'int main( { return 0; }\n',
    'a.css': 'a { color: red; \n.b { margin\n',
    'a.sh': 'if [ -f x ]; then\n  echo hi\n',
  };

  for (const [path, text] of Object.entries(good)) {
    it(`accepts valid ${path}`, async () => assert.equal(await problems(path, text), 0));
  }
  for (const [path, text] of Object.entries(broken)) {
    it(`finds the error in broken ${path}`, async () => assert.ok((await problems(path, text)) > 0, `${path} was not flagged`));
  }

  it('reports where the error is, with a clean, short snippet', async () => {
    const report = await checkSyntax('a.ts', `const ok = 1;\nconst bad = ;\u001b[31m ${'x'.repeat(200)}\nconst fine = 2;\n`);
    const first = report?.problems[0];
    assert.equal(report?.language, 'typescript');
    assert.equal(first?.line, 2);
    assert.ok((first?.snippet.length ?? 0) <= 90);
    assert.ok(!(first?.snippet ?? '').includes('\u001b'));
  });

  it('stays bounded on a file full of errors', async () => {
    const report = await checkSyntax('a.ts', 'const = ;\n'.repeat(5_000));
    assert.ok((report?.problems.length ?? 0) <= 20);
  });
});

describe('what an edit introduced', () => {
  it('reports every problem in a file that was fine, and nothing when it stays fine', async () => {
    const fine = await checkSyntax('a.ts', 'const a = 1;\n');
    const broken = await checkSyntax('a.ts', 'const a = ;\n');
    assert.ok(introducedProblems(fine, broken).length > 0);
    assert.deepEqual(introducedProblems(fine, fine), []);
    assert.ok(introducedProblems(null, broken).length > 0, 'a new file that is broken');
  });

  it('says nothing when the file was already broken and the edit did not make it worse, or when it fixed it', async () => {
    const one = await checkSyntax('a.ts', 'const a = ;\n');
    const fixed = await checkSyntax('a.ts', 'const a = 1;\n');
    assert.deepEqual(introducedProblems(one, one), []);
    assert.deepEqual(introducedProblems(one, fixed), []);
    const two = await checkSyntax('a.ts', 'const a = ;\nconst b = ;\n');
    assert.ok(introducedProblems(one, two).length > 0, 'a second error was added');
  });

  it('writes a note a model can act on, and nothing for no problems', async () => {
    const broken = await checkSyntax('src/a.ts', 'const a = ;\n');
    const note = syntaxNote('src/a.ts', introducedProblems(null, broken));
    assert.match(note, /src\/a\.ts no longer parses cleanly/);
    assert.match(note, /line 1, column/);
    assert.match(note, /Fix them before going on/);
    assert.equal(syntaxNote('a.ts', []), '');
  });
});

describe('no false alarms on real code', () => {
  it('finds nothing wrong in any TypeScript or JavaScript file of this project, which the compiler already accepts', async () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    let checked = 0;
    for (const name of await readdir(root)) {
      for (const folder of ['src', 'test', 'bin']) {
        const files = await readdir(join(root, name, folder), { recursive: true }).catch(() => [] as string[]);
        for (const file of files.filter((entry) => /\.(ts|mjs)$/.test(entry))) {
          const text = await readFile(join(root, name, folder, file), 'utf8');
          const report = await checkSyntax(file, text);
          assert.deepEqual(report?.problems ?? [], [], `${name}/${folder}/${file} was flagged: a valid file must never be`);
          checked += 1;
        }
      }
    }
    assert.ok(checked > 100, `only ${checked} files were checked`);
  });
});

describe('the grammars themselves', () => {
  it('all match their pinned hashes, and work next to the bash parser in one process', async () => {
    assert.deepEqual(await unusableGrammars(), []);
    assert.ok(await loadBashParser());
    assert.equal(await problems('a.ts', 'const a = 1;'), 0);
    assert.equal(await problems('a.sh', 'echo hi'), 0);
  });
});
