// Packs the VS Code extension into a .vsix. A developer tool, not part of hn. Nothing is published.
//
//   node --disable-proto=throw scripts/pack-vsix.ts --version 0.1.0 --out <folder>
//
// A .vsix is a zip: `extension/` (the manifest, the compiled JavaScript, the readme and licence), an
// `extension.vsixmanifest` and `[Content_Types].xml`. The extension has no runtime dependency, so nothing is vendored.
// The zip is written by the small writer below with a fixed timestamp and sorted entries, so two packs of one commit
// are byte-identical. Publishing to a marketplace is the owner's step, with the owner's publisher account.

import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { crc32, deflateRawSync } from 'node:zlib';
import { EXTENSION_DIR, buildExtension } from './build-vscode.ts';

const ROOT = join(import.meta.dirname, '..');

export interface ZipEntry {
  readonly path: string;
  readonly data: Buffer;
}

/** A zip with deflate, UTF-8 names, and the DOS epoch (1980-01-01) as every file's time. */
export function zip(entries: readonly ZipEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const entry of sorted) {
    const name = Buffer.from(entry.path, 'utf8');
    const packed = deflateRawSync(entry.data, { level: 9 });
    const sum = crc32(entry.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(sum, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    parts.push(local, name, packed);
    const head = Buffer.alloc(46);
    head.writeUInt32LE(0x02014b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(20, 6);
    head.writeUInt16LE(0x0800, 8);
    head.writeUInt16LE(8, 10);
    head.writeUInt16LE(0, 12);
    head.writeUInt16LE(0x21, 14);
    head.writeUInt32LE(sum, 16);
    head.writeUInt32LE(packed.length, 20);
    head.writeUInt32LE(entry.data.length, 24);
    head.writeUInt16LE(name.length, 28);
    head.writeUInt32LE(offset, 42);
    central.push(head, name);
    offset += local.length + name.length + packed.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

const escapeXml = (text: string): string => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export interface Packed {
  readonly path: string;
  readonly id: string;
  readonly sha256: string;
  readonly files: readonly string[];
}

export async function packVsix(options: { version: string; out: string }): Promise<Packed> {
  if (!/^\d+\.\d+\.\d+$/.test(options.version)) throw new Error('--version must look like 0.1.0.');
  // Compiled into a folder of its own and read at once: `dist` belongs to the editor tests, and building it here would
  // delete it under a VS Code that is loading it.
  const scratch = await mkdtemp(join(tmpdir(), 'hn-vsix-build-'));
  const compiled: ZipEntry[] = [];
  try {
    const built = await buildExtension(scratch);
    for (const name of (await readdir(built)).filter((file) => file.endsWith('.js')).sort()) compiled.push({ path: `extension/dist/${name}`, data: await readFile(join(built, name)) });
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
  const source = JSON.parse(await readFile(join(EXTENSION_DIR, 'package.json'), 'utf8')) as Record<string, unknown>;
  // The workspace's private name and dev dependencies stay behind. The extension's own id is publisher.name.
  const { devDependencies: _dev, private: _private, ...rest } = source;
  const manifest: Record<string, unknown> = {
    ...rest,
    name: 'haven-harness',
    version: options.version,
    repository: { type: 'git', url: 'https://github.com/AkbarSheikh-debug/Haven-Harness.git' },
    homepage: 'https://github.com/AkbarSheikh-debug/Haven-Harness',
    bugs: { url: 'https://github.com/AkbarSheikh-debug/Haven-Harness/issues' },
  };
  const publisher = String(manifest['publisher']);
  const files: ZipEntry[] = [{ path: 'extension/package.json', data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) }];
  files.push(...compiled);
  files.push({ path: 'extension/readme.md', data: await readFile(join(EXTENSION_DIR, 'README.md')) });
  files.push({ path: 'extension/LICENSE.txt', data: await readFile(join(ROOT, 'LICENSE')) });
  const engine = String((manifest['engines'] as Record<string, unknown>)['vscode']);
  const vsix = `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="haven-harness" Version="${options.version}" Publisher="${escapeXml(publisher)}" />
    <DisplayName>${escapeXml(String(manifest['displayName']))}</DisplayName>
    <Description xml:space="preserve">${escapeXml(String(manifest['description']))}</Description>
    <Tags></Tags>
    <Categories>Other</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="${escapeXml(engine)}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
    </Properties>
    <License>extension/LICENSE.txt</License>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" />
  </Installation>
  <Dependencies />
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/readme.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE.txt" Addressable="true" />
  </Assets>
</PackageManifest>
`;
  files.push({ path: 'extension.vsixmanifest', data: Buffer.from(vsix) });
  files.push({
    path: '[Content_Types].xml',
    data: Buffer.from(
      '<?xml version="1.0" encoding="utf-8"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".md" ContentType="text/markdown"/><Default Extension=".txt" ContentType="text/plain"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>\n',
    ),
  });
  const bytes = zip(files);
  await mkdir(options.out, { recursive: true });
  const path = join(options.out, `haven-harness-${options.version}.vsix`);
  await writeFile(path, bytes);
  return { path, id: `${publisher}.haven-harness`, sha256: createHash('sha256').update(bytes).digest('hex'), files: files.map((file) => file.path).sort() };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const { values } = parseArgs({ options: { version: { type: 'string' }, out: { type: 'string' } } });
  if (values.version === undefined || values.out === undefined) throw new Error('Usage: pack-vsix.ts --version 0.1.0 --out <folder>');
  const packed = await packVsix({ version: values.version, out: values.out });
  console.log(`${packed.path}\nsha256 ${packed.sha256}\n${packed.files.join('\n')}`);
}
