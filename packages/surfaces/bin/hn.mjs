#!/usr/bin/env node
// Every run gets --disable-proto=throw, which cannot be turned on after startup.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const result = spawnSync(process.execPath, ['--disable-proto=throw', '--no-warnings', main, ...process.argv.slice(2)], {
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
