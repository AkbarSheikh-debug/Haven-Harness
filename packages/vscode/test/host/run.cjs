// Loaded by a real VS Code (--extensionTestsPath) inside its extension host. It runs the suite the driver names and
// writes the outcome to a file, because a window has no terminal to print to. A thrown error also fails the exit code.
const { pathToFileURL } = require('node:url');
const path = require('node:path');
const fs = require('node:fs');

exports.run = async () => {
  const result = process.env.HN_HOST_RESULT;
  try {
    const suite = await import(pathToFileURL(path.join(__dirname, process.env.HN_HOST_SUITE)).href);
    await suite.run(JSON.parse(fs.readFileSync(process.env.HN_HOST_CONFIG, 'utf8')));
    fs.writeFileSync(result, JSON.stringify({ ok: true }));
  } catch (error) {
    fs.writeFileSync(result, JSON.stringify({ ok: false, error: String((error && error.stack) || error) }));
    throw error;
  }
};
