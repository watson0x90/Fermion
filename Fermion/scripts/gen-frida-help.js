// Generates src/frida-help.json — the documentation index behind the REPL's
// `help <name>` — from the Frida type definitions in node_modules. Run by
// `npm run build` (see esbuild.config.mjs); the output is a build artifact and
// is not committed.
//   node scripts/gen-frida-help.js
const fs = require('fs');
const path = require('path');
const { buildHelpIndex } = require('../src/frida-help-index.js');

const SRC = path.join(__dirname, '..', 'node_modules', '@types', 'frida-gum', 'index.d.ts');
const OUT = path.join(__dirname, '..', 'src', 'frida-help.json');

function generate() {
  const index = buildHelpIndex(fs.readFileSync(SRC, 'utf8'));
  fs.writeFileSync(OUT, JSON.stringify(index));
  return { entries: Object.keys(index).length, bytes: fs.statSync(OUT).size, out: OUT };
}

if (require.main === module) {
  const r = generate();
  console.log(`frida-help: ${r.entries} entries, ${(r.bytes / 1024).toFixed(0)} KB -> src/frida-help.json`);
}

module.exports = { generate };
