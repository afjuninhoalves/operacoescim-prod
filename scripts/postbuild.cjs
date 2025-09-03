// scripts/postbuild.cjs
const fs = require('fs');
const path = require('path');

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;           // se não existir, só ignora
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

fs.mkdirSync('dist/views', { recursive: true });
fs.mkdirSync('dist/public', { recursive: true });

copyDir('src/views', 'dist/views');
copyDir('public', 'dist/public');
