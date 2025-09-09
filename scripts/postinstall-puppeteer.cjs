// scripts/postinstall-puppeteer.cjs
const { spawnSync } = require('child_process');

if (process.platform === 'win32') {
  console.log('[postinstall] Windows detectado — pulando download do Chrome (ok para desenvolvimento).');
  process.exit(0);
}

const env = {
  ...process.env,
  // No Render, vamos usar esse cache (não quebra em dev/local)
  PUPPETEER_CACHE_DIR: process.env.PUPPETEER_CACHE_DIR || '/opt/render/.cache/puppeteer'
};

console.log('[postinstall] Instalando Chrome para o Puppeteer...');
const r = spawnSync('npx', ['puppeteer', 'browsers', 'install', 'chrome'], {
  stdio: 'inherit',
  env,
  shell: true
});

process.exit(r.status ?? 0);
