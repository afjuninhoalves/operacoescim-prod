// scripts/postinstall-puppeteer.cjs
'use strict';

const { spawnSync } = require('child_process');

const isLinux = process.platform === 'linux';

// Em dev (Windows/macOS), não precisa baixar Chromium
if (!isLinux) {
  console.log('[postinstall] Windows/macOS detectado — pulando download do Chromium (ok para dev).');
  process.exit(0);
}

// No Render (Linux), baixar o Chromium pinado pelo Puppeteer
const env = {
  ...process.env,
  PUPPETEER_CACHE_DIR: '/opt/render/.cache/puppeteer',
  PUPPETEER_SKIP_DOWNLOAD: '', // não pular download
};

console.log('[postinstall] Instalando Chromium pinado pelo puppeteer...');
const res = spawnSync(process.execPath, ['node_modules/puppeteer/install.js'], {
  stdio: 'inherit',
  env,
});
if (res.status !== 0) {
  console.error('[postinstall] Falha ao baixar Chromium. Código:', res.status);
  process.exit(res.status || 1);
}
console.log('[postinstall] Chromium instalado com sucesso.');
