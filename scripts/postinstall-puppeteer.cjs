// scripts/postinstall-puppeteer.cjs
const { spawnSync } = require('child_process');

const isLinux = process.platform === 'linux';
if (!isLinux) {
  console.log('[postinstall] Ambiente não-Linux detectado — pulando download do Chrome (ok local/Windows).');
  process.exit(0);
}

const cacheDir = process.env.PUPPETEER_CACHE_DIR || '/opt/render/.cache/puppeteer';
const pptrVersion = require('puppeteer/package.json').version;

console.log(`[postinstall] Instalando Chrome via Puppeteer CLI (v${pptrVersion}) em: ${cacheDir}`);

const res = spawnSync(
  'npx',
  ['--yes', `puppeteer@${pptrVersion}`, 'browsers', 'install', 'chrome', '--path', cacheDir],
  {
    stdio: 'inherit',
    env: { ...process.env, PUPPETEER_CACHE_DIR: cacheDir },
    shell: true, // garante que o 'npx' seja resolvido no ambiente do Render
  }
);

if (res.status !== 0) {
  console.error('[postinstall] Falha ao baixar o Chrome.');
  process.exit(res.status || 1);
}

console.log('[postinstall] Chrome instalado com sucesso.');
