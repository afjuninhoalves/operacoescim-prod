#!/usr/bin/env node
/* Baixa o Chrome no Render (Linux). No Windows/local, só pula. */
const { execSync } = require('child_process');

const isLinux = process.platform === 'linux';

if (!isLinux) {
  console.log('[postinstall] Ambiente não-Linux detectado — pulando download do Chrome (ok para desenvolvimento local).');
  process.exit(0);
}

try {
  // Use o mesmo caminho que o Puppeteer usará em runtime
  process.env.PUPPETEER_CACHE_DIR = process.env.PUPPETEER_CACHE_DIR || '/opt/render/.cache/puppeteer';
  console.log('[postinstall] Baixando Chrome para:', process.env.PUPPETEER_CACHE_DIR);

  // Usa o gerenciador de browsers oficial do Puppeteer (compatível com v24+)
  execSync('npx --yes puppeteer@24.19.0 browsers install chrome', {
    stdio: 'inherit',
    env: process.env,
  });

  console.log('[postinstall] Chrome baixado com sucesso.');
} catch (e) {
  console.error('[postinstall] Falha ao baixar o Chrome:', e?.message || e);
  process.exit(1);
}
