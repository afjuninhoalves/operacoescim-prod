// src/server.ts
import express from 'express';
import session from 'express-session';
import compression from 'compression';
import morgan from 'morgan';
import path from 'path';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import knex, { Knex } from 'knex';
import bcrypt from 'bcryptjs';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import crypto from 'crypto';
import 'dotenv/config';
import { db, ensureSchemaAndAdmin } from './db/conn'; 

const app = express();

// rota de teste para confirmar conexão com Neon
app.get('/debug/db-version', async (req, res) => {
  try {
    const r: any = await db.raw('SELECT version()'); // PG -> r.rows[0].version
    const version = r?.rows?.[0]?.version || r?.[0]?.version || 'ok';
    res.type('text').send(version);
  } catch (err: any) {
    console.error(err);
    res.status(500).send('Erro na conexão com o banco: ' + err.message);
  }
});




const NODE_ENV = process.env.NODE_ENV || 'development';
const IN_PROD = NODE_ENV === 'production';



// Permissão genérica para EDITAR um evento (fiscalização/pessoa/veículo/apreensão)
async function canEditEvento(
  user: any,
  operacao_id: number | string,
  evento_id: number | string
): Promise<{ ok: boolean; reason?: string; evento?: any; status?: number }> {
  const oId = Number(operacao_id);
  const eId = Number(evento_id);

  if (!Number.isFinite(oId) || oId <= 0 || !Number.isFinite(eId) || eId <= 0) {
    return { ok: false, reason: 'Parâmetros inválidos (opId/eventoId).', status: 400 };
  }

  const evento = await db('operacao_eventos')
    .where('operacao_id', oId)
    .andWhere('id', eId)
    .first();

  if (!evento) return { ok: false, reason: 'Evento não encontrado.', status: 404 };

  if (['admin', 'gestor'].includes(user?.role)) return { ok: true, evento };

  if (user?.cidade_id === evento.cidade_id || user?.id === evento.user_id) {
    return { ok: true, evento };
  }

  return { ok: false, reason: 'Sem permissão.', status: 403 };
}

function pickReturnTo(req: express.Request, fallback: string) {
  const raw = String((req.body as any)?.return_to || '');
  // evita open-redirect: só paths locais simples
  if (raw && /^\/[A-Za-z0-9/_?&=.\-]*$/.test(raw)) return raw;
  return fallback;
}


// Helper: nunca retorna 0,0; valida faixa e converte para NULL quando inválido
function getGeoFromBody(req: any) {
  const lat = Number(req.body.lat ?? req.body.latitude);
  const lng = Number(req.body.lng ?? req.body.longitude);
  const acc = Number(req.body.acc ?? req.body.accuracy);

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return { lat: null, lng: null, acc: null };
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180)   return { lat: null, lng: null, acc: null };
  // descarta 0,0 e “quase 0,0”
  if (Math.abs(lat) < 0.0001 && Math.abs(lng) < 0.0001)    return { lat: null, lng: null, acc: null };

  return { lat, lng, acc: Number.isFinite(acc) ? acc : null };
}

function parseMaybeNumber(v: any): number | null {
  if (v === undefined || v === null) return null;
  if (typeof v === 'string' && v.trim() === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// helper (coloque perto dos outros helpers)
function parseLocation(body:any){
  const lat = Number(body.lat ?? body.latitude);
  const lng = Number(body.lng ?? body.longitude);
  const acc = Number(body.acc ?? body.accuracy);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  // descarta 0,0 e quase 0,0
  if (Math.abs(lat) < 0.0001 && Math.abs(lng) < 0.0001) return null;
  return { lat, lng, accuracy: Number.isFinite(acc) ? acc : null };
}



// =============================================================================
// SEGURANÇA / MIDDLEWARES
// =============================================================================
app.set('trust proxy', 1);
if (IN_PROD) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.originalUrl);
    }
    next();
  });
}

app.use(helmet({
  contentSecurityPolicy: false,           // habilite com nonce em produção HTTPS
  crossOriginResourcePolicy: false,       // DEV por IP/porta
  referrerPolicy: { policy: 'no-referrer' }
}));

// CORS fechado (ajuste se precisar expor para um front separado)
app.use(cors({ origin: false, credentials: true }));

app.use(compression());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(process.cwd(), 'public')));

// Sessão
app.use(session({
  secret: process.env.SESSION_SECRET || 'secretkey',
  resave: false,
  saveUninitialized: false,
  name: IN_PROD ? '__Host-operacoescim.sid' : 'operacoescim.sid',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IN_PROD, // só HTTPS em produção
    path: '/',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Views e estáticos
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const staticDir = path.resolve(process.cwd(), 'public');
console.log('Servindo /public a partir de:', staticDir);
app.use('/public', express.static(staticDir));

const uploadsDir = path.resolve(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

// =============================================================================
// UPLOAD (multer) — bloco único, sem duplicações
// =============================================================================
function makeStorage(subdir: string) {
  return multer.diskStorage({
    destination: (_req, _file, cb) => {
      const dir = path.join(uploadsDir, subdir);
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
    }
  });
}

const MAX_MB = 10 * 1024 * 1024;

function tryUnlinkUpload(p?: string | null) {
  try {
    if (!p) return;
    // esperamos algo como "/uploads/alguma-pasta/arquivo.jpg"
    const rel = p.replace(/^\/+/, ''); // remove "/" inicial
    const abs = path.resolve(process.cwd(), rel);
    // só apaga se estiver dentro da pasta /uploads
    if (abs.startsWith(uploadsDir)) fs.unlink(abs, () => {});
  } catch {
    // ignora
  }
}

// Aceita imagens comuns (inclui HEIC)
function imageFilter(_req: express.Request, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  if (/^image\/(jpe?g|png|webp|gif|bmp|heic)$/i.test(file.mimetype)) return cb(null, true);
  cb(new Error('Apenas imagens são permitidas (jpg, png, webp, gif, bmp, heic).'));
}

// Uploader para fotos em geral
const uploadFotos = multer({
  storage: makeStorage('fotos'),
  limits: { fileSize: MAX_MB },
  fileFilter: imageFilter
});

// Uploader para logos
const uploadLogo = multer({
  storage: makeStorage('logos'),
  limits: { fileSize: MAX_MB },
  fileFilter: imageFilter
});

// Aceitar tanto "foto" (1) quanto "fotos" (várias) nos formulários
const uploadFotosFields = uploadFotos.fields([
  { name: 'foto',  maxCount: 1  },
  { name: 'fotos', maxCount: 10 },
]);

// Consolidar arquivos enviados em `foto` e/ou `fotos`
function fotosFromRequest(req: any): Express.Multer.File[] {
  if (req.files && !Array.isArray(req.files)) {
    const out: Express.Multer.File[] = [];
    if (Array.isArray(req.files.fotos)) out.push(...req.files.fotos);
    if (Array.isArray(req.files.foto))  out.push(...req.files.foto);
    return out;
  }
  return (req.files as Express.Multer.File[]) || [];
}


// =============================================================================
// RATE LIMIT
// =============================================================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Muitas tentativas. Tente novamente em alguns minutos.'
});
app.use('/login', authLimiter);

// =============================================================================
// CSRF (cookie mode)
// =============================================================================
const csrfProtection = csurf({
  cookie: {
    key: '_csrf',
    httpOnly: true,
    sameSite: 'lax',
    secure: IN_PROD,
    path: '/'
  }
});

// =============================================================================
// HELPERS DE AUTH/PERM
// =============================================================================
function onlyDigits(s: string): string {
  return (s || '').replace(/\D/g, '');
}
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (req.session && (req.session as any).user) return next();
  return res.redirect('/login');
}
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const user = (req.session as any).user;
  if (user?.role === 'admin') return next();
  return res.status(403).send('Acesso negado.');
}
function requireAdminOrGestor(req: express.Request, res: express.Response, next: express.NextFunction) {
  const role = (req.session as any).user?.role;
  if (role === 'admin' || role === 'gestor') return next();
  return res.status(403).send('Acesso negado.');
}
async function canUserPostOnOperation(opId: number, user: any) {
  const op = await db('operacoes').where({ id: opId }).first();
  if (!op || op.status !== 'em_andamento') return false;
  if (!user?.cidade_id) return false;
  const participante = await db('operacao_cidades')
    .where({ operacao_id: opId, cidade_id: user.cidade_id })
    .first();
  return !!participante;
}
async function createEventoBase(args: {
  operacao_id: number; cidade_id: number; user_id: number; tipo: string; obs: string | null;
}): Promise<number> {
  const isPg = !!process.env.DATABASE_URL;

  if (isPg) {
    const [row] = await db('operacao_eventos')
      .insert({
        operacao_id: args.operacao_id,
        cidade_id: args.cidade_id,
        user_id: args.user_id,
        tipo: args.tipo,
        obs: args.obs || null
      })
      .returning('id');
    return Number((row as any).id ?? row);
  } else {
    const [id] = await db('operacao_eventos').insert({
      operacao_id: args.operacao_id,
      cidade_id: args.cidade_id,
      user_id: args.user_id,
      tipo: args.tipo,
      obs: args.obs || null
    });
    return Number(id);
  }
}

async function createOperacao(args: {
  nome: string;
  descricao?: string | null;
  inicio_agendado: string | Date;
  created_by: number | null; // id do usuário logado
}): Promise<number> {
  const isPg = !!process.env.DATABASE_URL;

  // normaliza a data/hora
  const ts = (args.inicio_agendado instanceof Date)
    ? args.inicio_agendado
    : new Date(args.inicio_agendado);

  if (Number.isNaN(ts.getTime())) {
    throw new Error('Data/hora inválida para inicio_agendado');
  }

  if (isPg) {
    // Postgres: precisa do .returning('id')
    const [row] = await db('operacoes')
      .insert({
        nome: args.nome,
        descricao: args.descricao || null,
        inicio_agendado: ts,
        status: 'agendada',
        created_by: args.created_by
      })
      .returning('id'); // <-- ESSENCIAL NO PG

    // row pode ser { id: number } ou um número, dependendo da versão do driver
    const opId = typeof row === 'object' ? (row as any).id : row;
    return Number(opId);
  } else {
    // SQLite: o insert retorna [id]
    const [id] = await db('operacoes').insert({
      nome: args.nome,
      descricao: args.descricao || null,
      inicio_agendado: ts,
      status: 'agendada',
      created_by: args.created_by
    });
    return Number(id);
  }
}



//-----  Rota de health check----- 

app.get('/healthz', (_req, res) => res.status(200).send('ok'));

// =============================================================================
// AUTH
// =============================================================================
app.get('/login', csrfProtection, (_req, res) => {
  res.render('login', { csrfToken: (_req as any).csrfToken(), error: null });
});

app.post('/login', csrfProtection, async (req, res) => {
  try {
    const cpf = onlyDigits(req.body.cpf);
    const senha = String(req.body.senha || '');

    if (!cpf || !senha) {
      return res.status(400).render('login', { csrfToken: (req as any).csrfToken(), error: 'Informe CPF e senha.' });
    }
    const user = await db('usuarios').where({ cpf }).first();
    if (!user || !user.ativo) {
      return res.status(401).render('login', { csrfToken: (req as any).csrfToken(), error: 'CPF ou senha inválidos.' });
    }
    const ok = await bcrypt.compare(senha, user.senha_hash);
    if (!ok) {
      return res.status(401).render('login', { csrfToken: (req as any).csrfToken(), error: 'CPF ou senha inválidos.' });
    }

    await db('usuarios').where({ id: user.id }).update({ ultimo_login_at: db.fn.now() });

    (req.session as any).user = {
      id: user.id, cpf: user.cpf, nome: user.nome, role: user.role, cidade_id: user.cidade_id
    };

    return res.redirect('/');
  } catch (err) {
    console.error(err);
    return res.status(500).render('login', { csrfToken: (req as any).csrfToken(), error: 'Erro interno.' });
  }
});

app.post('/logout', csrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/operacoes', async (req, res) => {
  try {
    const { nome, descricao, inicio_agendado } = req.body;

    // pegue o id do usuário logado conforme sua sessão/autenticação
    const created_by = req.session?.user?.id ?? null;

    const opId = await createOperacao({
      nome,
      descricao: descricao || null,
      inicio_agendado,  // pode vir como '2025-09-01T10:30' do <input type="datetime-local">
      created_by
    });

    // redirecione/retorne já usando o ID criado
    return res.redirect(`/operacoes/${opId}`);
    // ou: res.status(201).json({ id: opId });
  } catch (err: any) {
    console.error('Erro ao criar operação:', err);
    return res.status(500).send('Falha ao criar operação: ' + err.message);
  }
});


// =============================================================================
// HOME
// =============================================================================
app.get('/', requireAuth, csrfProtection, async (req, res) => {
  const u = (req.session as any).user;
  const cidade = u?.cidade_id ? await db('cidades').where({ id: u.cidade_id }).first() : null;
  res.render('home', { user: u, cidade, csrfToken: (req as any).csrfToken() });
});

// =============================================================================
// CIDADES (ADMIN)
// =============================================================================
app.get('/cidades', requireAdmin, async (_req, res) => {
  const cidades = await db('cidades').select('*').orderBy('nome');
  res.render('cidades-list', { cidades });
});

app.get('/cidades/nova', requireAdmin, csrfProtection, (req, res) => {
  res.render('cidades-form', { csrfToken: (req as any).csrfToken(), errors: [], values: {} });
});

// ⚠️ Multer ANTES do CSRF nesta rota
app.post('/cidades/nova', requireAdmin, uploadLogo.single('logo'), csrfProtection, async (req, res) => {
  try {
    const nome = String(req.body.nome || '').trim();
    const corporacao = String(req.body.corporacao || '').trim();
    const comandante = String(req.body.comandante || '').trim();
    const contato = String(req.body.contato || '').trim();

    const errors: string[] = [];
    if (!nome) errors.push('Informe o nome da cidade.');
    if (await db('cidades').where({ nome }).first()) errors.push('Cidade já cadastrada.');

    if (errors.length) {
      return res.status(400).render('cidades-form', {
        csrfToken: (req as any).csrfToken(),
        errors, values: { nome, corporacao, comandante, contato }
      });
    }

    await db('cidades').insert({
      nome,
      corporacao: corporacao || null,
      comandante: comandante || null,
      contato: contato || null,
      logo_path: req.file ? `/uploads/logos/${req.file.filename}` : null
    });

    return res.redirect('/cidades');
  } catch (e) {
    console.error(e);
    return res.status(500).send('Erro ao cadastrar cidade.');
  }
});

// =============================================================================
// USUÁRIOS (ADMIN)
// =============================================================================
app.get('/admin/usuarios', requireAdmin, csrfProtection, async (req, res) => {
  const usuarios = await db('usuarios').select('*').orderBy('id', 'asc');
  res.render('admin-usuarios-list', { usuarios, csrfToken: (req as any).csrfToken() });
});

app.get('/admin/usuarios/novo', requireAdmin, csrfProtection, async (req, res) => {
  const cidades = await db('cidades').select('id', 'nome').orderBy('nome');
  res.render('admin-usuarios-form', {
    mode: 'create',
    csrfToken: (req as any).csrfToken(),
    cidades, errors: [], values: {}
  });
});

app.post('/admin/usuarios/novo', requireAdmin, csrfProtection, async (req, res) => {
  const cidades = await db('cidades').select('id', 'nome').orderBy('nome');
  try {
    const nome = String(req.body.nome || '').trim();
    const cpf = String(req.body.cpf || '').replace(/\D/g, '');
    const email = String(req.body.email || '').trim() || null;
    const role = String(req.body.role || 'operador');
    const cidade_id = req.body.cidade_id ? Number(req.body.cidade_id) : null;
    const senha = String(req.body.senha || '');
    const errors: string[] = [];

    if (!nome) errors.push('Informe o nome.');
    if (!cpf || cpf.length !== 11) errors.push('CPF inválido.');
    if (!['admin','gestor','operador','auditor'].includes(role)) errors.push('Perfil inválido.');
    if (!cidade_id) errors.push('Selecione a cidade.');
    if (!senha || senha.length < 10) errors.push('Senha muito curta (mín. 10).');

    if (await db('usuarios').where({ cpf }).first()) errors.push('CPF já cadastrado.');
    if (email && await db('usuarios').where({ email }).first()) errors.push('E-mail já cadastrado.');

    if (errors.length) {
      return res.status(400).render('admin-usuarios-form', {
        mode: 'create', csrfToken: (req as any).csrfToken(), cidades, errors,
        values: { nome, cpf, email, role, cidade_id }
      });
    }

    const senha_hash = await bcrypt.hash(senha, 12);
    await db('usuarios').insert({ nome, cpf, email, senha_hash, role, cidade_id, ativo: 1 });
    return res.redirect('/admin/usuarios');
  } catch (e) {
    console.error(e);
    return res.status(500).render('admin-usuarios-form', {
      mode: 'create', csrfToken: (req as any).csrfToken(), cidades,
      errors: ['Erro ao criar usuário.'], values: req.body
    });
  }
});

app.get('/admin/usuarios/:id/editar', requireAdmin, csrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const u = await db('usuarios').where({ id }).first();
  if (!u) return res.status(404).send('Usuário não encontrado.');

  const cidades = await db('cidades').select('id','nome').orderBy('nome');
  res.render('admin-usuarios-form', {
    mode: 'edit',
    csrfToken: (req as any).csrfToken(),
    cidades,
    errors: [],
    values: { id: u.id, nome: u.nome, cpf: u.cpf, email: u.email || '', role: u.role, cidade_id: u.cidade_id }
  });
});

app.post('/admin/usuarios/:id/editar', requireAdmin, csrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const cidades = await db('cidades').select('id','nome').orderBy('nome');
  try {
    const nome = String(req.body.nome || '').trim();
    const cpf = String(req.body.cpf || '').replace(/\D/g, '');
    const email = String(req.body.email || '').trim() || null;
    const role = String(req.body.role || 'operador');
    const cidade_id = req.body.cidade_id ? Number(req.body.cidade_id) : null;
    const senha = String(req.body.senha || ''); // opcional
    const errors: string[] = [];

    const u = await db('usuarios').where({ id }).first();
    if (!u) return res.status(404).send('Usuário não encontrado.');

    if (!nome) errors.push('Informe o nome.');
    if (!cpf || cpf.length !== 11) errors.push('CPF inválido.');
    if (!['admin','gestor','operador','auditor'].includes(role)) errors.push('Perfil inválido.');
    if (!cidade_id) errors.push('Selecione a cidade.');

    const dupCpf = await db('usuarios').where({ cpf }).andWhereNot({ id }).first();
    if (dupCpf) errors.push('CPF já em uso por outro usuário.');
    if (email) {
      const dupEmail = await db('usuarios').where({ email }).andWhereNot({ id }).first();
      if (dupEmail) errors.push('E-mail já em uso por outro usuário.');
    }

    if (errors.length) {
      return res.status(400).render('admin-usuarios-form', {
        mode: 'edit', csrfToken: (req as any).csrfToken(), cidades, errors,
        values: { id, nome, cpf, email, role, cidade_id }
      });
    }

    const patch: any = { nome, cpf, email, role, cidade_id };
    if (senha) patch.senha_hash = await bcrypt.hash(senha, 12);

    await db('usuarios').where({ id }).update(patch);
    return res.redirect('/admin/usuarios');
  } catch (e) {
    console.error(e);
    return res.status(500).render('admin-usuarios-form', {
      mode: 'edit', csrfToken: (req as any).csrfToken(), cidades,
      errors: ['Erro ao salvar usuário.'], values: { id, ...req.body }
    });
  }
});

app.post('/admin/usuarios/:id/toggle', requireAdmin, csrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const u = await db('usuarios').where({ id }).first();
  if (!u) return res.status(404).send('Usuário não encontrado.');
  await db('usuarios').where({ id }).update({ ativo: u.ativo ? 0 : 1 });
  return res.redirect('/admin/usuarios');
});

app.post('/admin/usuarios/:id/reset', requireAdmin, csrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const usuario = await db('usuarios').where({ id }).first();
  if (!usuario) return res.status(404).send('Usuário não encontrado.');

  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 15 * 60 * 1000);
  await db('password_resets').insert({ user_id: usuario.id, token, expires_at: expires.toISOString() });
  const link = `/reset/${token}`;
  return res.render('admin-usuarios-reset', { usuario, link });
});

app.get('/reset/:token', csrfProtection, async (req, res) => {
  const r = await db('password_resets').where({ token: req.params.token }).first();
  if (!r) return res.status(404).send('Token inválido.');
  if (new Date(r.expires_at).getTime() < Date.now()) return res.status(400).send('Token expirado.');
  res.render('reset-form', { csrfToken: (req as any).csrfToken(), token: req.params.token, errors: [] });
});

app.post('/reset/:token', csrfProtection, async (req, res) => {
  const r = await db('password_resets').where({ token: req.params.token }).first();
  if (!r) return res.status(404).send('Token inválido.');
  if (new Date(r.expires_at).getTime() < Date.now()) return res.status(400).send('Token expirado.');

  const senha = String(req.body.senha || '');
  const confirm = String(req.body.confirm || '');
  const errors: string[] = [];
  if (senha.length < 10) errors.push('Senha muito curta (mín. 10).');
  if (senha !== confirm) errors.push('Senhas não conferem.');
  if (errors.length) return res.status(400).render('reset-form', { csrfToken: (req as any).csrfToken(), token: req.params.token, errors });

  const senha_hash = await bcrypt.hash(senha, 12);
  await db('usuarios').where({ id: r.user_id }).update({ senha_hash });
  await db('password_resets').where({ id: r.id }).del();
  return res.send('Senha alterada com sucesso. Você já pode fazer login.');
});

// =============================================================================
// OPERAÇÕES
// =============================================================================

// LISTA
app.get('/operacoes', requireAuth, async (req, res) => {
  const user = (req.session as any).user;

  let opsQuery = db('operacoes').select('*').orderBy('inicio_agendado', 'desc');
  if (!['admin', 'gestor'].includes(user.role)) {
    opsQuery = opsQuery.whereIn(
      'id',
      db('operacao_cidades').select('operacao_id').where({ cidade_id: user.cidade_id })
    );
  }
  const operacoes = await opsQuery;

  const parts = await db('operacao_cidades')
    .join('cidades', 'cidades.id', 'operacao_cidades.cidade_id')
    .select('operacao_cidades.operacao_id', 'cidades.nome')
    .orderBy(['operacao_id', 'cidades.nome']);

  const participantes: Record<number, string[]> = {};
  parts.forEach((p: any) => {
    participantes[p.operacao_id] ??= [];
    participantes[p.operacao_id].push(p.nome);
  });

  res.render('operacoes-list', { user, operacoes, participantes });
});

// NOVA (ADMIN ou GESTOR)
app.get('/operacoes/nova', requireAdminOrGestor, csrfProtection, async (_req, res) => {
  const cidades = await db('cidades').select('*').orderBy('nome');
  res.render('operacoes-form', { csrfToken: (_req as any).csrfToken(), cidades, values: {}, errors: [] });
});

app.post('/operacoes/nova', requireAdminOrGestor, csrfProtection, async (req, res) => {
  try {
    const user = (req.session as any).user;
    const nome = String(req.body.nome || '').trim();
    const descricao = String(req.body.descricao || '').trim();
    const inicio_agendado = String(req.body.inicio_agendado || '').trim();

    let cidades = req.body.cidades || [];
    if (!Array.isArray(cidades)) cidades = [cidades];
    cidades = cidades.filter(Boolean).map((x: any) => Number(x));

    const errors: string[] = [];
    if (!nome) errors.push('Informe o nome da operação.');
    if (!inicio_agendado) errors.push('Informe a data/hora agendadas.');
    if (!cidades.length) errors.push('Selecione ao menos uma cidade participante.');

    if (errors.length) {
      const allCidades = await db('cidades').orderBy('nome');
      return res.status(400).render('operacoes-form', {
        csrfToken: (req as any).csrfToken(),
        cidades: allCidades,
        values: { nome, descricao, inicio_agendado, cidades },
        errors
      });
    }

    const [opId] = await db('operacoes').insert({
      nome,
      descricao: descricao || null,
      inicio_agendado,
      status: 'agendada',
      created_by: user.id
    });

    await db('operacao_cidades').insert(
      cidades.map((cid: number) => ({ operacao_id: opId, cidade_id: cid }))
    );

    return res.redirect(`/operacoes/${opId}`);
  } catch (err) {
    console.error(err);
    return res.status(500).send('Erro ao criar operação.');
  }
});

// DETALHE
app.get('/operacoes/:id', requireAuth, csrfProtection, async (req, res) => {
  const user = (req.session as any).user;
  const id = Number(req.params.id);

  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).send('Operação não encontrada.');

  const cidades = await db('operacao_cidades')
    .where({ operacao_id: id })
    .join('cidades', 'cidades.id', 'operacao_cidades.cidade_id')
    .select('cidades.id', 'cidades.nome');

  // Feed de eventos (com foto_path consolidado)
  const eventos = await db('operacao_eventos as e')
    .where('e.operacao_id', id)
    .leftJoin('cidades as c', 'c.id', 'e.cidade_id')
    .leftJoin('usuarios as u', 'u.id', 'e.user_id')
    .leftJoin('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
    .leftJoin('evento_pessoa as p', 'p.evento_id', 'e.id')
    .leftJoin('evento_veiculo as v', 'v.evento_id', 'e.id')
    .leftJoin('evento_apreensao as a', 'a.evento_id', 'e.id')
    .select(
      'e.id','e.tipo','e.ts','e.obs',
      'e.user_id as e_user_id','e.cidade_id as e_cidade_id',
      'c.nome as cidade_nome',
      'u.nome as user_nome',
      db.raw("COALESCE(p.foto_path, f.foto_path, v.foto_path, a.foto_path) as foto_path"),
      'f.tipo_local',
      'p.nome as pessoa_nome','p.cpf as pessoa_cpf',
      'v.tipo_veiculo','v.marca_modelo','v.placa',
      'a.tipo as apreensao_tipo','a.quantidade','a.unidade'
    )
    .orderBy('e.ts','desc')
    .limit(100);

  // Fiscalizações da MINHA CIDADE (para selects)
  let minhasFiscalizacoes: any[] = [];
  if (user.cidade_id) {
    minhasFiscalizacoes = await db('operacao_eventos as e')
      .where({ 'e.operacao_id': id, 'e.cidade_id': user.cidade_id, 'e.tipo': 'fiscalizacao' })
      .join('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
      .select('e.id', 'f.tipo_local', 'e.ts')
      .orderBy('e.ts', 'desc');
  }

  const podeLancar = await canUserPostOnOperation(id, user);

  const operacao = {
    ...op,
    inicio_fmt: op.inicio_agendado ? new Date(op.inicio_agendado).toLocaleString('pt-BR') : null,
    cidades_str: cidades.map((c: any) => c.nome).join(', '),
    podeEncerrar: ['admin','gestor'].includes(user?.role) && op.status !== 'encerrada'
  };

  const countOf = async (tipo: string) => {
    const row = await db('operacao_eventos').where({ operacao_id: id, tipo }).count<{ c: number }>({ c: '*' }).first();
    return Number(row?.c || 0);
  };
  const resumo = {
    fiscalizacoes: await countOf('fiscalizacao'),
    pessoas:       await countOf('pessoa'),
    veiculos:      await countOf('veiculo'),
    apreensoes:    await countOf('apreensao')
  };

  res.render('operacoes-detalhe', {
    csrfToken: (req as any).csrfToken(),
    user,
    operacao,
    cidades,
    eventos,
    fiscalizacoes: minhasFiscalizacoes.map(f => ({ id: f.id, tipo_local: f.tipo_local })),
    podeLancar,
    resumo
  });
});

// INICIAR/ENCERRAR (ADMIN ou GESTOR)
app.post('/operacoes/:id/status', requireAdminOrGestor, csrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const action = String(req.body.action || '');
  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).send('Operação não encontrada.');

  if (action === 'iniciar') {
    await db('operacoes').where({ id }).update({ status: 'em_andamento' });
  } else if (action === 'encerrar') {
    await db('operacoes').where({ id }).update({ status: 'encerrada' });
  }
  return res.redirect(`/operacoes/${id}`);
});

// =============================================================================
// EVENTOS — ⚠️ multer ANTES do csrfProtection
// =============================================================================


// -----------------------------------------------------------------------------
// Fiscalização
app.post('/operacoes/:id/fiscalizacoes',
  requireAuth, uploadFotosFields, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    if (!user?.cidade_id) return res.status(400).send('Usuário sem cidade vinculada.');
    if (!(await canUserPostOnOperation(operacao_id, user))) return res.status(403).send('Sem permissão.');

    const tipo_local = String(req.body.tipo_local || '').trim();
    const obs = String(req.body.obs || '').trim() || null;
    if (!tipo_local) return res.redirect(go);

    const evento_id = await createEventoBase({
      operacao_id, cidade_id: user.cidade_id, user_id: user.id, tipo: 'fiscalizacao', obs
    });

    await db('evento_fiscalizacao').insert({ evento_id, tipo_local });

    const files = fotosFromRequest(req);
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat, lng, accuracy: acc
        }))
      );
    }
    return res.redirect(go);
  }
);

// Pessoa
app.post('/operacoes/:id/pessoas',
  requireAuth, uploadFotosFields, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    if (!user?.cidade_id) return res.status(400).send('Usuário sem cidade vinculada.');
    if (!(await canUserPostOnOperation(operacao_id, user))) return res.status(403).send('Sem permissão.');

    const nome = String(req.body.nome || '').trim();
    const cpf = onlyDigits(req.body.cpf || '');
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

    const evento_id = await createEventoBase({
      operacao_id, cidade_id: user.cidade_id, user_id: user.id, tipo: 'pessoa', obs
    });

    const files = fotosFromRequest(req);
    const primeira = files[0] ? `/uploads/fotos/${files[0].filename}` : null;

    await db('evento_pessoa').insert({
      evento_id,
      nome: nome || null,
      cpf: cpf || null,
      foto_path: primeira, // compat legado
      fiscalizacao_evento_id: fiscalizacao_id || null
    });

    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat, lng, accuracy: acc
        }))
      );
    }
    return res.redirect(go);
  }
);

// Veículo
app.post('/operacoes/:id/veiculos',
  requireAuth, uploadFotosFields, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    if (!user?.cidade_id) return res.status(400).send('Usuário sem cidade vinculada.');
    if (!(await canUserPostOnOperation(operacao_id, user))) return res.status(403).send('Sem permissão.');

    const tipo_veiculo = String(req.body.tipo_veiculo || '').trim();
    const marca_modelo = String(req.body.marca_modelo || '').trim();
    const placa = String(req.body.placa || '').trim().toUpperCase();
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

    const evento_id = await createEventoBase({
      operacao_id, cidade_id: user.cidade_id, user_id: user.id, tipo: 'veiculo', obs
    });

    await db('evento_veiculo').insert({
      evento_id,
      tipo_veiculo: tipo_veiculo || null,
      marca_modelo: marca_modelo || null,
      placa: placa || null,
      fiscalizacao_evento_id: fiscalizacao_id || null
    });

    const files = fotosFromRequest(req);
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat, lng, accuracy: acc
        }))
      );
    }
    return res.redirect(go);
  }
);

// Apreensão
app.post('/operacoes/:id/apreensoes',
  requireAuth, uploadFotosFields, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    if (!user?.cidade_id) return res.status(400).send('Usuário sem cidade vinculada.');
    if (!(await canUserPostOnOperation(operacao_id, user))) return res.status(403).send('Sem permissão.');

    const tipo = String(req.body.tipo || '').trim();
    const quantidade = req.body.quantidade ? Number(req.body.quantidade) : null;
    const unidade = String(req.body.unidade || '').trim() || null;
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

    const evento_id = await createEventoBase({
      operacao_id, cidade_id: user.cidade_id, user_id: user.id, tipo: 'apreensao', obs
    });

    await db('evento_apreensao').insert({
      evento_id, tipo: tipo || null, quantidade, unidade, fiscalizacao_evento_id: fiscalizacao_id || null
    });

    const files = fotosFromRequest(req);
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat, lng, accuracy: acc
        }))
      );
    }
    return res.redirect(go);
  }
);



// Anexar mais fotos a um evento existente




// -----------------------------------------------------------------------------
// GALERIA DE FOTOS DA OPERAÇÃO
// -----------------------------------------------------------------------------
app.get('/operacoes/:id/fotos', requireAuth, async (req, res) => {
  const user = (req.session as any).user;
  const id = Number(req.params.id);

  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).send('Operação não encontrada.');

  if (!['admin', 'gestor'].includes(user.role)) {
    const participa = await db('operacao_cidades')
      .where({ operacao_id: id, cidade_id: user.cidade_id })
      .first();
    if (!participa) return res.status(403).send('Sem permissão para ver esta operação.');
  }

  const cidadeFilter = req.query.cidade_id ? Number(req.query.cidade_id) : null;
  const tipoFilter   = req.query.tipo ? String(req.query.tipo) : null; // pessoa|veiculo|apreensao|fiscalizacao

  const cidades = await db('operacao_cidades')
    .where({ operacao_id: id })
    .join('cidades', 'cidades.id', 'operacao_cidades.cidade_id')
    .select('cidades.id', 'cidades.nome')
    .orderBy('cidades.nome');

  // 1) Fonte principal: EVENTO_FOTOS
  const fotosEF = await db('evento_fotos as ef')
    .join('operacao_eventos as e', 'e.id', 'ef.evento_id')
    .join('cidades as c', 'c.id', 'e.cidade_id')
    .where('e.operacao_id', id)
    .modify(q => { if (cidadeFilter) q.andWhere('e.cidade_id', cidadeFilter); })
    .modify(q => { if (tipoFilter)   q.andWhere('e.tipo', tipoFilter); })
    .select('ef.path', 'e.tipo', 'e.ts', 'c.nome as cidade_nome');

  // 2) Legado: foto_path de PESSOA **apenas** se o evento não tem fotos em evento_fotos
  const legado: any[] = [];
  try {
    const hasPessoaFoto = await db.schema.hasColumn('evento_pessoa', 'foto_path');
    if (hasPessoaFoto) {
      const pRows = await db('operacao_eventos as e')
        .join('cidades as c', 'c.id', 'e.cidade_id')
        .join('evento_pessoa as p', 'p.evento_id', 'e.id')
        .where('e.operacao_id', id)
        .whereNotNull('p.foto_path')
        // evita duplicar com evento_fotos
        .whereNotExists(
          db('evento_fotos as ef').select(db.raw('1')).whereRaw('ef.evento_id = e.id')
        )
        .modify(q => { if (cidadeFilter) q.andWhere('e.cidade_id', cidadeFilter); })
        .modify(q => { if (tipoFilter)   q.andWhere('e.tipo', tipoFilter); })
        .select('p.foto_path as path', 'e.tipo', 'e.ts', 'c.nome as cidade_nome');

      legado.push(...pRows);
    }
  } catch { /* ignore introspection errors */ }

  // 3) Junta e deduplica por path; ordena por data desc
  const byPath = new Map<string, any>();
  for (const r of [...fotosEF, ...legado]) {
    if (!byPath.has(r.path)) byPath.set(r.path, r);
  }
  const fotos = Array.from(byPath.values()).sort(
    (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
  );

  res.render('operacoes-fotos', {
    user,
    operacao: op,
    cidades,
    fotos,
    filtro: { cidade_id: cidadeFilter, tipo: tipoFilter }
  });
});


// =============================================================================
// MONITOR (ADMIN/GESTOR)
// =============================================================================
async function buildOperationMetrics(opId: number) {
  // Conta por tipo
  type TotRow = { tipo: string; c: number };

  const totRows = (await db('operacao_eventos as e')
    .where('e.operacao_id', opId)
    .select('e.tipo')
    .count<{ c: number }>('e.id as c')     // alias portátil p/ SQLite e Postgres
    .groupBy('e.tipo')) as TotRow[];

  const totals = { fiscalizacoes: 0, pessoas: 0, veiculos: 0, apreensoes: 0 };
  for (const r of totRows) {
    if (r.tipo === 'fiscalizacao') totals.fiscalizacoes = Number(r.c);
    if (r.tipo === 'pessoa')       totals.pessoas       = Number(r.c);
    if (r.tipo === 'veiculo')      totals.veiculos      = Number(r.c);
    if (r.tipo === 'apreensao')    totals.apreensoes    = Number(r.c);
  }
  const participantes = await db('operacao_cidades as oc')
    .where('oc.operacao_id', opId)
    .join('cidades as c', 'c.id', 'oc.cidade_id')
    .select('c.id', 'c.nome')
    .orderBy('c.nome');

  const grouped = await db('operacao_eventos as e')
    .where('e.operacao_id', opId)
    .join('cidades as c', 'c.id', 'e.cidade_id')
    .select('c.id as cidade_id', 'c.nome as cidade_nome', 'e.tipo')
    .count<{ c: number }>({ c: '*' })
    .groupBy('c.id', 'c.nome', 'e.tipo');

  const byCity: Record<number, any> = {};
  for (const p of participantes) {
    byCity[p.id] = { cidade_id: p.id, cidade: p.nome, fiscalizacoes: 0, pessoas: 0, veiculos: 0, apreensoes: 0 };
  }
  for (const r of grouped as any[]) {
    const row = byCity[r.cidade_id] || (byCity[r.cidade_id] = {
      cidade_id: r.cidade_id, cidade: r.cidade_nome, fiscalizacoes: 0, pessoas: 0, veiculos: 0, apreensoes: 0
    });
    if (r.tipo === 'fiscalizacao') row.fiscalizacoes = Number(r.c);
    if (r.tipo === 'pessoa')       row.pessoas       = Number(r.c);
    if (r.tipo === 'veiculo')      row.veiculos      = Number(r.c);
    if (r.tipo === 'apreensao')    row.apreensoes    = Number(r.c);
  }
  const perCity = Object.values(byCity).sort((a: any, b: any) => a.cidade.localeCompare(b.cidade));

  const latest = await db('operacao_eventos as e')
    .where('e.operacao_id', opId)
    .leftJoin('cidades as c', 'c.id', 'e.cidade_id')
    .leftJoin('usuarios as u', 'u.id', 'e.user_id')
    .select('e.id', 'e.ts', 'e.tipo', 'e.obs', 'c.nome as cidade', 'u.nome as usuario')
    .orderBy('e.ts', 'desc')
    .limit(20);

  return { totals, perCity, latest };
}

app.get('/operacoes/:id/monitor', requireAdminOrGestor, async (req, res) => {
  const id = Number(req.params.id);
  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).send('Operação não encontrada.');

  const operacao = {
    ...op,
    inicio_fmt: op.inicio_agendado ? new Date(op.inicio_agendado).toLocaleString('pt-BR') : null
  };
  res.render('operacoes-monitor', { operacao });
});

app.get('/operacoes/:id/metrics', requireAdminOrGestor, async (req, res) => {
  const id = Number(req.params.id);
  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).json({ error: 'Operação não encontrada' });

  const data = await buildOperationMetrics(id);

  res.json({
    op: { id: op.id, nome: op.nome, status: op.status, inicio_agendado: op.inicio_agendado },
    totals: data.totals,
    perCity: data.perCity,
    latest: data.latest,
    serverTime: new Date().toISOString()
  });
});


app.get('/usuarios', requireAdmin, (_req, res) => res.redirect('/admin/usuarios'));
app.get('/usuarios/novo', requireAdmin, (_req, res) => res.redirect('/admin/usuarios/novo'));

// =============================================================================
// FISCALIZAÇÃO: EDITAR + GERENCIAR FOTOS
// =============================================================================


// GET editar fiscalização
app.get('/operacoes/:opId/fiscalizacoes/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op    = await db('operacoes').where({ id: opId }).first();
    const f     = await db('evento_fiscalizacao').where({ evento_id: eventoId }).first();
    const fotos = await db('evento_fotos').where({ evento_id: eventoId }).orderBy('id', 'desc');

    return res.render('fiscalizacao-edit', {
      csrfToken: (req as any).csrfToken(),
      user,
      operacao: op,
      operacaoId: opId,
      eventoId,
      values: { tipo_local: f?.tipo_local || '', obs: perm.evento?.obs || '' },
      fotos
    });
  }
);






// POST: salvar alterações na fiscalização + (opcional) anexar novas fotos
// Aceita campos: tipo_local, obs e (opcional) fotos[] / foto
app.post('/operacoes/:opId/fiscalizacoes/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const tipo_local = String(req.body.tipo_local || '').trim();
    const obs        = String(req.body.obs || '').trim() || null;
    if (!tipo_local) return res.status(400).send('Informe o tipo de local.');

    await db('evento_fiscalizacao').where({ evento_id: eventoId }).update({ tipo_local });
    await db('operacao_eventos').where({ id: eventoId }).update({ obs });

    return res.redirect(`/operacoes/${opId}/fiscalizacoes/${eventoId}/editar`);
  }
);

app.post('/operacoes/:opId/fiscalizacoes/:eventoId/fotos',
  requireAuth,
  uploadFotosFields,   // << primeiro o multer (lê o body)
  csrfProtection,      // << depois valida o _csrf
  async (req, res) => {
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const files = fotosFromRequest(req); // aceita "foto" e/ou "fotos[]"
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({ evento_id: eventoId, path: `/uploads/fotos/${f.filename}` }))
      );
    }
    return res.redirect(`/operacoes/${opId}/fiscalizacoes/${eventoId}/editar`);
  }
);



// POST: remover UMA foto da fiscalização

app.post('/operacoes/:opId/fiscalizacoes/:eventoId/fotos/:fotoId/delete',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);
    const fotoId = Number(req.params.fotoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const foto = await db('evento_fotos').where({ id: fotoId, evento_id: eventoId }).first();
    if (foto) {
      await db('evento_fotos').where({ id: fotoId }).del();
      tryUnlinkUpload(foto.path);
    }
    return res.redirect(`/operacoes/${opId}/fiscalizacoes/${eventoId}/editar`);
  }
);




// =============================================================================
// REGISTROS (lista unificada de eventos) — fiscalizações, pessoas, veículos, apreensões
// =============================================================================
app.get('/registros', requireAuth, csrfProtection, async (req, res) => {
  const user = (req.session as any).user;

  const tipo = String((req.query.tipo as string) || '').trim(); // 'fiscalizacao'|'pessoa'|'veiculo'|'apreensao'|''(todos)
  const opId = req.query.opId ? Number(req.query.opId) : null;
  const cidadeId = req.query.cidade_id ? Number(req.query.cidade_id) : null;
  const q = String((req.query.q as string) || '').trim();
  const from = String((req.query.from as string) || '').trim(); // YYYY-MM-DD ou datetime
  const to = String((req.query.to as string) || '').trim();     // YYYY-MM-DD ou datetime
  const page = Math.max(1, Number(req.query.page) || 1);
  const PAGE_SIZE = 20;

  let base = db('operacao_eventos as e')
    .join('operacoes as o', 'o.id', 'e.operacao_id')
    .join('cidades as c', 'c.id', 'e.cidade_id')
    .leftJoin('usuarios as u', 'u.id', 'e.user_id')
    .leftJoin('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
    .leftJoin('evento_pessoa as p', 'p.evento_id', 'e.id')
    .leftJoin('evento_veiculo as v', 'v.evento_id', 'e.id')
    .leftJoin('evento_apreensao as a', 'a.evento_id', 'e.id')
    .select(
      'e.id', 'e.tipo', 'e.ts', 'e.operacao_id', 'e.cidade_id',
      'o.nome as op_nome',
      'c.nome as cidade_nome',
      'u.nome as user_nome',
      'e.obs',
      db.raw('(SELECT COUNT(*) FROM evento_fotos ef WHERE ef.evento_id = e.id) as fotos'),
      'f.tipo_local',
      'p.nome as pessoa_nome', 'p.cpf as pessoa_cpf',
      'v.tipo_veiculo', 'v.marca_modelo', 'v.placa',
      'a.tipo as apreensao_tipo', 'a.quantidade', 'a.unidade'
    );

  // Permissão: admin/gestor vê tudo; demais veem apenas operações nas quais sua cidade participa
  if (!['admin', 'gestor'].includes(user.role)) {
    base = base.whereIn(
      'e.operacao_id',
      db('operacao_cidades').select('operacao_id').where({ cidade_id: user.cidade_id })
    );
  }

  // Filtros
  if (tipo && tipo !== 'todos') base = base.andWhere('e.tipo', tipo);
  if (opId) base = base.andWhere('e.operacao_id', opId);
  if (cidadeId) base = base.andWhere('e.cidade_id', cidadeId);

  if (from) base = base.andWhere('e.ts', '>=', from);
  if (to) {
    const toValue = to.length === 10 ? `${to} 23:59:59` : to;
    base = base.andWhere('e.ts', '<=', toValue);
  }

  if (q) {
    base = base.andWhere(qb => {
      qb.where('o.nome', 'like', `%${q}%`)
        .orWhere('c.nome', 'like', `%${q}%`)
        .orWhere('u.nome', 'like', `%${q}%`)
        .orWhere('e.obs', 'like', `%${q}%`)
        .orWhere('f.tipo_local', 'like', `%${q}%`)
        .orWhere('p.nome', 'like', `%${q}%`)
        .orWhere('p.cpf', 'like', `%${q}%`)
        .orWhere('v.marca_modelo', 'like', `%${q}%`)
        .orWhere('v.placa', 'like', `%${q}%`)
        .orWhere('a.tipo', 'like', `%${q}%`);
    });
  }

  // Total + paginação
  const countRow = await base.clone().clearSelect().clearOrder().count<{ c: number }>({ c: '*' }).first();
  const total = Number(countRow?.c || 0);
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const registros = await base.orderBy('e.ts', 'desc')
    .limit(PAGE_SIZE)
    .offset((page - 1) * PAGE_SIZE);

  // Listas para filtros (operações e cidades)
  let opsList;
  if (['admin', 'gestor'].includes(user.role)) {
    opsList = await db('operacoes').select('id', 'nome').orderBy('inicio_agendado', 'desc');
  } else {
    opsList = await db('operacoes')
      .whereIn('id',
        db('operacao_cidades').select('operacao_id').where({ cidade_id: user.cidade_id })
      )
      .select('id', 'nome')
      .orderBy('inicio_agendado', 'desc');
  }
  const cidades = await db('cidades').select('id', 'nome').orderBy('nome');

  res.render('registros-list', {
    csrfToken: (req as any).csrfToken(),
    user,
    filtros: { tipo, opId, cidadeId, q, from, to },
    opsList,
    cidades,
    page, pages, total,
    registros
  });
});

// =============================================================================
// PESSOA: EDITAR + GERENCIAR FOTOS
// =============================================================================

// GET editar pessoa
app.get('/operacoes/:opId/pessoas/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op  = await db('operacoes').where({ id: opId }).first();
    const det = await db('evento_pessoa').where({ evento_id: eventoId }).first();
    const fotos = await db('evento_fotos').where({ evento_id: eventoId }).orderBy('id', 'desc');

    // fiscalizações da MESMA cidade deste evento (para vincular)
    const fiscList = await db('operacao_eventos as e')
      .join('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
      .where({ 'e.operacao_id': opId, 'e.cidade_id': perm.evento!.cidade_id, 'e.tipo': 'fiscalizacao' })
      .select('e.id', 'f.tipo_local')
      .orderBy('e.ts', 'desc');

    return res.render('pessoa-edit', {
      csrfToken: (req as any).csrfToken(),
      user,
      operacao: op,
      operacaoId: opId,
      eventoId,
      values: {
        nome: det?.nome || '',
        cpf: det?.cpf || '',
        fiscalizacao_id: det?.fiscalizacao_evento_id || '',
        obs: perm.evento?.obs || ''
      },
      fiscList,
      fotos
    });
  }
);

// POST salvar campos (sem upload)
app.post('/operacoes/:opId/pessoas/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const nome  = String(req.body.nome || '').trim();
    const cpf   = String(req.body.cpf || '').replace(/\D/g, '');
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs   = String(req.body.obs || '').trim() || null;

    await db('evento_pessoa').where({ evento_id: eventoId }).update({
      nome: nome || null,
      cpf: cpf || null,
      fiscalizacao_evento_id: fiscalizacao_id
    });
    await db('operacao_eventos').where({ id: eventoId }).update({ obs });

    return res.redirect(`/operacoes/${opId}/pessoas/${eventoId}/editar`);
  }
);

// POST anexar fotos (multer antes do csrf!)
app.post('/operacoes/:opId/pessoas/:eventoId/fotos',
  requireAuth,
  uploadFotosFields,
  csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const files = fotosFromRequest(req);
    if (files.length) {
      await db('evento_fotos').insert(files.map(f => ({
        evento_id: eventoId, path: `/uploads/fotos/${f.filename}`
      })));
    }
    return res.redirect(`/operacoes/${opId}/pessoas/${eventoId}/editar`);
  }
);

// POST remover foto
app.post('/operacoes/:opId/pessoas/:eventoId/fotos/:fotoId/delete',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);
    const fotoId   = Number(req.params.fotoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const foto = await db('evento_fotos').where({ id: fotoId, evento_id: eventoId }).first();
    if (foto) {
      await db('evento_fotos').where({ id: fotoId }).del();
      tryUnlinkUpload(foto.path);
    }
    return res.redirect(`/operacoes/${opId}/pessoas/${eventoId}/editar`);
  }
);



// =============================================================================
// VEÍCULO: EDITAR + GERENCIAR FOTOS
// =============================================================================

app.get('/operacoes/:opId/veiculos/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op  = await db('operacoes').where({ id: opId }).first();
    const det = await db('evento_veiculo').where({ evento_id: eventoId }).first();
    const fotos = await db('evento_fotos').where({ evento_id: eventoId }).orderBy('id', 'desc');

    const fiscList = await db('operacao_eventos as e')
      .join('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
      .where({ 'e.operacao_id': opId, 'e.cidade_id': perm.evento!.cidade_id, 'e.tipo': 'fiscalizacao' })
      .select('e.id', 'f.tipo_local')
      .orderBy('e.ts', 'desc');

    return res.render('veiculo-edit', {
      csrfToken: (req as any).csrfToken(),
      user,
      operacao: op,
      operacaoId: opId,
      eventoId,
      values: {
        tipo_veiculo: det?.tipo_veiculo || '',
        marca_modelo: det?.marca_modelo || '',
        placa: det?.placa || '',
        fiscalizacao_id: det?.fiscalizacao_evento_id || '',
        obs: perm.evento?.obs || ''
      },
      fiscList,
      fotos
    });
  }
);

app.post('/operacoes/:opId/veiculos/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const tipo_veiculo    = String(req.body.tipo_veiculo || '').trim();
    const marca_modelo    = String(req.body.marca_modelo || '').trim();
    const placa           = String(req.body.placa || '').trim().toUpperCase();
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs             = String(req.body.obs || '').trim() || null;

    await db('evento_veiculo').where({ evento_id: eventoId }).update({
      tipo_veiculo: tipo_veiculo || null,
      marca_modelo: marca_modelo || null,
      placa: placa || null,
      fiscalizacao_evento_id: fiscalizacao_id
    });
    await db('operacao_eventos').where({ id: eventoId }).update({ obs });

    return res.redirect(`/operacoes/${opId}/veiculos/${eventoId}/editar`);
  }
);

app.post('/operacoes/:opId/veiculos/:eventoId/fotos',
  requireAuth,
  uploadFotosFields,
  csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const files = fotosFromRequest(req);
    if (files.length) {
      await db('evento_fotos').insert(files.map(f => ({
        evento_id: eventoId, path: `/uploads/fotos/${f.filename}`
      })));
    }
    return res.redirect(`/operacoes/${opId}/veiculos/${eventoId}/editar`);
  }
);

app.post('/operacoes/:opId/veiculos/:eventoId/fotos/:fotoId/delete',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);
    const fotoId   = Number(req.params.fotoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const foto = await db('evento_fotos').where({ id: fotoId, evento_id: eventoId }).first();
    if (foto) {
      await db('evento_fotos').where({ id: fotoId }).del();
      tryUnlinkUpload(foto.path);
    }
    return res.redirect(`/operacoes/${opId}/veiculos/${eventoId}/editar`);
  }
);



// =============================================================================
// APREENSÃO: EDITAR + GERENCIAR FOTOS
// =============================================================================

app.get('/operacoes/:opId/apreensoes/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op  = await db('operacoes').where({ id: opId }).first();
    const det = await db('evento_apreensao').where({ evento_id: eventoId }).first();
    const fotos = await db('evento_fotos').where({ evento_id: eventoId }).orderBy('id', 'desc');

    const fiscList = await db('operacao_eventos as e')
      .join('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
      .where({ 'e.operacao_id': opId, 'e.cidade_id': perm.evento!.cidade_id, 'e.tipo': 'fiscalizacao' })
      .select('e.id', 'f.tipo_local')
      .orderBy('e.ts', 'desc');

    return res.render('apreensao-edit', {
      csrfToken: (req as any).csrfToken(),
      user,
      operacao: op,
      operacaoId: opId,
      eventoId,
      values: {
        tipo: det?.tipo || '',
        quantidade: det?.quantidade ?? '',
        unidade: det?.unidade || '',
        fiscalizacao_id: det?.fiscalizacao_evento_id || '',
        obs: perm.evento?.obs || ''
      },
      fiscList,
      fotos
    });
  }
);

app.post('/operacoes/:opId/apreensoes/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const tipo  = String(req.body.tipo || '').trim();
    const quantidade = req.body.quantidade === '' ? null : Number(req.body.quantidade);
    const unidade = String(req.body.unidade || '').trim() || null;
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs   = String(req.body.obs || '').trim() || null;

    await db('evento_apreensao').where({ evento_id: eventoId }).update({
      tipo: tipo || null,
      quantidade,
      unidade,
      fiscalizacao_evento_id: fiscalizacao_id
    });
    await db('operacao_eventos').where({ id: eventoId }).update({ obs });

    return res.redirect(`/operacoes/${opId}/apreensoes/${eventoId}/editar`);
  }
);

app.post('/operacoes/:opId/apreensoes/:eventoId/fotos',
  requireAuth,
  uploadFotosFields,
  csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const files = fotosFromRequest(req);
    if (files.length) {
      await db('evento_fotos').insert(files.map(f => ({
        evento_id: eventoId, path: `/uploads/fotos/${f.filename}`
      })));
    }
    return res.redirect(`/operacoes/${opId}/apreensoes/${eventoId}/editar`);
  }
);

app.post('/operacoes/:opId/apreensoes/:eventoId/fotos/:fotoId/delete',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user     = (req.session as any).user;
    const opId     = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);
    const fotoId   = Number(req.params.fotoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const foto = await db('evento_fotos').where({ id: fotoId, evento_id: eventoId }).first();
    if (foto) {
      await db('evento_fotos').where({ id: fotoId }).del();
      tryUnlinkUpload(foto.path);
    }
    return res.redirect(`/operacoes/${opId}/apreensoes/${eventoId}/editar`);
  }
);

// NOVA TELA: inserir ações (fiscalização, pessoa, veículo, apreensão)
app.get('/operacoes/:id/acoes/nova', requireAuth, csrfProtection, async (req, res) => {
  const user = (req.session as any).user;
  const id = Number(req.params.id);

  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).send('Operação não encontrada.');

  // Pode lançar? (em andamento + cidade participante)
  const podeLancar = await canUserPostOnOperation(id, user);

  // Fiscalizações da MINHA CIDADE para relacionar nos outros formulários
  let fiscalizacoes: any[] = [];
  if (user?.cidade_id) {
    fiscalizacoes = await db('operacao_eventos as e')
      .where({ 'e.operacao_id': id, 'e.cidade_id': user.cidade_id, 'e.tipo': 'fiscalizacao' })
      .join('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
      .select('e.id', 'f.tipo_local', 'e.ts')
      .orderBy('e.ts', 'desc');
  }

  // cidades participantes (pra mostrar)
  const cidades = await db('operacao_cidades')
    .where({ operacao_id: id })
    .join('cidades', 'cidades.id', 'operacao_cidades.cidade_id')
    .select('cidades.id', 'cidades.nome')
    .orderBy('cidades.nome');

  const operacao = {
    ...op,
    inicio_fmt: op.inicio_agendado ? new Date(op.inicio_agendado).toLocaleString('pt-BR') : null,
    cidades_str: cidades.map((c: any) => c.nome).join(', ')
  };

  res.render('operacoes-acoes-nova', {
    csrfToken: (req as any).csrfToken(),
    user,
    operacao,
    cidades,
    fiscalizacoes,
    podeLancar
  });
});

// -----------------------------------------------------------------------------
// MAPA DA OPERAÇÃO (usa geolocalização das fotos dos eventos)
// -----------------------------------------------------------------------------
app.get('/operacoes/:id/mapa', requireAuth, async (req, res) => {
  const user = (req.session as any).user;
  const id = Number(req.params.id);

  const op = await db('operacoes').where({ id }).first();
  if (!op) return res.status(404).send('Operação não encontrada.');

  // permissão: admin/gestor vê tudo; demais, somente se sua cidade participa
  if (!['admin', 'gestor'].includes(user.role)) {
    const participa = await db('operacao_cidades')
      .where({ operacao_id: id, cidade_id: user.cidade_id })
      .first();
    if (!participa) return res.status(403).send('Sem permissão.');
  }

  // subquery: última foto COM geo por evento
  const gsub = db('evento_fotos')
    .whereNotNull('lat').whereNotNull('lng')
    .select('evento_id')
    .max<{ evento_id: number; max_id: number }>('id as max_id')
    .groupBy('evento_id')
    .as('g');

  const rows = await db('operacao_eventos as e')
    .where('e.operacao_id', id)
    .join(gsub, 'g.evento_id', 'e.id')
    .join('evento_fotos as ef', 'ef.id', 'g.max_id')
    .leftJoin('cidades as c', 'c.id', 'e.cidade_id')
    .leftJoin('usuarios as u', 'u.id', 'e.user_id')
    .leftJoin('evento_fiscalizacao as f', 'f.evento_id', 'e.id')
    .leftJoin('evento_pessoa as p', 'p.evento_id', 'e.id')
    .leftJoin('evento_veiculo as v', 'v.evento_id', 'e.id')
    .leftJoin('evento_apreensao as a', 'a.evento_id', 'e.id')
    .select(
      'e.id', 'e.tipo', 'e.ts', 'e.obs',
      'c.nome as cidade',
      'u.nome as usuario',
      'ef.lat', 'ef.lng', 'ef.accuracy',
      'f.tipo_local',
      'p.nome as pessoa_nome', 'p.cpf as pessoa_cpf',
      'v.tipo_veiculo', 'v.marca_modelo', 'v.placa',
      'a.tipo as apreensao_tipo', 'a.quantidade', 'a.unidade'
    )
    .orderBy('e.ts', 'desc');

  // monta popup por tipo
  const markers = rows.map(r => {
    let title = '';
    if (r.tipo === 'fiscalizacao') {
      title = `<strong>Fiscalização</strong><br>Local: ${r.tipo_local || '—'}`;
    } else if (r.tipo === 'pessoa') {
      title = `<strong>Pessoa</strong><br>Nome: ${r.pessoa_nome || '—'}<br>CPF: ${r.pessoa_cpf || '—'}`;
    } else if (r.tipo === 'veiculo') {
      title = `<strong>Veículo</strong><br>Tipo: ${r.tipo_veiculo || '—'}<br>Modelo: ${r.marca_modelo || '—'}<br>Placa: ${r.placa || '—'}`;
    } else if (r.tipo === 'apreensao') {
      title = `<strong>Apreensão</strong><br>Tipo: ${r.apreensao_tipo || '—'}<br>Qtd: ${r.quantidade ?? '—'} ${r.unidade || ''}`;
    }
    const when = new Date(r.ts).toLocaleString('pt-BR');
    const rodape = `<div class="muted">Cidade: ${r.cidade || '—'} · ${when} · ${r.usuario || ''}</div>`;
    const obs = r.obs ? `<div class="muted">${r.obs}</div>` : '';
    return {
      id: r.id,
      tipo: r.tipo,
      lat: r.lat,
      lng: r.lng,
      accuracy: r.accuracy,
      popup: `${title}${obs ? '<br>'+obs : ''}<br>${rodape}`
    };
  });

  return res.render('operacoes-mapa', {
    user: (req.session as any).user,
    operacao: { id: op.id, nome: op.nome, inicio_agendado: op.inicio_agendado, status: op.status },
    markers
  });
});





// =============================================================================
// 404
// =============================================================================
app.use((req, res) => {
  res.status(404).send('404 - Not Found');
});

// =============================================================================
// BOOT
// =============================================================================
// Handler de erro
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[error handler]', err);
  res.status(500).send('Internal Server Error');
});

const PORT = Number(process.env.PORT) || 3000;

// Sobe o servidor **depois** de garantir schema + seed
(async () => {
  try {
    await ensureSchemaAndAdmin();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT} (env: ${process.env.NODE_ENV || 'dev'})`);
    });
  } catch (e) {
    console.error('Erro ao preparar schema:', e);
    process.exit(1);
  }
})();

export default app;
