// src/server.ts
import express, { Request, Response, NextFunction } from 'express';
import type * as ExpressNS from 'express'; // <- para usar ExpressNS.Multer.File nos tipos

import session from 'express-session';
import compression from 'compression';
import morgan from 'morgan';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import dotenv from 'dotenv';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import knex, { Knex } from 'knex';
import bcrypt from 'bcryptjs';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';
import multer from 'multer';


const app = express();


// rota de teste para confirmar conexão com Neon
app.get('/debug/db-version', async (_req: Request, res: Response) => {
  try {
    if (DB_CLIENT === 'pg') {
      const r = await db.raw('select version()');
      const ver = (r as any).rows?.[0]?.version ?? JSON.stringify(r);
      res.type('text').send(ver);
    } else {
      const r = await db.raw("select sqlite_version() as version");
      const ver = (r as any)[0]?.version ?? JSON.stringify(r);
      res.type('text').send(ver);
    }
  } catch (err: any) {
    console.error(err);
    res.status(500).send('Erro na conexão com o banco: ' + err.message);
  }
});
dotenv.config();


const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IN_PROD = NODE_ENV === 'production';

// =============================================================================
// BANCO (SQLite local em disco OU Postgres via DATABASE_URL)
// =============================================================================
const DATA_DIR = process.env.DATA_DIR || path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

type DbClient = 'sqlite3' | 'pg';
const DB_CLIENT: DbClient = process.env.DATABASE_URL ? 'pg' : 'sqlite3';

const db: Knex = knex(
  DB_CLIENT === 'sqlite3'
    ? {
      client: 'sqlite3',
      connection: { filename: path.join(DATA_DIR, 'operacoescim.sqlite') },
      useNullAsDefault: true,
      pool: { min: 0, max: 1 }
    }
    : {
      client: 'pg',
      connection: {
        // no Render/Heroku, a URL já vem com usuário/senha/host/DB
        connectionString: process.env.DATABASE_URL as string,
        // SSL costuma ser obrigatório no Render/Heroku
        ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
      },
      pool: { min: 0, max: 10 }
    }
);

// Helper para adicionar coluna, se ainda não existir
async function ensureColumn(
  table: string,
  name: string,
  add: (t: Knex.CreateTableBuilder | Knex.AlterTableBuilder) => void
) {
  const has = await db.schema.hasColumn(table, name);
  if (!has) await db.schema.alterTable(table, (t) => add(t));
}

const isPg = DB_CLIENT === 'pg';

async function insertGetId(table: string, data: any, idCol: string = 'id'): Promise<number> {
  if (isPg) {
    const [row] = await db(table).insert(data).returning(idCol);
    return Number(row[idCol]);
  } else {
    const [id] = await db(table).insert(data);
    return Number(id);
  }
}


async function ensureSchemaAndAdmin() {
  // Habilita FKs no SQLite
  if (DB_CLIENT === 'sqlite3') {
    try { await db.raw('PRAGMA foreign_keys = ON'); } catch { }
  }

  // --- CIDADES
  if (!(await db.schema.hasTable('cidades'))) {
    await db.schema.createTable('cidades', (t) => {
      t.increments('id').primary();
      t.string('nome', 160).notNullable().unique();
      t.string('corporacao', 180);
      t.string('comandante', 160);
      t.string('contato', 60);
      t.string('logo_path', 255);
      t.timestamps(true, true); // created_at/updated_at com default now
    });
  } else {
    await ensureColumn('cidades', 'corporacao', (t) => (t as Knex.AlterTableBuilder).string('corporacao', 180));
    await ensureColumn('cidades', 'comandante', (t) => (t as Knex.AlterTableBuilder).string('comandante', 160));
    await ensureColumn('cidades', 'contato', (t) => (t as Knex.AlterTableBuilder).string('contato', 60));
    await ensureColumn('cidades', 'logo_path', (t) => (t as Knex.AlterTableBuilder).string('logo_path', 255));
  }

  // --- USUÁRIOS
  if (!(await db.schema.hasTable('usuarios'))) {
    await db.schema.createTable('usuarios', (t) => {
      t.increments('id').primary();
      t.string('cpf', 14).notNullable().unique();
      t.string('email', 160).unique();
      t.string('nome', 160).notNullable();
      t.string('senha_hash', 255).notNullable();
      t.string('role', 32).notNullable().defaultTo('admin'); // admin|gestor|operador|auditor
      t.boolean('ativo').notNullable().defaultTo(true);
      t.integer('cidade_id').references('id').inTable('cidades').onDelete('SET NULL');
      t.timestamp('ultimo_login_at');
      t.timestamps(true, true);
    });
  } else {
    await ensureColumn('usuarios', 'cidade_id', (t) =>
      (t as Knex.AlterTableBuilder).integer('cidade_id').references('id').inTable('cidades').onDelete('SET NULL')
    );
    await ensureColumn('usuarios', 'role', (t) =>
      (t as Knex.AlterTableBuilder).string('role', 32).notNullable().defaultTo('operador')
    );
  }

  // --- OPERAÇÕES
  if (!(await db.schema.hasTable('operacoes'))) {
    await db.schema.createTable('operacoes', (t) => {
      t.increments('id').primary();
      t.string('nome', 200).notNullable();
      t.text('descricao');
      // timestamp funciona bem nos dois bancos; useTz true adiciona TZ no Postgres
      t.timestamp('inicio_agendado', { useTz: DB_CLIENT === 'pg' }).notNullable();
      t.string('status', 32).notNullable().defaultTo('agendada'); // agendada|em_andamento|encerrada|cancelada
      t.integer('created_by').references('id').inTable('usuarios').onDelete('SET NULL');
      t.timestamps(true, true);
    });
  }

  if (!(await db.schema.hasTable('operacao_cidades'))) {
    await db.schema.createTable('operacao_cidades', (t) => {
      t.increments('id').primary();
      t.integer('operacao_id').notNullable().references('id').inTable('operacoes').onDelete('CASCADE');
      t.integer('cidade_id').notNullable().references('id').inTable('cidades').onDelete('CASCADE');
      t.unique(['operacao_id', 'cidade_id']);
    });
  }

  if (!(await db.schema.hasTable('operacao_eventos'))) {
    await db.schema.createTable('operacao_eventos', (t) => {
      t.increments('id').primary();
      t.integer('operacao_id').notNullable().references('id').inTable('operacoes').onDelete('CASCADE');
      t.integer('cidade_id').notNullable().references('id').inTable('cidades').onDelete('CASCADE');
      t.integer('user_id').notNullable().references('id').inTable('usuarios').onDelete('SET NULL');
      t.string('tipo', 32).notNullable(); // fiscalizacao|pessoa|veiculo|apreensao
      t.timestamp('ts', { useTz: DB_CLIENT === 'pg' }).notNullable().defaultTo(db.fn.now());
      t.text('obs');
    });
  }

  // --- DETALHES DE EVENTO
  if (!(await db.schema.hasTable('evento_fiscalizacao'))) {
    await db.schema.createTable('evento_fiscalizacao', (t) => {
      t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('tipo_local', 160).notNullable();
      t.string('foto_path', 255);
    });
  } else {
    await ensureColumn('evento_fiscalizacao', 'foto_path', (t) => (t as Knex.AlterTableBuilder).string('foto_path', 255));
  }

  if (!(await db.schema.hasTable('evento_pessoa'))) {
    await db.schema.createTable('evento_pessoa', (t) => {
      t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('nome', 160).notNullable();
      t.string('cpf', 14);
      t.string('foto_path', 255);
      t.integer('fiscalizacao_evento_id').references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL');
    });
  } else {
    await ensureColumn('evento_pessoa', 'foto_path', (t) => (t as Knex.AlterTableBuilder).string('foto_path', 255));
    await ensureColumn('evento_pessoa', 'fiscalizacao_evento_id', (t) =>
      (t as Knex.AlterTableBuilder).integer('fiscalizacao_evento_id')
        .references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL')
    );
  }

  if (!(await db.schema.hasTable('evento_veiculo'))) {
    await db.schema.createTable('evento_veiculo', (t) => {
      t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('tipo_veiculo', 80).notNullable();
      t.string('marca_modelo', 160);
      t.string('placa', 20);
      t.integer('fiscalizacao_evento_id').references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL');
      t.string('foto_path', 255);
    });
  } else {
    await ensureColumn('evento_veiculo', 'foto_path', (t) => (t as Knex.AlterTableBuilder).string('foto_path', 255));
    await ensureColumn('evento_veiculo', 'fiscalizacao_evento_id', (t) =>
      (t as Knex.AlterTableBuilder).integer('fiscalizacao_evento_id')
        .references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL')
    );
  }

  if (!(await db.schema.hasTable('evento_apreensao'))) {
    await db.schema.createTable('evento_apreensao', (t) => {
      t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('tipo', 120).notNullable();
      t.decimal('quantidade', 12, 2).notNullable(); // em PG vira NUMERIC(12,2)
      t.string('unidade', 40);
      t.integer('fiscalizacao_evento_id').references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL');
      t.string('foto_path', 255);
    });
  } else {
    await ensureColumn('evento_apreensao', 'foto_path', (t) => (t as Knex.AlterTableBuilder).string('foto_path', 255));
    await ensureColumn('evento_apreensao', 'fiscalizacao_evento_id', (t) =>
      (t as Knex.AlterTableBuilder).integer('fiscalizacao_evento_id')
        .references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL')
    );
  }

  // --- FOTOS (canônico) + GEO
  if (!(await db.schema.hasTable('evento_fotos'))) {
    await db.schema.createTable('evento_fotos', (t) => {
      t.increments('id').primary();
      t.integer('evento_id').notNullable().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('path', 255).notNullable();
      t.float('lat');      // latitude
      t.float('lng');      // longitude
      t.float('accuracy'); // precisão (m)
      t.timestamp('created_at', { useTz: DB_CLIENT === 'pg' }).defaultTo(db.fn.now());
      t.index(['evento_id']);
    });
  } else {
    await ensureColumn('evento_fotos', 'lat', (t) => (t as Knex.AlterTableBuilder).float('lat'));
    await ensureColumn('evento_fotos', 'lng', (t) => (t as Knex.AlterTableBuilder).float('lng'));
    await ensureColumn('evento_fotos', 'accuracy', (t) => (t as Knex.AlterTableBuilder).float('accuracy'));
  }

  // Normaliza 0,0 → NULL (idempotente)
  try {
    await db('evento_fotos')
      .whereNotNull('lat')
      .whereNotNull('lng')
      .andWhere((qb) => {
        qb.where({ lat: 0, lng: 0 })
          .orWhereRaw('ABS(lat) < 0.0001 AND ABS(lng) < 0.0001');
      })
      .update({ lat: null, lng: null, accuracy: null });
  } catch (e) {
    console.warn('Aviso: normalização de coordenadas falhou:', e);
  }

  // --- PASSWORD RESETS
  if (!(await db.schema.hasTable('password_resets'))) {
    await db.schema.createTable('password_resets', (t) => {
      t.increments('id').primary();
      t.integer('user_id').notNullable().references('id').inTable('usuarios').onDelete('CASCADE');
      t.string('token', 128).notNullable().unique();
      t.timestamp('expires_at', { useTz: DB_CLIENT === 'pg' }).notNullable();
      t.timestamps(true, true);
    });
  }

  // --- Seed admin
  const ADMIN_CPF = process.env.ADMIN_CPF || '00000000000';
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@operacoescim';
  const ADMIN_NOME = process.env.ADMIN_NOME || 'Administrador';
  const ADMIN_SENHA = process.env.ADMIN_SENHA || 'Admin@123';

  const exists = await db('usuarios').where({ cpf: ADMIN_CPF }).first();
  if (!exists) {
    const hash = await bcrypt.hash(ADMIN_SENHA, 12);
    await db('usuarios').insert({
      cpf: ADMIN_CPF,
      email: ADMIN_EMAIL,
      nome: ADMIN_NOME,
      senha_hash: hash,
      role: 'admin',
      ativo: true,
      cidade_id: null
    });
    console.log(`Usuário admin criado (cpf=${ADMIN_CPF}, email=${ADMIN_EMAIL}).`);
  }
}



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

function pickReturnTo(req: Request, fallback: string): string {
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
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return { lat: null, lng: null, acc: null };
  // descarta 0,0 e “quase 0,0”
  if (Math.abs(lat) < 0.0001 && Math.abs(lng) < 0.0001) return { lat: null, lng: null, acc: null };

  return { lat, lng, acc: Number.isFinite(acc) ? acc : null };
}

function parseMaybeNumber(v: any): number | null {
  if (v === undefined || v === null) return null;
  if (typeof v === 'string' && v.trim() === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// helper (coloque perto dos outros helpers)
function parseLocation(body: any) {
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
app.use(morgan('combined'));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

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
    if (abs.startsWith(uploadsDir)) fs.unlink(abs, () => { });
  } catch {
    // ignora
  }
}

// Aceita imagens comuns (inclui HEIC)
function imageFilter(_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback): void {
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
  { name: 'foto', maxCount: 1 },
  { name: 'fotos', maxCount: 10 },
]);

// Consolidar arquivos enviados em `foto` e/ou `fotos`
function fotosFromRequest(req: any): Express.Multer.File[] {
  if (req.files && !Array.isArray(req.files)) {
    const out: Express.Multer.File[] = [];
    if (Array.isArray(req.files.fotos)) out.push(...req.files.fotos);
    if (Array.isArray(req.files.foto)) out.push(...req.files.foto);
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
function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (req.session && (req.session as any).user) {
    next();
    return;
  }
  res.redirect('/login');
}
function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const user = (req.session as any).user;
  if (user?.role === 'admin') {
    next();
    return;
  }
  res.status(403).send('Acesso negado.');
}
function requireAdminOrGestor(req: Request, res: Response, next: NextFunction): void {
  const role = (req.session as any)?.user?.role;
  if (role === 'admin' || role === 'gestor') {
    next();
    return;
  }
  res.status(403).send('Acesso negado.');
}
async function canUserPostOnOperation(opId: number, user: any) {
  const op = await db('operacoes').where({ id: opId }).first();
  if (!op || op.status !== 'em_andamento') return false;
  // Admin/Gestor pode lançar sem estar atrelado a uma cidade participante
  if (user?.role === 'admin' || user?.role === 'gestor') return true;
  // Demais perfis: cidade obrigatória + participação na operação
  if (!user?.cidade_id) return false;
  const participante = await db('operacao_cidades')
    .where({ operacao_id: opId, cidade_id: user.cidade_id })
    .first();
  return !!participante;
}

async function createEventoBase(args: {
  operacao_id: number; cidade_id: number; user_id: number; tipo: string; obs: string | null;
}): Promise<number> {
  const eventoId = await insertGetId('operacao_eventos', {
    operacao_id: args.operacao_id,
    cidade_id: args.cidade_id,
    user_id: args.user_id,
    tipo: args.tipo,
    obs: args.obs || null
  });
  return eventoId;
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
    if (!['admin', 'gestor', 'operador', 'auditor'].includes(role)) errors.push('Perfil inválido.');
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

  const cidades = await db('cidades').select('id', 'nome').orderBy('nome');
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
  const cidades = await db('cidades').select('id', 'nome').orderBy('nome');
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
    if (!['admin', 'gestor', 'operador', 'auditor'].includes(role)) errors.push('Perfil inválido.');
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
  await db('usuarios').where({ id }).update({ ativo: !u.ativo });
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

    const opId = await insertGetId('operacoes', {
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
      'e.id', 'e.tipo', 'e.ts', 'e.obs',
      'e.user_id as e_user_id', 'e.cidade_id as e_cidade_id',
      'c.nome as cidade_nome',
      'u.nome as user_nome',
      db.raw("COALESCE(p.foto_path, f.foto_path, v.foto_path, a.foto_path) as foto_path"),
      'f.tipo_local',
      'p.nome as pessoa_nome', 'p.cpf as pessoa_cpf',
      'v.tipo_veiculo', 'v.marca_modelo', 'v.placa',
      'a.tipo as apreensao_tipo', 'a.quantidade', 'a.unidade'
    )
    .orderBy('e.ts', 'desc')
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
    podeEncerrar: ['admin', 'gestor'].includes(user?.role) && op.status !== 'encerrada'
  };

  const countOf = async (tipo: string) => {
    const row = await db('operacao_eventos').where({ operacao_id: id, tipo }).count<{ c: number }>({ c: '*' }).first();
    return Number(row?.c || 0);
  };
  const resumo = {
    fiscalizacoes: await countOf('fiscalizacao'),
    pessoas: await countOf('pessoa'),
    veiculos: await countOf('veiculo'),
    apreensoes: await countOf('apreensao')
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
app.post(
  '/operacoes/:id/fiscalizacoes',
  requireAuth,
  uploadFotosFields, // multer antes do CSRF
  csrfProtection,
  async (req: Request, res: Response) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    // operação deve estar em andamento
    if (!(await canUserPostOnOperation(operacao_id, user))) {
      return res.status(403).send('Sem permissão.');
    }

    // cidade: admin/gestor pode escolher; demais, a do usuário
    let cidade_id: number | null =
      user?.role === 'admin' || user?.role === 'gestor'
        ? (req.body.cidade_id ? Number(req.body.cidade_id) : (user.cidade_id ?? null))
        : (user.cidade_id ?? null);

    if (!Number.isFinite(cidade_id)) return res.status(400).send('Selecione a cidade.');

    const participa = await db('operacao_cidades').where({ operacao_id, cidade_id }).first();
    if (!participa) return res.status(400).send('Cidade não participa desta operação.');

    // campos obrigatórios
    const tipo_local = String(req.body.tipo_local || '').trim();
    if (!tipo_local) return res.status(400).send('Informe o tipo de local da fiscalização.');

    const obs = String(req.body.obs || '').trim() || null;

    // evento base
    const evento_id = await createEventoBase({
      operacao_id,
      cidade_id: Number(cidade_id),
      user_id: user.id,
      tipo: 'fiscalizacao',
      obs
    });

    // detalhe da fiscalização
    await db('evento_fiscalizacao').insert({ evento_id, tipo_local });

    // fotos + geo (opcional)
    const files = fotosFromRequest(req);
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat,
          lng,
          accuracy: acc
        }))
      );
    }

    return res.redirect(go);
  }
);


// Pessoa
app.post(
  '/operacoes/:id/pessoas',
  requireAuth,
  uploadFotosFields,
  csrfProtection,
  async (req: Request, res: Response) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    if (!(await canUserPostOnOperation(operacao_id, user))) {
      return res.status(403).send('Sem permissão.');
    }

    let cidade_id: number | null =
      user?.role === 'admin' || user?.role === 'gestor'
        ? (req.body.cidade_id ? Number(req.body.cidade_id) : (user.cidade_id ?? null))
        : (user.cidade_id ?? null);

    if (!Number.isFinite(cidade_id)) return res.status(400).send('Selecione a cidade.');

    const participa = await db('operacao_cidades').where({ operacao_id, cidade_id }).first();
    if (!participa) return res.status(400).send('Cidade não participa desta operação.');

    // campos
    const nome = String(req.body.nome || '').trim();
    const cpf = String(req.body.cpf || '').replace(/\D/g, '') || null;
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

    // nome é NOT NULL no schema
    if (!nome) return res.status(400).send('Informe o nome da pessoa.');

    // cria evento base
    const evento_id = await createEventoBase({
      operacao_id,
      cidade_id: Number(cidade_id),
      user_id: user.id,
      tipo: 'pessoa',
      obs
    });

    // primeira foto para compat legado
    const files = fotosFromRequest(req);
    const primeira = files[0] ? `/uploads/fotos/${files[0].filename}` : null;

    await db('evento_pessoa').insert({
      evento_id,
      nome,
      cpf,
      foto_path: primeira,
      fiscalizacao_evento_id: fiscalizacao_id || null
    });

    // fotos canônicas + geo
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat,
          lng,
          accuracy: acc
        }))
      );
    }

    return res.redirect(go);
  }
);


// Veículo
app.post(
  '/operacoes/:id/veiculos',
  requireAuth,
  uploadFotosFields,
  csrfProtection,
  async (req: Request, res: Response) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    if (!(await canUserPostOnOperation(operacao_id, user))) {
      return res.status(403).send('Sem permissão.');
    }

    let cidade_id: number | null =
      user?.role === 'admin' || user?.role === 'gestor'
        ? (req.body.cidade_id ? Number(req.body.cidade_id) : (user.cidade_id ?? null))
        : (user.cidade_id ?? null);

    if (!Number.isFinite(cidade_id)) return res.status(400).send('Selecione a cidade.');

    const participa = await db('operacao_cidades').where({ operacao_id, cidade_id }).first();
    if (!participa) return res.status(400).send('Cidade não participa desta operação.');

    // campos (tipo_veiculo é NOT NULL no schema)
    const tipo_veiculo = String(req.body.tipo_veiculo || '').trim();
    if (!tipo_veiculo) return res.status(400).send('Informe o tipo do veículo.');

    const marca_modelo = String(req.body.marca_modelo || '').trim() || null;
    const placa = String(req.body.placa || '').trim().toUpperCase() || null;
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

    // cria evento base
    const evento_id = await createEventoBase({
      operacao_id,
      cidade_id: Number(cidade_id),
      user_id: user.id,
      tipo: 'veiculo',
      obs
    });

    await db('evento_veiculo').insert({
      evento_id,
      tipo_veiculo,
      marca_modelo,
      placa,
      fiscalizacao_evento_id: fiscalizacao_id || null
    });

    // fotos + geo
    const files = fotosFromRequest(req);
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat,
          lng,
          accuracy: acc
        }))
      );
    }

    return res.redirect(go);
  }
);


// Apreensão
app.post(
  '/operacoes/:id/apreensoes',
  requireAuth,
  uploadFotosFields, // multer antes do CSRF
  csrfProtection,
  async (req: Request, res: Response) => {
    const user = (req.session as any).user;
    const operacao_id = Number(req.params.id);
    const fallback = `/operacoes/${operacao_id}`;
    const go = pickReturnTo(req, fallback);

    // Só deixa lançar se a operação estiver EM ANDAMENTO
    if (!(await canUserPostOnOperation(operacao_id, user))) {
      return res.status(403).send('Sem permissão.');
    }

    // Definir a cidade do evento:
    // - admin/gestor: pode escolher via form (name="cidade_id"); se não enviar, usa a do usuário (se tiver)
    // - outros perfis: sempre a cidade do usuário
    let cidade_id: number | null =
      user?.role === 'admin' || user?.role === 'gestor'
        ? (req.body.cidade_id ? Number(req.body.cidade_id) : (user.cidade_id ?? null))
        : (user.cidade_id ?? null);

    if (!Number.isFinite(cidade_id)) {
      return res.status(400).send('Selecione a cidade.');
    }

    // A cidade precisa participar da operação
    const participa = await db('operacao_cidades')
      .where({ operacao_id, cidade_id })
      .first();
    if (!participa) {
      return res.status(400).send('Cidade não participa desta operação.');
    }

    // Campos
    const tipo = String(req.body.tipo || '').trim();
    const quantidade = Number(req.body.quantidade);
    const unidade = String(req.body.unidade || '').trim() || null;
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

    // Validações
    const errors: string[] = [];
    if (!tipo) errors.push('Informe o tipo da apreensão.');
    if (!Number.isFinite(quantidade)) errors.push('Informe a quantidade.');
    if (errors.length) return res.status(400).send(errors.join(' '));

    // Cria o evento base (usa helper com .returning() no PG)
    const evento_id = await createEventoBase({
      operacao_id,
      cidade_id: Number(cidade_id),
      user_id: user.id,
      tipo: 'apreensao',
      obs
    });

    // Detalhes de apreensão
    await db('evento_apreensao').insert({
      evento_id,
      tipo,
      quantidade,
      unidade,
      fiscalizacao_evento_id: fiscalizacao_id || null
    });

    // Fotos (opcional) + geo
    const files = fotosFromRequest(req);
    const { lat, lng, acc } = getGeoFromBody(req);
    if (files.length) {
      await db('evento_fotos').insert(
        files.map(f => ({
          evento_id,
          path: `/uploads/fotos/${f.filename}`,
          lat,
          lng,
          accuracy: acc
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
  const tipoFilter = req.query.tipo ? String(req.query.tipo) : null; // pessoa|veiculo|apreensao|fiscalizacao

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
    .modify(q => { if (tipoFilter) q.andWhere('e.tipo', tipoFilter); })
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
        .modify(q => { if (tipoFilter) q.andWhere('e.tipo', tipoFilter); })
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
    if (r.tipo === 'pessoa') totals.pessoas = Number(r.c);
    if (r.tipo === 'veiculo') totals.veiculos = Number(r.c);
    if (r.tipo === 'apreensao') totals.apreensoes = Number(r.c);
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
    if (r.tipo === 'pessoa') row.pessoas = Number(r.c);
    if (r.tipo === 'veiculo') row.veiculos = Number(r.c);
    if (r.tipo === 'apreensao') row.apreensoes = Number(r.c);
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

    const op = await db('operacoes').where({ id: opId }).first();
    const f = await db('evento_fiscalizacao').where({ evento_id: eventoId }).first();
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
    const obs = String(req.body.obs || '').trim() || null;
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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op = await db('operacoes').where({ id: opId }).first();
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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const nome = String(req.body.nome || '').trim();
    const cpf = String(req.body.cpf || '').replace(/\D/g, '');
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
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
    return res.redirect(`/operacoes/${opId}/pessoas/${eventoId}/editar`);
  }
);



// =============================================================================
// VEÍCULO: EDITAR + GERENCIAR FOTOS
// =============================================================================

app.get('/operacoes/:opId/veiculos/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op = await db('operacoes').where({ id: opId }).first();
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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const tipo_veiculo = String(req.body.tipo_veiculo || '').trim();
    const marca_modelo = String(req.body.marca_modelo || '').trim();
    const placa = String(req.body.placa || '').trim().toUpperCase();
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
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
    return res.redirect(`/operacoes/${opId}/veiculos/${eventoId}/editar`);
  }
);



// =============================================================================
// APREENSÃO: EDITAR + GERENCIAR FOTOS
// =============================================================================

app.get('/operacoes/:opId/apreensoes/:eventoId/editar',
  requireAuth, csrfProtection,
  async (req, res) => {
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const op = await db('operacoes').where({ id: opId }).first();
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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
    const eventoId = Number(req.params.eventoId);

    const perm = await canEditEvento(user, opId, eventoId);
    if (!perm.ok) return res.status(perm.status || 403).send(perm.reason || 'Não autorizado.');

    const tipo = String(req.body.tipo || '').trim();
    const quantidade = Number(req.body.quantidade);
    if (!Number.isFinite(quantidade)) return res.status(400).send('Informe a quantidade.');
    const fiscalizacao_id = req.body.fiscalizacao_id ? Number(req.body.fiscalizacao_id) : null;
    const obs = String(req.body.obs || '').trim() || null;

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
    const user = (req.session as any).user;
    const opId = Number(req.params.opId);
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
      popup: `${title}${obs ? '<br>' + obs : ''}<br>${rodape}`
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
app.use((_req, res) => res.status(404).send('Não encontrado'));

// =============================================================================
// BOOT
// =============================================================================
ensureSchemaAndAdmin().then(() => {
  app.listen(PORT, () => {
    console.log(`operacoescim rodando na porta ${PORT} (${NODE_ENV})`);
  });
});
