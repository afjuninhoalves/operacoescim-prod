"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = void 0;
exports.ensureSchemaAndAdmin = ensureSchemaAndAdmin;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const knex_1 = __importDefault(require("knex"));
const bcrypt_1 = __importDefault(require("bcrypt"));
// === Diretório de dados para SQLite (dev) ===
const DATA_DIR = process.env.DATA_DIR || path_1.default.resolve(process.cwd(), 'data');
if (!fs_1.default.existsSync(DATA_DIR))
    fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
const DB_CLIENT = process.env.DATABASE_URL ? 'pg' : 'sqlite3';
// === Instância do Knex ===
exports.db = (0, knex_1.default)(DB_CLIENT === 'sqlite3'
    ? {
        client: 'sqlite3',
        connection: { filename: path_1.default.join(DATA_DIR, 'operacoescim.sqlite') },
        useNullAsDefault: true,
        pool: { min: 0, max: 1 }
    }
    : {
        client: 'pg',
        connection: {
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
        },
        pool: { min: 0, max: 10 }
    });
// === Helper: adiciona coluna se ainda não existir ===
async function ensureColumn(table, name, add) {
    const has = await exports.db.schema.hasColumn(table, name);
    if (!has)
        await exports.db.schema.alterTable(table, (t) => add(t));
}
// === Cria/atualiza schema e garante usuário admin ===
async function ensureSchemaAndAdmin() {
    // Habilita FKs no SQLite
    if (DB_CLIENT === 'sqlite3') {
        try {
            await exports.db.raw('PRAGMA foreign_keys = ON');
        }
        catch { }
    }
    // --- CIDADES ---
    if (!(await exports.db.schema.hasTable('cidades'))) {
        await exports.db.schema.createTable('cidades', (t) => {
            t.increments('id').primary();
            t.string('nome', 160).notNullable().unique();
            t.string('corporacao', 180);
            t.string('comandante', 160);
            t.string('contato', 60);
            t.string('logo_path', 255);
            t.timestamps(true, true);
        });
    }
    else {
        await ensureColumn('cidades', 'corporacao', (t) => t.string('corporacao', 180));
        await ensureColumn('cidades', 'comandante', (t) => t.string('comandante', 160));
        await ensureColumn('cidades', 'contato', (t) => t.string('contato', 60));
        await ensureColumn('cidades', 'logo_path', (t) => t.string('logo_path', 255));
    }
    // --- USUÁRIOS ---
    if (!(await exports.db.schema.hasTable('usuarios'))) {
        await exports.db.schema.createTable('usuarios', (t) => {
            t.increments('id').primary();
            t.string('cpf', 14).notNullable().unique();
            t.string('email', 160).unique();
            t.string('nome', 160).notNullable();
            t.string('senha_hash', 255).notNullable();
            t.string('role', 32).notNullable().defaultTo('operador'); // admin|gestor|operador|auditor
            t.boolean('ativo').notNullable().defaultTo(true);
            t.integer('cidade_id').references('id').inTable('cidades').onDelete('SET NULL');
            t.timestamp('ultimo_login_at', { useTz: DB_CLIENT === 'pg' });
            t.timestamps(true, true);
        });
    }
    else {
        await ensureColumn('usuarios', 'cidade_id', (t) => t.integer('cidade_id').references('id').inTable('cidades').onDelete('SET NULL'));
        await ensureColumn('usuarios', 'role', (t) => t.string('role', 32).notNullable().defaultTo('operador'));
    }
    // --- OPERAÇÕES ---
    if (!(await exports.db.schema.hasTable('operacoes'))) {
        await exports.db.schema.createTable('operacoes', (t) => {
            t.increments('id').primary();
            t.string('nome', 200).notNullable();
            t.text('descricao');
            t.timestamp('inicio_agendado', { useTz: DB_CLIENT === 'pg' }).notNullable();
            t.string('status', 32).notNullable().defaultTo('agendada'); // agendada|em_andamento|encerrada|cancelada
            t.integer('created_by').references('id').inTable('usuarios').onDelete('SET NULL');
            t.timestamps(true, true);
        });
    }
    // --- OPERAÇÃO x CIDADES ---
    if (!(await exports.db.schema.hasTable('operacao_cidades'))) {
        await exports.db.schema.createTable('operacao_cidades', (t) => {
            t.increments('id').primary();
            t.integer('operacao_id').notNullable().references('id').inTable('operacoes').onDelete('CASCADE');
            t.integer('cidade_id').notNullable().references('id').inTable('cidades').onDelete('CASCADE');
            t.unique(['operacao_id', 'cidade_id']);
        });
    }
    // --- EVENTOS ---
    if (!(await exports.db.schema.hasTable('operacao_eventos'))) {
        await exports.db.schema.createTable('operacao_eventos', (t) => {
            t.increments('id').primary();
            t.integer('operacao_id').notNullable().references('id').inTable('operacoes').onDelete('CASCADE');
            t.integer('cidade_id').notNullable().references('id').inTable('cidades').onDelete('CASCADE');
            // IMPORTANTE: sem .notNullable() para combinar com ON DELETE SET NULL
            t.integer('user_id').references('id').inTable('usuarios').onDelete('SET NULL');
            t.string('tipo', 32).notNullable(); // fiscalizacao|pessoa|veiculo|apreensao
            t.timestamp('ts', { useTz: DB_CLIENT === 'pg' }).notNullable().defaultTo(exports.db.fn.now());
            t.text('obs');
        });
    }
    // --- DETALHES: FISCALIZAÇÃO ---
    if (!(await exports.db.schema.hasTable('evento_fiscalizacao'))) {
        await exports.db.schema.createTable('evento_fiscalizacao', (t) => {
            t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
            t.string('tipo_local', 160).notNullable();
            t.string('foto_path', 255);
        });
    }
    else {
        await ensureColumn('evento_fiscalizacao', 'foto_path', (t) => t.string('foto_path', 255));
    }
    // --- DETALHES: PESSOA ---
    if (!(await exports.db.schema.hasTable('evento_pessoa'))) {
        await exports.db.schema.createTable('evento_pessoa', (t) => {
            t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
            t.string('nome', 160).notNullable();
            t.string('cpf', 14);
            t.string('foto_path', 255);
            t.integer('fiscalizacao_evento_id').references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL');
        });
    }
    else {
        await ensureColumn('evento_pessoa', 'foto_path', (t) => t.string('foto_path', 255));
        await ensureColumn('evento_pessoa', 'fiscalizacao_evento_id', (t) => t.integer('fiscalizacao_evento_id')
            .references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL'));
    }
    // --- DETALHES: VEÍCULO ---
    if (!(await exports.db.schema.hasTable('evento_veiculo'))) {
        await exports.db.schema.createTable('evento_veiculo', (t) => {
            t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
            t.string('tipo_veiculo', 80).notNullable();
            t.string('marca_modelo', 160);
            t.string('placa', 20);
            t.integer('fiscalizacao_evento_id').references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL');
            t.string('foto_path', 255);
        });
    }
    else {
        await ensureColumn('evento_veiculo', 'foto_path', (t) => t.string('foto_path', 255));
        await ensureColumn('evento_veiculo', 'fiscalizacao_evento_id', (t) => t.integer('fiscalizacao_evento_id')
            .references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL'));
    }
    // --- DETALHES: APREENSÃO ---
    if (!(await exports.db.schema.hasTable('evento_apreensao'))) {
        await exports.db.schema.createTable('evento_apreensao', (t) => {
            t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
            t.string('tipo', 120).notNullable();
            t.decimal('quantidade', 12, 2).notNullable(); // em PG vira NUMERIC(12,2)
            t.string('unidade', 40);
            t.integer('fiscalizacao_evento_id').references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL');
            t.string('foto_path', 255);
        });
    }
    else {
        await ensureColumn('evento_apreensao', 'foto_path', (t) => t.string('foto_path', 255));
        await ensureColumn('evento_apreensao', 'fiscalizacao_evento_id', (t) => t.integer('fiscalizacao_evento_id')
            .references('evento_id').inTable('evento_fiscalizacao').onDelete('SET NULL'));
    }
    // --- FOTOS CANÔNICAS + GEO ---
    if (!(await exports.db.schema.hasTable('evento_fotos'))) {
        await exports.db.schema.createTable('evento_fotos', (t) => {
            t.increments('id').primary();
            t.integer('evento_id').notNullable().references('id').inTable('operacao_eventos').onDelete('CASCADE');
            t.string('path', 255).notNullable();
            t.float('lat');
            t.float('lng');
            t.float('accuracy');
            t.timestamp('created_at', { useTz: DB_CLIENT === 'pg' }).defaultTo(exports.db.fn.now());
            t.index(['evento_id']);
        });
    }
    else {
        await ensureColumn('evento_fotos', 'lat', (t) => t.float('lat'));
        await ensureColumn('evento_fotos', 'lng', (t) => t.float('lng'));
        await ensureColumn('evento_fotos', 'accuracy', (t) => t.float('accuracy'));
    }
    // Normaliza 0,0 → NULL (idempotente)
    try {
        await (0, exports.db)('evento_fotos')
            .whereNotNull('lat')
            .whereNotNull('lng')
            .andWhere((qb) => {
            qb.where({ lat: 0, lng: 0 }).orWhereRaw('ABS(lat) < 0.0001 AND ABS(lng) < 0.0001');
        })
            .update({ lat: null, lng: null, accuracy: null });
    }
    catch (e) {
        console.warn('Aviso: normalização de coordenadas falhou:', e);
    }
    // --- PASSWORD RESETS ---
    if (!(await exports.db.schema.hasTable('password_resets'))) {
        await exports.db.schema.createTable('password_resets', (t) => {
            t.increments('id').primary();
            t.integer('user_id').notNullable().references('id').inTable('usuarios').onDelete('CASCADE');
            t.string('token', 128).notNullable().unique();
            t.timestamp('expires_at', { useTz: DB_CLIENT === 'pg' }).notNullable();
            t.timestamps(true, true);
        });
    }
    // --- Seed admin ---
    const ADMIN_CPF = process.env.ADMIN_CPF || '00000000000';
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@operacoescim';
    const ADMIN_NOME = process.env.ADMIN_NOME || 'Administrador';
    const ADMIN_SENHA = process.env.ADMIN_SENHA || 'Admin@123';
    const exists = await (0, exports.db)('usuarios').where({ cpf: ADMIN_CPF }).first();
    if (!exists) {
        const hash = await bcrypt_1.default.hash(ADMIN_SENHA, 12);
        await (0, exports.db)('usuarios').insert({
            cpf: ADMIN_CPF,
            email: ADMIN_EMAIL,
            nome: ADMIN_NOME,
            senha_hash: hash,
            role: 'admin',
            ativo: 1,
            cidade_id: null
        });
        console.log(`Usuário admin criado (cpf=${ADMIN_CPF}, email=${ADMIN_EMAIL}).`);
    }
}
