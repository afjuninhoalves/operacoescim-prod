import fs from 'fs';
import path from 'path';
import knex, { Knex } from 'knex';
import bcrypt from 'bcrypt';

// === Diretório de dados para SQLite (dev) ===
const DATA_DIR = process.env.DATA_DIR || path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// === Seleção do client ===
type DbClient = 'sqlite3' | 'pg';
const DB_CLIENT: DbClient = process.env.DATABASE_URL ? 'pg' : 'sqlite3';

// === Instância do Knex ===
export const db: Knex = knex(
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
          connectionString: process.env.DATABASE_URL as string,
          ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
        },
        pool: { min: 0, max: 10 }
      }
);

// === Helper: adiciona coluna se ainda não existir ===
async function ensureColumn(
  table: string,
  name: string,
  add: (t: Knex.CreateTableBuilder | Knex.AlterTableBuilder) => void
) {
  const has = await db.schema.hasColumn(table, name);
  if (!has) await db.schema.alterTable(table, (t) => add(t));
}

// === Cria/atualiza schema e garante usuário admin ===
export async function ensureSchemaAndAdmin() {
  // Habilita FKs no SQLite
  if (DB_CLIENT === 'sqlite3') {
    try { await db.raw('PRAGMA foreign_keys = ON'); } catch {}
  }

  // --- CIDADES ---
  if (!(await db.schema.hasTable('cidades'))) {
    await db.schema.createTable('cidades', (t) => {
      t.increments('id').primary();
      t.string('nome', 160).notNullable().unique();
      t.string('corporacao', 180);
      t.string('comandante', 160);
      t.string('contato', 60);
      t.string('logo_path', 255);
      t.timestamps(true, true);
    });
  } else {
    await ensureColumn('cidades', 'corporacao', (t) => (t as Knex.AlterTableBuilder).string('corporacao', 180));
    await ensureColumn('cidades', 'comandante', (t) => (t as Knex.AlterTableBuilder).string('comandante', 160));
    await ensureColumn('cidades', 'contato', (t) => (t as Knex.AlterTableBuilder).string('contato', 60));
    await ensureColumn('cidades', 'logo_path', (t) => (t as Knex.AlterTableBuilder).string('logo_path', 255));
  }

  // --- USUÁRIOS ---
  if (!(await db.schema.hasTable('usuarios'))) {
    await db.schema.createTable('usuarios', (t) => {
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
  } else {
    await ensureColumn('usuarios', 'cidade_id', (t) =>
      (t as Knex.AlterTableBuilder).integer('cidade_id').references('id').inTable('cidades').onDelete('SET NULL')
    );
    await ensureColumn('usuarios', 'role', (t) =>
      (t as Knex.AlterTableBuilder).string('role', 32).notNullable().defaultTo('operador')
    );
  }

  // --- OPERAÇÕES ---
  if (!(await db.schema.hasTable('operacoes'))) {
    await db.schema.createTable('operacoes', (t) => {
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
  if (!(await db.schema.hasTable('operacao_cidades'))) {
    await db.schema.createTable('operacao_cidades', (t) => {
      t.increments('id').primary();
      t.integer('operacao_id').notNullable().references('id').inTable('operacoes').onDelete('CASCADE');
      t.integer('cidade_id').notNullable().references('id').inTable('cidades').onDelete('CASCADE');
      t.unique(['operacao_id', 'cidade_id']);
    });
  }

  // --- EVENTOS ---
  if (!(await db.schema.hasTable('operacao_eventos'))) {
    await db.schema.createTable('operacao_eventos', (t) => {
      t.increments('id').primary();
      t.integer('operacao_id').notNullable().references('id').inTable('operacoes').onDelete('CASCADE');
      t.integer('cidade_id').notNullable().references('id').inTable('cidades').onDelete('CASCADE');
      // IMPORTANTE: sem .notNullable() para combinar com ON DELETE SET NULL
      t.integer('user_id').references('id').inTable('usuarios').onDelete('SET NULL');
      t.string('tipo', 32).notNullable(); // fiscalizacao|pessoa|veiculo|apreensao
      t.timestamp('ts', { useTz: DB_CLIENT === 'pg' }).notNullable().defaultTo(db.fn.now());
      t.text('obs');
    });
  }

  // --- DETALHES: FISCALIZAÇÃO ---
  if (!(await db.schema.hasTable('evento_fiscalizacao'))) {
    await db.schema.createTable('evento_fiscalizacao', (t) => {
      t.integer('evento_id').primary().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('tipo_local', 160).notNullable();
      t.string('foto_path', 255);
    });
  } else {
    await ensureColumn('evento_fiscalizacao', 'foto_path', (t) => (t as Knex.AlterTableBuilder).string('foto_path', 255));
  }

  // --- DETALHES: PESSOA ---
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

  // --- DETALHES: VEÍCULO ---
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

  // --- DETALHES: APREENSÃO ---
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

  // --- FOTOS CANÔNICAS + GEO ---
  if (!(await db.schema.hasTable('evento_fotos'))) {
    await db.schema.createTable('evento_fotos', (t) => {
      t.increments('id').primary();
      t.integer('evento_id').notNullable().references('id').inTable('operacao_eventos').onDelete('CASCADE');
      t.string('path', 255).notNullable();
      t.float('lat');
      t.float('lng');
      t.float('accuracy');
      t.timestamp('created_at', { useTz: DB_CLIENT === 'pg' }).defaultTo(db.fn.now());
      t.index(['evento_id']);
    });
  } else {
    await ensureColumn('evento_fotos', 'lat',      (t) => (t as Knex.AlterTableBuilder).float('lat'));
    await ensureColumn('evento_fotos', 'lng',      (t) => (t as Knex.AlterTableBuilder).float('lng'));
    await ensureColumn('evento_fotos', 'accuracy', (t) => (t as Knex.AlterTableBuilder).float('accuracy'));
  }

  // Normaliza 0,0 → NULL (idempotente)
  try {
    await db('evento_fotos')
      .whereNotNull('lat')
      .whereNotNull('lng')
      .andWhere((qb) => {
        qb.where({ lat: 0, lng: 0 }).orWhereRaw('ABS(lat) < 0.0001 AND ABS(lng) < 0.0001');
      })
      .update({ lat: null, lng: null, accuracy: null });
  } catch (e) {
    console.warn('Aviso: normalização de coordenadas falhou:', e);
  }

  // --- PASSWORD RESETS ---
  if (!(await db.schema.hasTable('password_resets'))) {
    await db.schema.createTable('password_resets', (t) => {
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

  const exists = await db('usuarios').where({ cpf: ADMIN_CPF }).first();
  if (!exists) {
    const hash = await bcrypt.hash(ADMIN_SENHA, 12);
    await db('usuarios').insert({
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
