import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // importante para Neon/Render
});

export async function query(text: string, params?: any[]) {
  return pool.query(text, params);
}
