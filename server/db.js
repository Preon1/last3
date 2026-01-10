import pg from 'pg'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const { Pool } = pg

let pool = null

export function initDatabase() {
  if (pool) return pool

  pool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
    database: process.env.POSTGRES_DB || 'lrcom',
    user: process.env.POSTGRES_USER || 'lrcom',
    password: process.env.POSTGRES_PASSWORD || 'changeme',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  })

  pool.on('error', (err) => {
    // No logs (privacy policy)
    void err
  })

  return pool
}

export function getPool() {
  if (!pool) {
    throw new Error('Database pool not initialized. Call initDatabase() first.')
  }
  return pool
}

export async function query(text, params) {
  const pool = getPool()
  return pool.query(text, params)
}

export async function transaction(callback) {
  const pool = getPool()
  const client = await pool.connect()
  
  try {
    await client.query('BEGIN')
    const result = await callback(client)
    await client.query('COMMIT')
    return result
  } catch (error) {
    await client.query('ROLLBACK')
    throw error
  } finally {
    client.release()
  }
}

export async function runMigrations() {
  const pool = getPool()
  const client = await pool.connect()

  try {
    await client.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())',
    )

    const appliedRes = await client.query('SELECT id FROM schema_migrations')
    const applied = new Set(appliedRes.rows.map((r) => String(r.id)))

    const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations')
    let files = []
    try {
      files = fs.readdirSync(dir)
    } catch {
      files = []
    }

    const sqlFiles = files
      .filter((f) => typeof f === 'string' && /^\d+_.*\.sql$/.test(f))
      .sort()
    for (const file of sqlFiles) {
      if (applied.has(file)) continue
      const full = path.join(dir, file)
      const sql = fs.readFileSync(full, 'utf8')
      if (!sql.trim()) {
        await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [file])
        continue
      }
      await client.query(sql)
      await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [file])
    }
  } finally {
    client.release()
  }
}
