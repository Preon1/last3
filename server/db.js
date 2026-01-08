import pg from 'pg'

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
