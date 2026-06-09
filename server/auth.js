import { query } from './db.js'

function parseRsaPublicJwk(jwkString) {
  if (!jwkString || typeof jwkString !== 'string') return null
  try {
    const jwk = JSON.parse(jwkString)
    const kty = typeof jwk?.kty === 'string' ? jwk.kty : null
    const n = typeof jwk?.n === 'string' ? jwk.n : null
    const e = typeof jwk?.e === 'string' ? jwk.e : null
    if (kty !== 'RSA' || !n || !e) return null
    return { kty: 'RSA', n, e }
  } catch {
    return null
  }
}

function normalizeRsaPublicJwkString(jwkString) {
  const parsed = parseRsaPublicJwk(jwkString)
  if (!parsed) return null
  // Store a minimal, stable public JWK representation.
  return JSON.stringify({ kty: 'RSA', n: parsed.n, e: parsed.e, ext: true, key_ops: ['encrypt'] })
}

export function normalizePublicKeyJwkString(jwkString) {
  return normalizeRsaPublicJwkString(jwkString)
}

/**
 * Register a new user
 */
export async function registerUser({ nameToken, publicKey, removeDate, vault }) {
  // Validate inputs
  const token = typeof nameToken === 'string' ? nameToken.trim() : ''
  // VOPRF output is opaque; constrain size to avoid abuse.
  if (!token || token.length < 16 || token.length > 256) {
    throw new Error('nameToken invalid')
  }

  if (!publicKey) {
    throw new Error('Public key is required')
  }

  const normalizedPublicKey = normalizeRsaPublicJwkString(publicKey)
  if (!normalizedPublicKey) {
    throw new Error('Public key is required')
  }

  if (!(removeDate instanceof Date) || Number.isNaN(removeDate.getTime())) {
    throw new Error('removeDate is required')
  }

  if (typeof vault !== 'string') {
    throw new Error('vault is required')
  }

  // Guard against accidental large writes.
  if (vault.length > 100_000) {
    throw new Error('vault too large')
  }

  // Check if nameToken already exists
  const existingUser = await query(
    'SELECT id FROM users WHERE name_token = $1',
    [token]
  )
  
  if (existingUser.rows.length > 0) {
    throw new Error('Username already exists')
  }

  // Insert user
  const result = await query(
    `INSERT INTO users (name_token, public_key, remove_date, vault)
     VALUES ($1, $2, $3, $4)
     RETURNING id, name_token, public_key, remove_date, hidden_mode, introvert_mode, vault`,
    [token, normalizedPublicKey, removeDate, vault]
  )

  return result.rows[0]
}

/**
 * Find a user by username+publicKey exact match.
 */
export async function findUserByNameTokenAndPublicKey({ nameToken, publicKey }) {
  if (!nameToken || typeof nameToken !== 'string') return null
  if (!publicKey || typeof publicKey !== 'string') return null
  const normalizedPublicKey = normalizeRsaPublicJwkString(publicKey)
  if (!normalizedPublicKey) return null

  const userResult = await query(
    'SELECT id, name_token, public_key, remove_date, hidden_mode, introvert_mode, vault FROM users WHERE name_token = $1 AND public_key = $2',
    [nameToken, normalizedPublicKey],
  )

  return userResult.rows[0] || null
}

/**
 * Check if username exists
 */
export async function userTokenExists(nameToken) {
  const token = typeof nameToken === 'string' ? nameToken.trim() : ''
  if (!token) return false
  const result = await query('SELECT id FROM users WHERE name_token = $1', [token])
  return result.rows.length > 0
}

/**
 * Get user by ID
 */
export async function getUserById(userId) {
  const result = await query(
    'SELECT id, public_key FROM users WHERE id = $1',
    [userId]
  )
  return result.rows[0] || null
}

/**
 * Get user by name token
 */
export async function getUserByNameToken(nameToken) {
  const token = typeof nameToken === 'string' ? nameToken.trim() : ''
  if (!token) return null
  const result = await query('SELECT id, public_key, vault, remove_date FROM users WHERE name_token = $1', [token])
  return result.rows[0] || null
}
