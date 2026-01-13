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
export async function registerUser({ username, publicKey, removeDate, vault }) {
  // Validate inputs
  if (!username || username.length < 3 || username.length > 64) {
    throw new Error('Username must be between 3 and 64 characters')
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

  // Check if username already exists
  const existingUser = await query(
    'SELECT id FROM users WHERE username = $1',
    [username]
  )
  
  if (existingUser.rows.length > 0) {
    throw new Error('Username already exists')
  }

  // Insert user
  const result = await query(
    `INSERT INTO users (username, public_key, remove_date, vault)
     VALUES ($1, $2, $3, $4)
     RETURNING id, username, public_key, remove_date, hidden_mode, introvert_mode, vault`,
    [username, normalizedPublicKey, removeDate, vault]
  )

  return result.rows[0]
}

/**
 * Find a user by username+publicKey exact match.
 */
export async function findUserByUsernameAndPublicKey({ username, publicKey }) {
  if (!username || typeof username !== 'string') return null
  if (!publicKey || typeof publicKey !== 'string') return null
  const normalizedPublicKey = normalizeRsaPublicJwkString(publicKey)
  if (!normalizedPublicKey) return null

  const userResult = await query(
    'SELECT id, username, public_key, remove_date, hidden_mode, introvert_mode, vault FROM users WHERE username = $1 AND public_key = $2',
    [username, normalizedPublicKey],
  )

  return userResult.rows[0] || null
}

/**
 * Check if username exists
 */
export async function userExists(username) {
  const result = await query(
    'SELECT id FROM users WHERE username = $1',
    [username]
  )
  return result.rows.length > 0
}

/**
 * Get user by ID
 */
export async function getUserById(userId) {
  const result = await query(
    'SELECT id, username, public_key FROM users WHERE id = $1',
    [userId]
  )
  return result.rows[0] || null
}

/**
 * Get user by username
 */
export async function getUserByUsername(username) {
  const result = await query(
    'SELECT id, username, public_key, vault, remove_date FROM users WHERE username = $1',
    [username]
  )
  return result.rows[0] || null
}
