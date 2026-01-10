import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { query, transaction } from './db.js'

const SALT_ROUNDS = 12

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

/**
 * Register a new user
 */
export async function registerUser({ username, password, publicKey, expirationDays }) {
  // Validate inputs
  if (!username || username.length < 3 || username.length > 64) {
    throw new Error('Username must be between 3 and 64 characters')
  }
  
  if (!password || password.length < 8) {
    throw new Error('Password must be at least 8 characters')
  }
  
  if (!publicKey) {
    throw new Error('Public key is required')
  }

  const normalizedPublicKey = normalizeRsaPublicJwkString(publicKey)
  if (!normalizedPublicKey) {
    throw new Error('Public key is required')
  }
  
  if (!expirationDays || expirationDays < 7 || expirationDays > 365) {
    throw new Error('Expiration days must be between 7 and 365')
  }

  // Check if username already exists
  const existingUser = await query(
    'SELECT id FROM users WHERE username = $1',
    [username]
  )
  
  if (existingUser.rows.length > 0) {
    throw new Error('Username already exists')
  }

  // Hash password
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS)
  
  // Calculate remove date
  const removeDate = new Date()
  removeDate.setDate(removeDate.getDate() + expirationDays)

  // Insert user
  const result = await query(
    `INSERT INTO users (username, password_hash, public_key, expiration_days, remove_date)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, username, public_key, expiration_days, remove_date, hidden_mode`,
    [username, passwordHash, normalizedPublicKey, expirationDays, removeDate]
  )

  return result.rows[0]
}

/**
 * Authenticate user and return user data with chats
 */
export async function loginUser({ username, password, publicKey }) {
  // Get user
  const userResult = await query(
    'SELECT id, username, password_hash, public_key, expiration_days, remove_date, hidden_mode FROM users WHERE username = $1',
    [username]
  )

  if (userResult.rows.length === 0) {
    throw new Error('Invalid credentials')
  }

  const user = userResult.rows[0]

  // Verify password
  const passwordValid = await bcrypt.compare(password, user.password_hash)
  if (!passwordValid) {
    throw new Error('Invalid credentials')
  }

  // Verify public key matches
  const storedParsed = parseRsaPublicJwk(String(user.public_key))
  const providedParsed = parseRsaPublicJwk(String(publicKey))
  if (storedParsed && providedParsed) {
    if (storedParsed.n !== providedParsed.n || storedParsed.e !== providedParsed.e) {
      throw new Error('Invalid credentials')
    }
  } else {
    // Fallback for legacy/non-JSON stored formats.
    if (String(user.public_key) !== String(publicKey)) {
      throw new Error('Invalid credentials')
    }
  }

  // Update remove date (reset expiration) with jitter to reduce timing inference.
  const jitterSeconds = crypto.randomInt(0, 86401)
  await query(
    `UPDATE users
     SET remove_date = NOW() + (expiration_days * INTERVAL '1 day') + ($2::int * INTERVAL '1 second')
     WHERE id = $1`,
    [user.id, jitterSeconds],
  )

  // Get user's chats
  const chatsResult = await query(
    `SELECT DISTINCT c.id, c.chat_type, c.chat_name
     FROM chats c
     INNER JOIN chat_members cm ON c.id = cm.chat_id
     WHERE cm.user_id = $1
     ORDER BY c.id DESC`,
    [user.id]
  )

  // Get unread messages
  const unreadResult = await query(
    `SELECT message_id, chat_id
     FROM unread_messages
     WHERE user_id = $1`,
    [user.id]
  )

  return {
    userId: user.id,
    username: user.username,
    hiddenMode: Boolean(user.hidden_mode),
    chats: chatsResult.rows,
    unreadMessages: unreadResult.rows,
  }
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
    'SELECT id, username, public_key FROM users WHERE username = $1',
    [username]
  )
  return result.rows[0] || null
}
