import crypto from 'crypto'

// In-memory only: no cookies, no DB sessions.
// Server restart => re-login required.
const tokens = new Map() // token -> { userId: string, expiresAt: number }
const userToToken = new Map() // userId -> token

const TOKEN_TTL_MS = Number(process.env.SIGNED_TOKEN_TTL_MS ?? 12 * 60 * 60 * 1000) // 12h

function nowMs() {
  return Date.now()
}

export function issueToken(userId) {
  if (!userId) throw new Error('userId required')

  // 256-bit random token, base64url.
  const token = crypto.randomBytes(32).toString('base64url')
  const expiresAt = nowMs() + TOKEN_TTL_MS

  const prev = userToToken.get(userId)
  if (prev) tokens.delete(prev)

  tokens.set(token, { userId: String(userId), expiresAt })
  userToToken.set(String(userId), token)

  return { token, expiresAt }
}

export function revokeToken(token) {
  if (!token) return
  const entry = tokens.get(token)
  if (entry?.userId) userToToken.delete(entry.userId)
  tokens.delete(token)
}

export function getUserIdForToken(token) {
  if (!token) return null
  const entry = tokens.get(token)
  if (!entry) return null
  if (entry.expiresAt <= nowMs()) {
    revokeToken(token)
    return null
  }
  return entry.userId
}

export function parseAuthTokenFromReq(req) {
  const auth = String(req?.headers?.authorization ?? '')
  if (auth.toLowerCase().startsWith('bearer ')) {
    const t = auth.slice(7).trim()
    return t || null
  }

  const t = String(req?.headers?.['x-auth-token'] ?? '').trim()
  return t || null
}

export function requireSignedAuth(req, res, next) {
  const token = parseAuthTokenFromReq(req)
  const userId = getUserIdForToken(token)
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }
  req._signedUserId = userId
  next()
}
