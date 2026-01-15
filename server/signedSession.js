import crypto from 'crypto'

// In-memory only: no cookies, no DB sessions.
// Server restart => re-login required.
const tokens = new Map() // token -> { userId: string, sessionId: string, expiresAt: number, issuedAt: number }
const userToTokens = new Map() // userId -> Array<{ token: string, sessionId: string, expiresAt: number, issuedAt: number }>

const TOKEN_TTL_MS = Number(process.env.SIGNED_TOKEN_TTL_MS ?? 12 * 60 * 60 * 1000) // 12h
const MAX_SESSIONS_PER_USER = Number(process.env.SIGNED_MAX_SESSIONS_PER_USER ?? 5)

function nowMs() {
  return Date.now()
}

export function issueToken(userId) {
  if (!userId) throw new Error('userId required')

  // 256-bit random token, base64url.
  const token = crypto.randomBytes(32).toString('base64url')
  const sessionId = crypto.randomBytes(18).toString('base64url')
  const issuedAt = nowMs()
  const expiresAt = nowMs() + TOKEN_TTL_MS

  const uid = String(userId)
  tokens.set(token, { userId: uid, sessionId, expiresAt, issuedAt })

  const list = userToTokens.get(uid) ?? []
  list.push({ token, sessionId, expiresAt, issuedAt })
  // Evict oldest sessions if over limit.
  const max = Number.isFinite(MAX_SESSIONS_PER_USER) && MAX_SESSIONS_PER_USER > 0 ? MAX_SESSIONS_PER_USER : 5
  const evicted = []
  if (list.length > max) {
    list.sort((a, b) => a.issuedAt - b.issuedAt)
    while (list.length > max) {
      const victim = list.shift()
      if (victim?.token) {
        tokens.delete(victim.token)
        evicted.push({ token: victim.token, sessionId: victim.sessionId })
      }
    }
  }
  userToTokens.set(uid, list)

  return { token, expiresAt, sessionId, evicted }
}

export function revokeToken(token) {
  if (!token) return
  const entry = tokens.get(token)
  if (entry?.userId) {
    const uid = String(entry.userId)
    const list = userToTokens.get(uid)
    if (Array.isArray(list)) {
      userToTokens.set(
        uid,
        list.filter((x) => x && x.token !== token),
      )
    }
  }
  tokens.delete(token)
}

function getEntryForToken(token) {
  if (!token) return null
  const entry = tokens.get(token)
  if (!entry) return null
  if (entry.expiresAt <= nowMs()) {
    revokeToken(token)
    return null
  }
  return entry
}

export function rotateToken(oldToken) {
  const entry = getEntryForToken(oldToken)
  if (!entry) return null

  const uid = String(entry.userId)
  const sessionId = String(entry.sessionId)
  const issuedAt = Number(entry.issuedAt) || nowMs()

  // New bearer token, same sessionId.
  const token = crypto.randomBytes(32).toString('base64url')
  const expiresAt = nowMs() + TOKEN_TTL_MS

  // Replace tokens map
  tokens.delete(oldToken)
  tokens.set(token, { userId: uid, sessionId, expiresAt, issuedAt })

  // Replace in per-user list
  const list = userToTokens.get(uid) ?? []
  const next = []
  for (const s of list) {
    if (!s?.token || !s?.sessionId) continue
    if (s.sessionId === sessionId) {
      next.push({ token, sessionId, expiresAt, issuedAt: s.issuedAt })
    } else {
      next.push(s)
    }
  }
  userToTokens.set(uid, next)

  return { token, expiresAt, sessionId }
}

export function getUserIdForToken(token) {
  const entry = getEntryForToken(token)
  return entry ? entry.userId : null
}

export function getSessionForToken(token) {
  const entry = getEntryForToken(token)
  return entry ? { userId: entry.userId, sessionId: entry.sessionId } : null
}

export function revokeAllTokensForUser(userId, opts = {}) {
  const uid = String(userId ?? '')
  if (!uid) return { revoked: [] }
  const keepSessionId = typeof opts.keepSessionId === 'string' ? opts.keepSessionId : null

  const list = userToTokens.get(uid) ?? []
  const revoked = []
  const kept = []
  for (const s of list) {
    if (!s?.token || !s?.sessionId) continue
    if (keepSessionId && s.sessionId === keepSessionId) {
      kept.push(s)
      continue
    }
    revoked.push({ token: s.token, sessionId: s.sessionId })
    tokens.delete(s.token)
  }
  userToTokens.set(uid, kept)
  return { revoked }
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
  const s = getSessionForToken(token)
  if (!s?.userId || !s?.sessionId) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }
  req._signedUserId = s.userId
  req._signedSessionId = s.sessionId
  next()
}
