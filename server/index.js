import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import path from 'path';
import express from 'express';
import webpush from 'web-push';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import { debugError } from './logger.js';
import { APP_VERSION as SERVER_APP_VERSION } from './appVersion.js';
import {
  upsertPushSubscriptionForUser,
  deletePushStateForUser,
  cleanupExpiredPushState,
  enqueuePushForUnreadMessage,
  listPushSubscriptionsForUser,
  pickPushQueueBatch,
  markPushAttempt,
  sendWebPushToSubscriptions,
  deleteSubscriptionsByEndpoint,
} from './pushDb.js';
import { initDatabase, query, runMigrations } from './db.js';
import { registerUser, findUserByUsernameAndPublicKey, getUserByUsername } from './auth.js';
import { issueToken, rotateToken, getSessionForToken, requireSignedAuth, parseAuthTokenFromReq, revokeAllTokensForUser, revokeToken } from './signedSession.js';
import {
  signedListChats,
  signedListChatsWithLastMessage,
  signedUnreadCounts,
  signedCreatePersonalChat,
  signedCreateGroupChat,
  signedListChatMembers,
  signedAddGroupMember,
  signedRenameGroupChat,
  signedGetLastMessagesForChatIds,
  signedFetchMessages,
  signedSendMessage,
  signedMarkChatRead,
  signedMarkMessagesRead,
  signedUnreadMessageIds,
  signedDeleteMessage,
  signedUpdateMessage,
  signedLeaveChat,
  signedDeletePersonalChat,
  signedCleanupExpiredUsers,
  signedDeleteAccount,
} from './signedDb.js';

const PORT = Number(process.env.PORT ?? 8443);
const HOST = process.env.HOST ?? '0.0.0.0';

const SERVER_DIR = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(path.join(SERVER_DIR, '..', 'client', 'dist'));

const TURN_URLS = (process.env.TURN_URLS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const TURN_SECRET = process.env.TURN_SECRET ?? '';
const TURN_USERNAME_TTL_SECONDS = Number(process.env.TURN_USERNAME_TTL_SECONDS ?? 3600);

// Optional STUN servers for ICE candidate gathering.
// If unset and TURN is configured, we avoid defaulting to third-party STUN.
// If TURN is not configured, we fall back to a public STUN server for usability.
const STUN_URLS = (process.env.STUN_URLS ?? '').split(',').map((s) => s.trim()).filter(Boolean);

const TURN_RELAY_MIN_PORT = Number(process.env.TURN_RELAY_MIN_PORT ?? 0);
const TURN_RELAY_MAX_PORT = Number(process.env.TURN_RELAY_MAX_PORT ?? 0);

const TLS_KEY_PATH = process.env.TLS_KEY_PATH ?? '';
const TLS_CERT_PATH = process.env.TLS_CERT_PATH ?? '';
const USE_HTTPS = true;

const SIGNED_CLEANUP_ENABLED = (process.env.SIGNED_CLEANUP_ENABLED ?? '1') !== '0';
// Expired-user cleanup: default every 10 minutes (configurable via env).
const SIGNED_CLEANUP_INTERVAL_MS = Number(process.env.SIGNED_CLEANUP_INTERVAL_MS ?? 10 * 60 * 1000);
const SIGNED_CLEANUP_INITIAL_DELAY_MS = Number(process.env.SIGNED_CLEANUP_INITIAL_DELAY_MS ?? 30 * 1000);

// Optional Web Push (background notifications). If keys are not provided, the app
// still supports in-tab notifications when the page is open.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY ?? '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY ?? '';
const PUSH_ENABLED = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);

const VAPID_SUBJECT = (process.env.VAPID_SUBJECT ?? '').trim() || 'mailto:admin@localhost';

// Login challenges are RAM-only. Server restart => login retry required.
// challengeId -> { userId: string, challenge: string, expiresAtMs: number }
const loginChallenges = new Map();
const LOGIN_CHALLENGE_TTL_MS = 60_000;

function cleanupLoginChallenges() {
  const now = Date.now();
  for (const [id, entry] of loginChallenges.entries()) {
    if (!entry || typeof entry.expiresAtMs !== 'number' || entry.expiresAtMs <= now) {
      loginChallenges.delete(id);
    }

  }
}

setInterval(cleanupLoginChallenges, 30_000).unref?.();

function parseRsaPublicJwkString(jwkString) {
  if (!jwkString || typeof jwkString !== 'string') return null;
  try {
    const jwk = JSON.parse(jwkString);
    const kty = typeof jwk?.kty === 'string' ? jwk.kty : null;
    const n = typeof jwk?.n === 'string' ? jwk.n : null;
    const e = typeof jwk?.e === 'string' ? jwk.e : null;
    if (kty !== 'RSA' || !n || !e) return null;
    return { kty: 'RSA', n, e, ext: true, key_ops: ['encrypt'] };
  } catch {
    return null;
  }
}

function encryptWithUserPublicKey(publicKeyJwkString, plaintext) {
  const jwk = parseRsaPublicJwkString(publicKeyJwkString);
  if (!jwk) throw new Error('Invalid public key');
  const keyObj = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ct = crypto.publicEncrypt(
    { key: keyObj, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(String(plaintext), 'utf8'),
  );
  return ct.toString('base64');
}

function safeTimingEqual(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) return false;
  try {
    return crypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

if (PUSH_ENABLED) {
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  } catch {
    // No logs (privacy policy).
  }
}

// Visual branding
const APP_NAME = (process.env.APP_NAME ?? 'Last').trim() || 'Last';

async function processPushQueueOnce() {
  if (!PUSH_ENABLED) return;

  const batch = await pickPushQueueBatch({ limit: 50 });
  if (!Array.isArray(batch) || batch.length === 0) return;

  for (const row of batch) {
    const uid = String(row.user_id ?? '');
    const messageId = String(row.message_id ?? '');
    const chatId = String(row.chat_id ?? '');
    const attempts = Number(row.attempts ?? 0) || 0;
    if (!uid || !messageId || !chatId) continue;

    // If the user is online, skip push.
    if (anySignedSocketOpen(uid)) continue;

    // Cap retries. The row remains until unread/expired/random cleanup.
    if (attempts >= 20) continue;

    const subs = await listPushSubscriptionsForUser(uid);
    if (!subs.length) continue;

    const payload = {
      title: APP_NAME,
      body: 'New message',
      tag: `lrcom-chat-${chatId}`,
      url: `/?chatId=${encodeURIComponent(chatId)}&sync=1`,
      data: { chatId },
    };

    const r = await sendWebPushToSubscriptions({ subscriptions: subs, payload, ttlSeconds: 60 * 60 });

    if (Array.isArray(r?.staleEndpoints) && r.staleEndpoints.length) {
      try {
        await deleteSubscriptionsByEndpoint(r.staleEndpoints);
      } catch {
        // ignore
      }
    }

    try {
      await markPushAttempt({ userId: uid, messageId, setSent: Number(r?.okCount ?? 0) > 0 });
    } catch {
      // ignore
    }
  }
}

function withInjectedServerVersionMeta(html) {
  try {
    const meta = `<meta name="lrcom-server-version" content="${String(SERVER_APP_VERSION)}">`;
    // Insert into <head> to keep CSP simple (no inline script).
    if (typeof html === 'string' && html.includes('<head>')) return html.replace('<head>', `<head>${meta}`);
    // Fallback: prepend if head tag missing (shouldn't happen for Vite builds).
    return `${meta}${String(html ?? '')}`;
  } catch {
    return html;
  }
}

function sendIndexHtmlWithVersion(res) {
  const indexPath = path.join(PUBLIC_DIR, 'index.html');
  if (!fs.existsSync(indexPath)) return false;
  try {
    const raw = fs.readFileSync(indexPath, 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(withInjectedServerVersionMeta(raw));
    return true;
  } catch {
    return false;
  }
}


const app = express();

// Parse JSON bodies for auth endpoints
app.use(express.json({ limit: '1mb' }));

app.disable('x-powered-by');

// Security headers (minimal, no external deps)
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'microphone=(self), camera=()');

  // Note: WebRTC needs 'connect-src' for WSS/WS to this origin.
  // Keep CSP simple; adjust if you add external assets.
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "img-src 'self' data:",
      "style-src 'self'",
      "script-src 'self'",
      "connect-src 'self' wss:",
    ].join('; '),
  );

  next();
});

// Ensure the client can read server version on page load.
app.get(['/', '/index.html'], (req, res, next) => {
  const ok = sendIndexHtmlWithVersion(res);
  if (ok) return;
  next();
});

app.use(express.static(PUBLIC_DIR, {
  etag: false,
  lastModified: false,
  setHeaders(res) {
    res.setHeader('Cache-Control', 'private, max-age=604800');
  },
}));

// If the built client isn't present, fail early with a clear message.
if (!fs.existsSync(path.join(PUBLIC_DIR, 'index.html'))) {
  throw new Error(
    `Built client not found at ${PUBLIC_DIR}. Run "npm run build" in the client/ folder (or build the Docker image).`,
  );
}

app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok');
});

app.get('/turn', (req, res) => {
  // Optional helper endpoint (not required by UI), returns time-limited TURN creds.
  // No authentication is implemented (per spec). For private use, keep it behind your network.
  res.json(makeTurnConfig());
});

app.get('/api/push/public-key', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ enabled: PUSH_ENABLED, publicKey: PUSH_ENABLED ? VAPID_PUBLIC_KEY : null });
});

// Signed session refresh: rotate bearer token without re-login.
app.post('/api/signed/session/refresh', requireSignedAuth, (req, res) => {
  try {
    const oldToken = parseAuthTokenFromReq(req);
    const rotated = rotateToken(oldToken);
    if (!rotated?.token) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ success: true, token: rotated.token, expiresAt: rotated.expiresAt });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/session/logout-other-devices', requireSignedAuth, (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const keepSessionId = String(req._signedSessionId);
    const { revoked } = revokeAllTokensForUser(userId, { keepSessionId });

    for (const s of revoked) {
      if (!s?.sessionId) continue;
      const ws = getSignedSocketForSession(userId, s.sessionId);
      if (ws && ws.readyState === 1) {
        sendReliable(ws, { type: 'signedForceLogout', reason: 'logout_other_devices', wipeLocalKeys: false });
        setTimeout(() => {
          try { ws.close(); } catch { /* ignore */ }
        }, 200);
      }
    }

    res.json({ success: true, revokedCount: Array.isArray(revoked) ? revoked.length : 0 });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/session/logout-and-remove-key-other-devices', requireSignedAuth, (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const keepSessionId = String(req._signedSessionId);
    const { revoked } = revokeAllTokensForUser(userId, { keepSessionId });

    for (const s of revoked) {
      if (!s?.sessionId) continue;
      const ws = getSignedSocketForSession(userId, s.sessionId);
      if (ws && ws.readyState === 1) {
        sendReliable(ws, { type: 'signedForceLogout', reason: 'logout_remove_key_other_devices', wipeLocalKeys: true });
        setTimeout(() => {
          try { ws.close(); } catch { /* ignore */ }
        }, 200);
      }
    }

    res.json({ success: true, revokedCount: Array.isArray(revoked) ? revoked.length : 0 });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signed push subscription registration (DB-persisted, privacy-minimal).
app.post('/api/signed/push/subscribe', requireSignedAuth, (req, res) => {
  (async () => {
    if (!PUSH_ENABLED) return res.status(503).json({ error: 'Push disabled' });
    const userId = String(req._signedUserId);
    const sub = req.body?.subscription;
    const r = await upsertPushSubscriptionForUser({ userId, subscriptionJson: sub });
    if (!r.ok) return res.status(400).json({ error: r.error || 'Invalid subscription' });
    res.json({ success: true });
  })().catch(() => {
    res.status(500).json({ error: 'Server error' });
  });
});

// Signed push disable: wipe subscriptions and queue.
app.post('/api/signed/push/disable', requireSignedAuth, (req, res) => {
  (async () => {
    const userId = String(req._signedUserId);
    await deletePushStateForUser(userId);
    res.json({ success: true });
  })().catch(() => {
    res.status(500).json({ error: 'Server error' });
  });
});

app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ appName: APP_NAME });
});

// Auth endpoints (password is local-only; server never sees it)
app.post('/api/auth/register', async (req, res) => {
  try {
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const publicKey = typeof req.body?.publicKey === 'string' ? req.body.publicKey : '';
    const removeDateIso = typeof req.body?.removeDate === 'string' ? req.body.removeDate : '';
    const vault = typeof req.body?.vault === 'string' ? req.body.vault : '';

    if (!username || !publicKey || !removeDateIso || !vault) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const removeDate = new Date(removeDateIso);

    const user = await registerUser({ username, publicKey, removeDate, vault });

    const { token, expiresAt, evicted } = issueToken(String(user.id));

    if (Array.isArray(evicted) && evicted.length) {
      for (const s of evicted) {
        if (!s?.sessionId) continue;
        const ws = getSignedSocketForSession(String(user.id), s.sessionId);
        if (ws && ws.readyState === 1) {
          sendReliable(ws, { type: 'signedForceLogout', reason: 'session_evicted', wipeLocalKeys: false });
          setTimeout(() => {
            try { ws.close(); } catch { /* ignore */ }
          }, 200);
        }
      }
    }

    res.json({
      success: true,
      token,
      expiresAt,
      userId: user.id,
      username: user.username,
      hiddenMode: Boolean(user.hidden_mode),
      introvertMode: Boolean(user.introvert_mode),
    });
  } catch (error) {
    res.status(400).json({ error: error?.message || 'Bad request' });
  }
});

// Step 1: init login with username + public key, return encrypted challenge.
app.post('/api/auth/login-init', async (req, res) => {
  try {
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const publicKey = typeof req.body?.publicKey === 'string' ? req.body.publicKey : '';
    if (!username || !publicKey) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = await findUserByUsernameAndPublicKey({ username, publicKey });
    if (!user) {
      // Special case for account recreation: if the username does not exist at all,
      // allow the client to offer re-registering with an existing local key.
      const byUsername = await getUserByUsername(username);
      if (!byUsername) {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    const challengeId = crypto.randomBytes(16).toString('base64url');
    loginChallenges.set(challengeId, { userId: String(user.id), challenge, expiresAtMs: Date.now() + LOGIN_CHALLENGE_TTL_MS });

    const encryptedChallengeB64 = encryptWithUserPublicKey(String(user.public_key), challenge);
    res.json({ success: true, challengeId, encryptedChallengeB64 });
  } catch {
    // No details.
    res.status(401).json({ error: 'Unauthorized' });
  }
});

// Step 2: finalize login by proving the private key (decrypt challenge).
app.post('/api/auth/login-final', async (req, res) => {
  try {
    const challengeId = typeof req.body?.challengeId === 'string' ? req.body.challengeId : '';
    const response = typeof req.body?.response === 'string' ? req.body.response : '';
    if (!challengeId || !response) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    cleanupLoginChallenges();
    const entry = loginChallenges.get(challengeId);
    if (!entry || typeof entry?.userId !== 'string' || typeof entry?.challenge !== 'string') {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (typeof entry.expiresAtMs !== 'number' || entry.expiresAtMs <= Date.now()) {
      loginChallenges.delete(challengeId);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const ok = safeTimingEqual(response, entry.challenge);
    // One-shot challenge.
    loginChallenges.delete(challengeId);

    if (!ok) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = String(entry.userId);
    const u = await query(
      'SELECT id, username, public_key, hidden_mode, introvert_mode, vault FROM users WHERE id = $1',
      [userId],
    );
    const user = u?.rows?.[0];
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { token, expiresAt, evicted } = issueToken(userId);

    if (Array.isArray(evicted) && evicted.length) {
      for (const s of evicted) {
        if (!s?.sessionId) continue;
        const ws = getSignedSocketForSession(userId, s.sessionId);
        if (ws && ws.readyState === 1) {
          sendReliable(ws, { type: 'signedForceLogout', reason: 'session_evicted', wipeLocalKeys: false });
          setTimeout(() => {
            try { ws.close(); } catch { /* ignore */ }
          }, 200);
        }
      }
    }

    res.json({
      success: true,
      token,
      expiresAt,
      userId: String(user.id),
      username: String(user.username),
      hiddenMode: Boolean(user.hidden_mode),
      introvertMode: Boolean(user.introvert_mode),
      vault: typeof user.vault === 'string' ? user.vault : '',
    });
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.post('/api/signed/account/update', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const sessionId = String(req._signedSessionId);

    const hiddenMode = req.body?.hiddenMode;
    const introvertMode = req.body?.introvertMode;
    const removeDateIso = req.body?.removeDate;
    const vault = req.body?.vault;

    const sets = [];
    const params = [userId];

    if (hiddenMode !== undefined) {
      if (typeof hiddenMode !== 'boolean') return res.status(400).json({ error: 'hiddenMode boolean required' });
      params.push(hiddenMode);
      sets.push(`hidden_mode = $${params.length}`);
    }

    if (introvertMode !== undefined) {
      if (typeof introvertMode !== 'boolean') return res.status(400).json({ error: 'introvertMode boolean required' });
      params.push(introvertMode);
      sets.push(`introvert_mode = $${params.length}`);
    }

    if (removeDateIso !== undefined) {
      if (typeof removeDateIso !== 'string') return res.status(400).json({ error: 'removeDate string required' });
      const d = new Date(removeDateIso);
      if (Number.isNaN(d.getTime())) return res.status(400).json({ error: 'removeDate invalid' });
      params.push(d);
      sets.push(`remove_date = $${params.length}`);
    }

    if (vault !== undefined) {
      if (typeof vault !== 'string') return res.status(400).json({ error: 'vault string required' });
      if (vault.length > 100_000) return res.status(400).json({ error: 'vault too large' });
      params.push(vault);
      sets.push(`vault = $${params.length}`);
    }

    if (!sets.length) return res.status(400).json({ error: 'No fields to update' });

    await query(
      `UPDATE users
       SET ${sets.join(', ')}
       WHERE id = $1`,
      params,
    );

    // Best-effort: sync settings to other online sessions for this user.
    const payload = {
      type: 'signedAccountUpdated',
      ...(hiddenMode !== undefined && typeof hiddenMode === 'boolean' ? { hiddenMode } : {}),
      ...(introvertMode !== undefined && typeof introvertMode === 'boolean' ? { introvertMode } : {}),
    };
    if (Object.keys(payload).length > 1) {
      sendToUserAllExceptSession(userId, sessionId, payload);
    }

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Backwards-compatible endpoints (legacy clients)
app.post('/api/signed/account/hidden-mode', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const sessionId = String(req._signedSessionId);
    const hiddenMode = req.body?.hiddenMode;
    if (typeof hiddenMode !== 'boolean') return res.status(400).json({ error: 'hiddenMode boolean required' });
    await query('UPDATE users SET hidden_mode = $2 WHERE id = $1', [userId, hiddenMode]);
    sendToUserAllExceptSession(userId, sessionId, { type: 'signedAccountUpdated', hiddenMode });
    res.json({ success: true, hiddenMode });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/account/introvert-mode', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const sessionId = String(req._signedSessionId);
    const introvertMode = req.body?.introvertMode;
    if (typeof introvertMode !== 'boolean') return res.status(400).json({ error: 'introvertMode boolean required' });
    await query('UPDATE users SET introvert_mode = $2 WHERE id = $1', [userId, introvertMode]);
    sendToUserAllExceptSession(userId, sessionId, { type: 'signedAccountUpdated', introvertMode });
    res.json({ success: true, introvertMode });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/check-username', async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    const user = await getUserByUsername(username);

    res.json({
      exists: !!user,
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signed-mode API (token auth; no cookies)
app.get('/api/signed/chats', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chats = await signedListChatsWithLastMessage(userId);
    const unread = await signedUnreadCounts(userId);
    res.json({ success: true, chats, unread });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/chats/last-messages', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatIdsRaw = req.body?.chatIds;
    const chatIds = Array.isArray(chatIdsRaw) ? chatIdsRaw.map(String).filter(Boolean) : [];
    if (!chatIds.length) return res.status(400).json({ error: 'chatIds required' });

    const lastMessages = await signedGetLastMessagesForChatIds(userId, chatIds, { enforceMembership: true });
    res.json({ success: true, lastMessages });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Signed presence (privacy-preserving): caller provides a list of userIds; response
// only indicates which of those are currently connected to signed WS.
app.post('/api/signed/presence', requireSignedAuth, async (req, res) => {
  try {
    const me = String(req._signedUserId);

    const raw = req.body?.userIds;
    const idsRaw = Array.isArray(raw) ? raw.map(String).filter(Boolean) : [];

    // Hard limit to reduce load and abuse potential.
    const MAX_PRESENCE_IDS = 25;
    const idsLimited = idsRaw.slice(0, MAX_PRESENCE_IDS);

    // Permission model: caller may only request presence for users they share
    // a personal chat with (a "private chats list").
    const allowed = new Set();
    if (idsLimited.length) {
      try {
        const r = await query(
          `SELECT DISTINCT other.user_id::text AS other_user_id
           FROM chats c
           INNER JOIN chat_members me_cm ON me_cm.chat_id = c.id AND me_cm.user_id::text = $1
           INNER JOIN chat_members other ON other.chat_id = c.id AND other.user_id::text <> $1
           WHERE c.chat_type = 'personal'`,
          [me],
        );
        for (const row of r?.rows ?? []) {
          const id = String(row.other_user_id ?? '');
          if (id) allowed.add(id);
        }
      } catch {
        // ignore
      }
    }

    const ids = idsLimited.filter((id) => id && id !== me && allowed.has(id));

    // Hidden-mode users should not appear online/busy to others.
    const hidden = new Set();
    if (ids.length) {
      try {
        const r = await query(
          'SELECT id::text AS id FROM users WHERE id = ANY($1::uuid[]) AND hidden_mode = true',
          [ids],
        );
        for (const row of r?.rows ?? []) {
          if (row?.id) hidden.add(String(row.id));
        }
      } catch {
        // ignore
      }
    }

    const online = [];
    const busy = [];
    for (const id of ids) {
      if (hidden.has(id)) continue;
      if (anySignedSocketOpen(id)) online.push(id);
      const su = signedUsers.get(id);
      if (su && su.roomId) busy.push(id);
    }
    res.json({
      success: true,
      onlineUserIds: online,
      busyUserIds: busy,
      serverVersion: String(SERVER_APP_VERSION),
    });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/chats/create-personal', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const otherUsername = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    if (!otherUsername) return res.status(400).json({ error: 'Username required' });

    const result = await signedCreatePersonalChat(userId, otherUsername);
    if (!result.ok) {
      const code = result.reason === 'not_found' ? 404 : 400;
      if (result.reason === 'introvert') {
        return res.status(403).json({
          error:
            'This is in introvert mode and he can not be added. If it your friend ask him to create a chat, or disaple introvert mode',
        });
      }
      return res.status(code).json({ error: result.reason });
    }

    // Ensure the chat appears immediately for both members (if online) without
    // requiring the other user to also create it.
    try {
      const chatId = String(result?.chat?.id ?? '');
      const otherUserId = String(result?.chat?.otherUserId ?? '');
      if (chatId && otherUserId) {
        const payload = { type: 'signedChatsChanged' };
        for (const uid of [userId, otherUserId]) {
          forEachSignedSocket(String(uid), (ws) => {
            if (ws && ws.readyState === 1) sendReliable(ws, payload);
          });
        }
      }
    } catch {
      // ignore
    }

    res.json({ success: true, chat: result.chat });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/chats/create-group', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const name = typeof req.body?.name === 'string' ? req.body.name : '';
    const result = await signedCreateGroupChat(userId, name);
    if (!result.ok) return res.status(400).json({ error: result.reason });
    res.json({ success: true, chat: result.chat });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/signed/chats/members', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.query?.chatId === 'string' ? req.query.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });

    const members = await signedListChatMembers(userId, chatId);
    res.json({ success: true, members });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    if (e && e.code === 'not_group') return res.status(400).json({ error: 'not_group' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/chats/add-member', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    if (!chatId || !username) return res.status(400).json({ error: 'chatId and username required' });

    const result = await signedAddGroupMember(userId, chatId, username);
    if (!result.ok) {
      const code = result.reason === 'not_found' ? 404 : 400;
      if (result.reason === 'introvert') {
        return res.status(403).json({
          error:
            'This is in introvert mode and he can not be added. If it your friend ask him to create a chat, or disaple introvert mode',
        });
      }
      return res.status(code).json({ error: result.reason });
    }

    // Notify the added user (and best-effort the actor) to refresh their chat list.
    try {
      const addedUserId = String(result?.member?.userId ?? '');
      const targets = [addedUserId, userId].filter(Boolean);
      const payload = { type: 'signedChatsChanged' };
      for (const uid of targets) {
        forEachSignedSocket(String(uid), (ws) => {
          if (ws && ws.readyState === 1) sendReliable(ws, payload);
        });
      }
    } catch {
      // ignore
    }

    res.json({ success: true, member: result.member });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/chats/rename-group', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const name = typeof req.body?.name === 'string' ? req.body.name : '';
    if (!chatId || !name) return res.status(400).json({ error: 'chatId and name required' });

    const result = await signedRenameGroupChat(userId, chatId, name);
    if (!result.ok) {
      const code = result.reason === 'not_found' ? 404 : 400;
      return res.status(code).json({ error: result.reason });
    }

    try {
      const payload = { type: 'signedChatsChanged' };
      for (const uid of result.memberIds || []) {
        forEachSignedSocket(String(uid), (ws) => {
          if (ws && ws.readyState === 1) sendReliable(ws, payload);
        });
      }
    } catch {
      // ignore
    }

    res.json({ success: true, chat: result.chat });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/signed/messages', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.query?.chatId === 'string' ? req.query.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });

    const limit = typeof req.query?.limit === 'string' ? Number(req.query.limit) : 50;
    const before = typeof req.query?.before === 'string' ? req.query.before : null;

    const messages = await signedFetchMessages(userId, chatId, limit, before);
    res.json({ success: true, messages });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

// List unread message UUIDs for a chat (spec requirement).
app.get('/api/signed/messages/unread', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.query?.chatId === 'string' ? req.query.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });
    const limit = typeof req.query?.limit === 'string' ? Number(req.query.limit) : 500;
    const messageIds = await signedUnreadMessageIds(userId, chatId, limit);
    res.json({ success: true, chatId, messageIds });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

const MAX_ENCRYPTED_MESSAGE_BYTES = 50 * 1024;
const ERR_ENCRYPTED_TOO_LARGE = 'Encrypted message too large';

app.post('/api/signed/messages/send', requireSignedAuth, async (req, res) => {
  try {
    const senderId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const encryptedData = typeof req.body?.encryptedData === 'string' ? req.body.encryptedData : '';
    if (!chatId || !encryptedData) return res.status(400).json({ error: 'chatId and encryptedData required' });

    if (Buffer.byteLength(encryptedData, 'utf8') > MAX_ENCRYPTED_MESSAGE_BYTES) {
      return res.status(413).json({ error: ERR_ENCRYPTED_TOO_LARGE });
    }

    const senderUsernameRes = await query('SELECT username FROM users WHERE id = $1 LIMIT 1', [senderId]);
    const senderUsername = String(senderUsernameRes?.rows?.[0]?.username ?? '');

    const { messageId, memberIds } = await signedSendMessage({ senderId, chatId, encryptedData });

    // Best-effort realtime notify to signed sockets.
    const payload = {
      type: 'signedMessage',
      chatId,
      id: messageId,
      senderId,
      senderUsername,
      encryptedData,
    };
    for (const uid of memberIds) {
      forEachSignedSocket(uid, (ws) => {
        if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
      });
    }

    // Best-effort Web Push notify for offline recipients (RAM-only subs).
    // Do not include message plaintext.
    for (const uid of memberIds) {
      if (String(uid) === String(senderId)) continue;
      if (anySignedSocketOpen(uid)) continue;

      // Enqueue push attempt for this unread message.
      try {
        await enqueuePushForUnreadMessage({ userId: uid, messageId });
      } catch {
        // ignore
      }
    }

    res.json({ success: true, messageId });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/messages/delete', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const messageId = typeof req.body?.messageId === 'string' ? req.body.messageId : '';
    if (!chatId || !messageId) return res.status(400).json({ error: 'chatId and messageId required' });

    const r = await signedDeleteMessage({ userId, chatId, messageId });
    if (!r.ok) {
      if (r.reason === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
      return res.status(404).json({ error: 'Not found' });
    }

    const payload = { type: 'signedMessageDeleted', chatId, id: messageId };
    for (const uid of r.memberIds) {
      forEachSignedSocket(uid, (ws) => {
        if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
      });
    }

    res.json({ success: true });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/messages/update', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const messageId = typeof req.body?.messageId === 'string' ? req.body.messageId : '';
    const encryptedData = typeof req.body?.encryptedData === 'string' ? req.body.encryptedData : '';
    if (!chatId || !messageId || !encryptedData) {
      return res.status(400).json({ error: 'chatId, messageId, encryptedData required' });
    }

    if (Buffer.byteLength(encryptedData, 'utf8') > MAX_ENCRYPTED_MESSAGE_BYTES) {
      return res.status(413).json({ error: ERR_ENCRYPTED_TOO_LARGE });
    }

    const r = await signedUpdateMessage({ userId, chatId, messageId, encryptedData });
    if (!r.ok) {
      if (r.reason === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
      if (r.reason === 'bad_payload') return res.status(400).json({ error: 'Bad payload' });
      return res.status(404).json({ error: 'Not found' });
    }

    const senderUsernameRes = await query('SELECT username FROM users WHERE id = $1 LIMIT 1', [userId]);
    const senderUsername = String(senderUsernameRes?.rows?.[0]?.username ?? '');

    const payload = { type: 'signedMessageUpdated', chatId, id: messageId, senderId: userId, senderUsername, encryptedData };
    for (const uid of r.memberIds) {
      forEachSignedSocket(uid, (ws) => {
        if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
      });
    }

    res.json({ success: true });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/messages/mark-read', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });
    const messageIdsRaw = req.body?.messageIds;
    if (Array.isArray(messageIdsRaw) && messageIdsRaw.length) {
      const { unreadCount } = await signedMarkMessagesRead(userId, chatId, messageIdsRaw);
      return res.json({ success: true, chatId, unreadCount });
    }

    await signedMarkChatRead(userId, chatId);
    res.json({ success: true, chatId, unreadCount: 0 });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/chats/delete', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });

    // Spec: in personal chats, deletion deletes the whole chat for both users.
    // For groups, this endpoint acts as "leave" (UI labels it accordingly).
    const del = await signedDeletePersonalChat(userId, chatId);
    if (del && del.ok) {
      const payload = { type: 'signedChatDeleted', chatId };
      for (const uid of del.memberIds) {
        forEachSignedSocket(uid, (ws) => {
          if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
        });
      }
    } else {
      const left = await signedLeaveChat(userId, chatId);
      if (left && left.ok) {
        // Remaining members should refresh chat list (membership/messages changed).
        try {
          const payload = { type: 'signedChatsChanged', chatId, reason: left.chatDeleted ? 'group_deleted' : 'member_left' };
          for (const uid of left.remainingMemberIds || []) {
            forEachSignedSocket(String(uid), (ws) => {
              if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
            });
          }
        } catch {
          // ignore
        }

        // Remove leaver's messages from remaining members' in-memory views.
        try {
          const ids = Array.isArray(left.deletedMessageIds) ? left.deletedMessageIds : [];
          if (ids.length) {
            // Avoid huge websocket frames if someone deletes a lot of messages.
            const CHUNK = 500;
            for (let i = 0; i < ids.length; i += CHUNK) {
              const part = ids.slice(i, i + CHUNK);
              const payload = { type: 'signedMessagesDeleted', chatId, ids: part };
              for (const uid of left.remainingMemberIds || []) {
                forEachSignedSocket(String(uid), (ws) => {
                  if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
                });
              }
            }
          }
        } catch {
          // ignore
        }
      }
    }
    res.json({ success: true });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/account/delete', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const token = parseAuthTokenFromReq(req);

    // Best-effort: force logout all sessions (online only).
    try {
      forEachSignedSocket(userId, (ws) => {
        if (ws && ws.readyState === 1) sendReliable(ws, { type: 'signedForceLogout', reason: 'account_deleted', wipeLocalKeys: false });
      });
    } catch {
      // ignore
    }

    // Best-effort: wipe push state before account removal (privacy requirement).
    try {
      await deletePushStateForUser(userId);
    } catch {
      // ignore
    }

    await signedDeleteAccount(userId);

    // Revoke all tokens after deletion.
    try {
      revokeAllTokensForUser(userId);
    } catch {
      // ignore
    }

    // Close all signed sockets after revocation.
    try {
      closeAllSignedSockets(userId);
    } catch {
      // ignore
    }

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// SPA fallback: serve index.html for navigation requests.
// (Keeps working for both legacy public/ and Vue dist/.)
app.get('*', (req, res, next) => {
  if (req.method !== 'GET') return next();
  if (req.headers.upgrade) return next();
  if (req.path.startsWith('/api') || req.path === '/healthz' || req.path === '/turn') return next();
  const accept = String(req.headers.accept ?? '');
  if (!accept.includes('text/html')) return next();

  const indexPath = path.join(PUBLIC_DIR, 'index.html');
  if (!fs.existsSync(indexPath)) return next();

  // Inject server version so client can detect updates on page load.
  const ok = sendIndexHtmlWithVersion(res);
  if (ok) return;
  return res.sendFile(indexPath);
});

function makeTurnCredentials() {
  if (!TURN_SECRET || TURN_URLS.length === 0) return null;

  const now = Math.floor(Date.now() / 1000);
  const expiry = now + TURN_USERNAME_TTL_SECONDS;
  const username = String(expiry);

  const hmac = crypto.createHmac('sha1', TURN_SECRET).update(username).digest('base64');
  const credential = hmac;

  return {
    urls: TURN_URLS,
    username,
    credential,
  };
}

function makeTurnConfig() {
  const turn = makeTurnCredentials();

  const defaultStun = ['stun:stun.l.google.com:19302'];
  const stunUrls = STUN_URLS.length > 0 ? STUN_URLS : (turn ? [] : defaultStun);

  const iceServers = [];
  if (stunUrls.length > 0) iceServers.push({ urls: stunUrls });
  if (turn) iceServers.push(turn);
  return { iceServers };
}

function makeId() {
  return crypto.randomBytes(12).toString('hex');
}

if (!TLS_KEY_PATH || !TLS_CERT_PATH) {
  throw new Error('HTTPS is required. Set TLS_KEY_PATH and TLS_CERT_PATH (or use docker-compose with AUTO_TLS=1).');
}

const server = https.createServer(
  {
    key: fs.readFileSync(TLS_KEY_PATH),
    cert: fs.readFileSync(TLS_CERT_PATH),
  },
  app,
);

const wss = new WebSocketServer({ server });

// Signed-mode: in-memory sockets keyed by authenticated userId + sessionId.
// Supports multi-device logins.
const signedSockets = new Map(); // userId -> Map(sessionId -> ws)

// Signed-mode: in-memory user state (presence + call state). Kept RAM-only.
const signedUsers = new Map(); // userId -> { id, name, ws, roomId, ... }

// Signed-only: keep small client message receipt cache (for idempotency).
const STALE_WS_MS = Number(process.env.STALE_WS_MS ?? 45000);
const CLIENT_MSGIDS_MAX = Number(process.env.CLIENT_MSGIDS_MAX ?? 2000);

// WS heartbeat (server ping/pong) to detect dead TCP connections without
// requiring the client to actively send WS messages.
const WS_HEARTBEAT_MS = Number(process.env.WS_HEARTBEAT_MS ?? 30000);

// Reliable WS notifications (signed mode) for small control-plane events.
// We retry until the client ACKs, but only while the WS is open.
const WS_NOTIFY_RETRY_MS = Number(process.env.WS_NOTIFY_RETRY_MS ?? 5000);

function sendBestEffort(ws, obj) {
  if (!ws || ws.readyState !== 1) return;
  try {
    ws.send(JSON.stringify(obj));
  } catch {
    // ignore
  }
}

function getUserSocketMap(userId) {
  const uid = String(userId ?? '');
  if (!uid) return null;
  let m = signedSockets.get(uid);
  if (!m) {
    m = new Map();
    signedSockets.set(uid, m);
  }
  return m;
}

function addSignedSocket(userId, sessionId, ws) {
  const uid = String(userId ?? '');
  const sid = String(sessionId ?? '');
  if (!uid || !sid || !ws) return;
  const m = getUserSocketMap(uid);
  if (!m) return;
  m.set(sid, ws);
}

function removeSignedSocket(userId, sessionId, ws) {
  const uid = String(userId ?? '');
  const sid = String(sessionId ?? '');
  if (!uid || !sid) return;
  const m = signedSockets.get(uid);
  if (!m) return;
  const cur = m.get(sid);
  // Only remove if it matches this instance.
  if (cur && ws && cur !== ws) return;
  m.delete(sid);
  if (m.size === 0) signedSockets.delete(uid);
}

function forEachSignedSocket(userId, fn) {
  const uid = String(userId ?? '');
  if (!uid) return;
  const m = signedSockets.get(uid);
  if (!m) return;
  for (const ws of m.values()) {
    try {
      fn(ws);
    } catch {
      // ignore
    }
  }
}

function anySignedSocketOpen(userId) {
  let open = false;
  forEachSignedSocket(userId, (ws) => {
    if (ws && ws.readyState === 1) open = true;
  });
  return open;
}

function closeAllSignedSockets(userId) {
  const uid = String(userId ?? '');
  if (!uid) return;
  const m = signedSockets.get(uid);
  if (!m) return;
  for (const ws of m.values()) {
    try {
      ws.close();
    } catch {
      // ignore
    }
  }
  signedSockets.delete(uid);
}

function getSignedSocketForSession(userId, sessionId) {
  const uid = String(userId ?? '');
  const sid = String(sessionId ?? '');
  if (!uid || !sid) return null;
  const m = signedSockets.get(uid);
  return m ? m.get(sid) ?? null : null;
}

function sendToUserAll(userId, obj) {
  forEachSignedSocket(userId, (ws) => {
    if (ws && ws.readyState === 1) sendBestEffort(ws, obj);
  });
}

function sendToUserAllExceptSession(userId, exceptSessionId, obj) {
  const uid = String(userId ?? '');
  const sid = String(exceptSessionId ?? '');
  if (!uid) return;
  const m = signedSockets.get(uid);
  if (!m) return;
  for (const [s, ws] of m.entries()) {
    if (sid && s === sid) continue;
    if (ws && ws.readyState === 1) sendBestEffort(ws, obj);
  }
}

function sendToUserSession(userId, sessionId, obj) {
  const ws = getSignedSocketForSession(userId, sessionId);
  if (ws && ws.readyState === 1) sendBestEffort(ws, obj);
}

function sendToUserCallSession(userId, obj) {
  const uid = String(userId ?? '');
  if (!uid) return;
  const u = signedUsers.get(uid);
  const preferredSid = typeof u?.controllingSessionId === 'string' ? u.controllingSessionId : null;
  if (preferredSid) {
    const ws = getSignedSocketForSession(uid, preferredSid);
    if (ws && ws.readyState === 1) {
      sendBestEffort(ws, obj);
      return;
    }
  }
  // Fallback: deliver to all sessions.
  sendToUserAll(uid, obj);
}

function ensureWsPendingNotifies(ws) {
  if (!ws) return null;
  if (!ws._lrcomPendingNotifies) ws._lrcomPendingNotifies = new Map();
  return ws._lrcomPendingNotifies;
}

function stopWsNotifyRetryTimerIfIdle(ws) {
  try {
    const pending = ws?._lrcomPendingNotifies;
    const hasPending = pending && pending.size > 0;
    if (hasPending) return;
    if (ws?._lrcomNotifyRetryTimer) {
      clearInterval(ws._lrcomNotifyRetryTimer);
      ws._lrcomNotifyRetryTimer = null;
    }
  } catch {
    // ignore
  }
}

function ensureWsNotifyRetryTimer(ws) {
  if (!ws) return;
  if (ws._lrcomNotifyRetryTimer) return;

  ws._lrcomNotifyRetryTimer = setInterval(() => {
    try {
      if (!ws || ws.readyState !== 1) {
        stopWsNotifyRetryTimerIfIdle(ws);
        return;
      }
      const pending = ws._lrcomPendingNotifies;
      if (!pending || pending.size === 0) {
        stopWsNotifyRetryTimerIfIdle(ws);
        return;
      }
      for (const obj of pending.values()) {
        sendBestEffort(ws, obj);
      }
    } catch {
      // ignore
    }
  }, Math.max(1000, WS_NOTIFY_RETRY_MS));
}

function sendReliable(ws, obj) {
  if (!ws || ws.readyState !== 1) return null;
  const pending = ensureWsPendingNotifies(ws);
  if (!pending) return null;

  const msgId = typeof obj?.msgId === 'string' && obj.msgId ? obj.msgId : `n:${makeId()}`;
  const payload = { ...obj, msgId };
  pending.set(msgId, payload);
  sendBestEffort(ws, payload);
  ensureWsNotifyRetryTimer(ws);
  return msgId;
}

function ackReliable(ws, msgId) {
  if (!ws) return;
  const id = typeof msgId === 'string' ? msgId : '';
  if (!id) return;
  const pending = ws._lrcomPendingNotifies;
  if (pending) pending.delete(id);
  stopWsNotifyRetryTimerIfIdle(ws);
}

function rememberClientReceipt(user, cMsgId, receipt) {
  if (!user._clientReceipts) {
    user._clientReceipts = new Map();
    user._clientReceiptQueue = [];
  }

  user._clientReceipts.set(cMsgId, receipt);
  user._clientReceiptQueue.push(cMsgId);
  if (user._clientReceiptQueue.length > CLIENT_MSGIDS_MAX) {
    const old = user._clientReceiptQueue.shift();
    if (old) user._clientReceipts.delete(old);
  }
}

function getClientReceipt(user, cMsgId) {
  return user?._clientReceipts?.get(cMsgId) ?? null;
}

function sendClientReceipt(user, ws, cMsgId, ok, code = null) {
  if (!cMsgId) return;
  const receipt = {
    type: 'receipt',
    cMsgId,
    // Stable msgId so acks clear reliably even with coalescing.
    msgId: `receipt:${cMsgId}`,
    ok: Boolean(ok),
    ...(code ? { code } : {}),
    atIso: new Date().toISOString(),
  };
  rememberClientReceipt(user, cMsgId, receipt);
  sendBestEffort(ws, receipt);
}

// ------------------------
// Signed-mode voice rooms
// ------------------------

// Keep signed call rooms separate from anonymous rooms.
const signedRooms = new Map();

function getSignedRoom(roomId) {
  return roomId ? signedRooms.get(roomId) : null;
}

function ensureSignedRoom(roomId) {
  if (!signedRooms.has(roomId)) {
    signedRooms.set(roomId, { id: roomId, members: new Set(), ownerId: null, joinQueue: [], joinActive: null });
  }
  return signedRooms.get(roomId);
}

function signedPickRoomOwner(room) {
  const ownerId = room.ownerId;
  if (ownerId && room.members.has(ownerId)) {
    if (anySignedSocketOpen(ownerId)) return ownerId;
  }
  for (const memberId of room.members) {
    if (anySignedSocketOpen(memberId)) return memberId;
  }
  return null;
}

function signedRemoveJoinRequestFromRoom(room, requesterId) {
  if (!room) return;
  if (!requesterId) return;

  if (room.joinActive === requesterId) {
    room.joinActive = null;
  }

  if (Array.isArray(room.joinQueue)) {
    room.joinQueue = room.joinQueue.filter((id) => id !== requesterId);
  }
}

function signedPumpJoinQueue(room) {
  if (!room) return;
  if (room.joinActive) return;
  if (!Array.isArray(room.joinQueue) || room.joinQueue.length === 0) return;

  while (room.joinQueue.length) {
    const nextId = room.joinQueue[0];
    const requester = signedUsers.get(nextId);
    if (!requester) {
      room.joinQueue.shift();
      continue;
    }

    const ownerId = signedPickRoomOwner(room);
    if (!ownerId) {
      // Nobody online to approve. Reject all pending requests.
      for (const rid of room.joinQueue.splice(0)) {
        const u = signedUsers.get(rid);
        const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
        if (u) {
          u.joinPendingRoomId = null;
          u.joinPendingSessionId = null;
        }
        if (joinSid) sendToUserSession(rid, joinSid, { type: 'callJoinResult', ok: false, reason: 'no_approver' });
        else sendToUserAll(rid, { type: 'callJoinResult', ok: false, reason: 'no_approver' });
      }
      return;
    }

    room.ownerId = ownerId;
    room.joinActive = nextId;
    const owner = signedUsers.get(ownerId);
    if (owner) sendToUserCallSession(ownerId, { type: 'joinRequest', from: requester.id, fromName: requester.name, roomId: room.id });
    return;
  }
}

function signedLeaveRoom(user) {
  const rid = user?.roomId;
  if (!rid) return;

  const room = signedRooms.get(rid);
  user.roomId = null;
  if (!room) return;

  room.members.delete(user.id);

  signedRemoveJoinRequestFromRoom(room, user.id);
  if (room.ownerId === user.id) room.ownerId = signedPickRoomOwner(room);

  for (const memberId of room.members) {
    sendToUserCallSession(memberId, { type: 'roomPeerLeft', roomId: rid, peerId: user.id });
  }

  if (room.members.size <= 1) {
    const lastId = Array.from(room.members)[0];
    if (lastId) {
      const last = signedUsers.get(lastId);
      if (last) {
        last.roomId = null;
        last.controllingSessionId = null;
        sendToUserAll(lastId, { type: 'callEnded', reason: 'alone' });
      }
    }

    // Reject any pending joiners.
    if (Array.isArray(room.joinQueue)) {
      for (const jid of room.joinQueue) {
        const u = signedUsers.get(jid);
        const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
        if (u) {
          u.joinPendingRoomId = null;
          u.joinPendingSessionId = null;
        }
        if (joinSid) sendToUserSession(jid, joinSid, { type: 'callJoinResult', ok: false, reason: 'ended' });
        else sendToUserAll(jid, { type: 'callJoinResult', ok: false, reason: 'ended' });
      }
    }
    if (room.joinActive) {
      const u = signedUsers.get(room.joinActive);
      const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
      if (u) {
        u.joinPendingRoomId = null;
        u.joinPendingSessionId = null;
      }
      if (joinSid) sendToUserSession(room.joinActive, joinSid, { type: 'callJoinResult', ok: false, reason: 'ended' });
      else sendToUserAll(room.joinActive, { type: 'callJoinResult', ok: false, reason: 'ended' });
    }

    signedRooms.delete(rid);
    return;
  }

  signedPumpJoinQueue(room);
}

function getTurnHostLabel() {
  // Best-effort parse from the first TURN url: turn:host:port?transport=...
  const first = TURN_URLS[0];
  if (!first) return null;
  const m = first.match(/^turns?:([^:?]+)(?::(\d+))?/i);
  if (!m) return null;
  const host = m[1];
  const port = m[2] ?? '3478';
  return `${host}:${port}`;
}

wss.on('connection', async (ws, req) => {
  // Signed-mode WS: separate world; requires token in querystring.
  try {
    const rawUrl = typeof req?.url === 'string' ? req.url : '/';
    if (rawUrl.startsWith('/signed')) {
      const u = new URL(rawUrl, 'http://localhost');
      const token = u.searchParams.get('token');
      const sess = getSessionForToken(token);
      if (!sess?.userId || !sess?.sessionId) {
        try { ws.close(); } catch { /* ignore */ }
        return;
      }

      const uid = String(sess.userId);
      const sid = String(sess.sessionId);

      // Mark alive; updated via 'pong'.
      ws.isAlive = true;
      ws.on('pong', () => {
        ws.isAlive = true;
      });

      let signedName = '';
      try {
        const r = await query('SELECT username FROM users WHERE id = $1', [String(uid)]);
        signedName = String(r?.rows?.[0]?.username ?? '') || '';
      } catch {
        signedName = '';
      }

      const prev = signedUsers.get(uid);

      // Reuse the existing per-user state on reconnect (preserves call state,
      // receipts, etc).
      const signedUser = prev ?? {
        id: uid,
        name: signedName,
        lastMsgAt: Date.now(),
        roomId: null,
        controllingSessionId: null,
        joinPendingRoomId: null,
        joinPendingSessionId: null,
        _clientReceipts: null,
        _clientReceiptQueue: null,
      };

      signedUser.name = signedName || signedUser.name;
      signedUser.lastMsgAt = Date.now();

      ws._lrcomSignedUserId = uid;
      ws._lrcomSessionId = sid;
      addSignedSocket(uid, sid, ws);
      signedUsers.set(uid, signedUser);

      sendBestEffort(ws, { type: 'signedHello', userId: uid });

      ws.on('message', async (data) => {
        signedUser.lastMsgAt = Date.now();
        let msg;
        try {
          msg = JSON.parse(String(data));
        } catch {
          return;
        }
        if (!msg || typeof msg.type !== 'string') return;

        if (msg.type === 'ack') {
          const msgId = typeof msg.msgId === 'string' ? msg.msgId : null;
          if (msgId) ackReliable(ws, msgId);
          // No receipt for ACK messages: they are idempotent and best-effort.
          return;
        }

        const cMsgId = typeof msg.cMsgId === 'string' && msg.cMsgId ? msg.cMsgId : null;
        if (cMsgId) {
          const prev = getClientReceipt(signedUser, cMsgId);
          if (prev) {
            sendBestEffort(ws, prev);
            return;
          }
        }

        if (msg.type === 'ping') {
          sendBestEffort(ws, { type: 'pong' });
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callStart') {
          const to = typeof msg.to === 'string' ? msg.to : null;
          if (!to) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, false, 'BAD_TO');
            return;
          }
          const callee = signedUsers.get(to);
          if (!callee || !anySignedSocketOpen(to)) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'offline' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          // Prevent starting a parallel call from another session.
          if (signedUser.roomId) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'busy' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          // Authorization: only allow calling users who share a signed chat.
          // Introvert mode: only allow calls if the users share a *personal* chat.
          let authRow = null;
          try {
            const auth = await query(
              `SELECT
                 COALESCE((SELECT introvert_mode FROM users WHERE id::text = $2), FALSE) AS introvert,
                 EXISTS(
                   SELECT 1
                   FROM chat_members cm1
                   INNER JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
                   WHERE cm1.user_id::text = $1 AND cm2.user_id::text = $2
                   LIMIT 1
                 ) AS has_any,
                 EXISTS(
                   SELECT 1
                   FROM chats c
                   INNER JOIN chat_members cm1 ON cm1.chat_id = c.id AND cm1.user_id::text = $1
                   INNER JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id::text = $2
                   WHERE c.chat_type = 'personal'
                   LIMIT 1
                 ) AS has_personal`,
              [signedUser.id, String(to)],
            );
            authRow = auth?.rows?.[0] ?? null;
          } catch (err) {
            const msgText = typeof err?.message === 'string' ? err.message : '';
            const mayBeMissingIntrovertColumn = msgText.includes('introvert_mode');

            if (mayBeMissingIntrovertColumn) {
              // Backward-compatible fallback: if the DB schema doesn't have introvert_mode yet,
              // skip introvert enforcement (feature not available) but still enforce shared-chat auth.
              try {
                const auth = await query(
                  `SELECT
                     EXISTS(
                       SELECT 1
                       FROM chat_members cm1
                       INNER JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
                       WHERE cm1.user_id::text = $1 AND cm2.user_id::text = $2
                       LIMIT 1
                     ) AS has_any,
                     EXISTS(
                       SELECT 1
                       FROM chats c
                       INNER JOIN chat_members cm1 ON cm1.chat_id = c.id AND cm1.user_id::text = $1
                       INNER JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id::text = $2
                       WHERE c.chat_type = 'personal'
                       LIMIT 1
                     ) AS has_personal`,
                  [signedUser.id, String(to)],
                );
                const row = auth?.rows?.[0] ?? null;
                authRow = row ? { ...row, introvert: false } : null;
              } catch (err2) {
                debugError('[signed callStart] auth query failed (fallback)', {
                  from: signedUser?.id,
                  to,
                  err: err2,
                });
                sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'server' });
                if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
                return;
              }
            } else {
              debugError('[signed callStart] auth query failed', {
                from: signedUser?.id,
                to,
                err,
              });
              sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'server' });
              if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
              return;
            }
          }

          if (!authRow) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'server' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          const hasAny = Boolean(authRow?.has_any);
          const hasPersonal = Boolean(authRow?.has_personal);
          const introvert = Boolean(authRow?.introvert);

          if (!hasAny) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'not_allowed' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          if (introvert && !hasPersonal) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'introvert' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          // Busy => allow join flow.
          if (callee.roomId) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'busy' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          const rid = makeId();
          const room = ensureSignedRoom(rid);
          room.members.add(signedUser.id);
          room.members.add(callee.id);
          room.ownerId = signedUser.id;
          signedUser.roomId = rid;
          signedUser.controllingSessionId = String(sid);
          callee.roomId = rid;
          callee.controllingSessionId = null;

          sendBestEffort(ws, { type: 'callStartResult', ok: true, roomId: rid });
          sendToUserAll(callee.id, { type: 'incomingCall', from: signedUser.id, fromName: signedUser.name, roomId: rid });
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callAccept') {
          if (signedUser.controllingSessionId && String(signedUser.controllingSessionId) !== String(sid)) {
            sendBestEffort(ws, { type: 'incomingCallCancelled', roomId: typeof msg.roomId === 'string' ? msg.roomId : null, reason: 'accepted_elsewhere' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          const from = typeof msg.from === 'string' ? msg.from : null;
          const rid = typeof msg.roomId === 'string' ? msg.roomId : signedUser.roomId;
          const caller = from ? signedUsers.get(from) : null;
          if (!caller) {
            signedUser.roomId = null;
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, false, 'NOT_FOUND');
            return;
          }

          if (!rid || caller.roomId !== rid || signedUser.roomId !== rid) {
            signedUser.roomId = null;
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, false, 'ROOM_MISMATCH');
            return;
          }

          const room = getSignedRoom(rid);
          if (!room) {
            signedUser.roomId = null;
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, false, 'ROOM_MISSING');
            return;
          }

          // This session becomes the call-controlling session for the callee.
          signedUser.controllingSessionId = String(sid);
          sendToUserAllExceptSession(signedUser.id, sid, { type: 'incomingCallCancelled', roomId: rid, reason: 'accepted_elsewhere' });

          const peer = { id: signedUser.id, name: signedUser.name };
          for (const memberId of room.members) {
            if (memberId === signedUser.id) continue;
            sendToUserCallSession(memberId, { type: 'roomPeerJoined', roomId: rid, peer });
          }

          const peers = Array.from(room.members)
            .filter((id) => id !== signedUser.id)
            .map((id) => {
              const u2 = signedUsers.get(id);
              return u2 ? { id: u2.id, name: u2.name } : null;
            })
            .filter(Boolean);

          sendBestEffort(ws, { type: 'roomPeers', roomId: rid, peers });
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callReject') {
          if (signedUser.controllingSessionId && String(signedUser.controllingSessionId) !== String(sid)) {
            sendBestEffort(ws, { type: 'incomingCallCancelled', roomId: typeof msg.roomId === 'string' ? msg.roomId : null, reason: 'rejected_elsewhere' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          const from = typeof msg.from === 'string' ? msg.from : null;
          const rid = typeof msg.roomId === 'string' ? msg.roomId : signedUser.roomId;
          const caller = from ? signedUsers.get(from) : null;
          if (caller) sendToUserCallSession(caller.id, { type: 'callRejected', reason: 'rejected' });
          if (rid) {
            // Clear incoming call UI on other sessions.
            sendToUserAllExceptSession(signedUser.id, sid, { type: 'incomingCallCancelled', roomId: rid, reason: 'rejected' });

            // If the call wasn't accepted yet, end the room without emitting callEnded.
            const room = getSignedRoom(rid);
            if (room && room.members.size === 2) {
              for (const memberId of room.members) {
                const u = signedUsers.get(memberId);
                if (u && u.roomId === rid) {
                  u.roomId = null;
                  u.controllingSessionId = null;
                }
              }

              // Reject any pending joiners.
              if (Array.isArray(room.joinQueue)) {
                for (const jid of room.joinQueue) {
                  const u = signedUsers.get(jid);
                  const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
                  if (u) {
                    u.joinPendingRoomId = null;
                    u.joinPendingSessionId = null;
                  }
                  if (joinSid) sendToUserSession(jid, joinSid, { type: 'callJoinResult', ok: false, reason: 'ended' });
                  else sendToUserAll(jid, { type: 'callJoinResult', ok: false, reason: 'ended' });
                }
              }
              if (room.joinActive) {
                const u = signedUsers.get(room.joinActive);
                const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
                if (u) {
                  u.joinPendingRoomId = null;
                  u.joinPendingSessionId = null;
                }
                if (joinSid) sendToUserSession(room.joinActive, joinSid, { type: 'callJoinResult', ok: false, reason: 'ended' });
                else sendToUserAll(room.joinActive, { type: 'callJoinResult', ok: false, reason: 'ended' });
              }

              signedRooms.delete(rid);
            }
          }

          signedUser.roomId = null;
          signedUser.controllingSessionId = null;
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callHangup') {
          if (signedUser.controllingSessionId && String(signedUser.controllingSessionId) !== String(sid)) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          const rid = signedUser.roomId;
          const room = rid ? getSignedRoom(rid) : null;
          if (rid && room && room.members.size === 2) {
            const otherId = Array.from(room.members).find((id) => id !== signedUser.id) ?? null;
            const other = otherId ? signedUsers.get(otherId) : null;
            const otherAccepted = Boolean(other?.controllingSessionId);
            if (otherId && !otherAccepted) {
              // Caller cancelled before callee accepted.
              sendToUserAll(otherId, { type: 'incomingCallCancelled', roomId: rid, reason: 'hangup' });
              for (const memberId of room.members) {
                const u = signedUsers.get(memberId);
                if (u && u.roomId === rid) {
                  u.roomId = null;
                  u.controllingSessionId = null;
                }
              }
              signedRooms.delete(rid);
              if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
              return;
            }
          }

          signedLeaveRoom(signedUser);
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinRequest') {
          const to = typeof msg.to === 'string' ? msg.to : null;
          const target = to ? signedUsers.get(to) : null;
          if (!target || !target.roomId) {
            sendBestEffort(ws, { type: 'callJoinResult', ok: false, reason: 'not_in_call' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          const room = getSignedRoom(target.roomId);
          if (!room) {
            sendBestEffort(ws, { type: 'callJoinResult', ok: false, reason: 'ended' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          signedUser.joinPendingRoomId = room.id;
          signedUser.joinPendingSessionId = String(sid);
          if (!Array.isArray(room.joinQueue)) room.joinQueue = [];
          room.joinQueue.push(signedUser.id);
          sendBestEffort(ws, { type: 'callJoinPending', roomId: room.id, toName: target.name });
          signedPumpJoinQueue(room);
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinCancel') {
          if (signedUser.joinPendingSessionId && String(signedUser.joinPendingSessionId) !== String(sid)) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          const rid = signedUser.joinPendingRoomId;
          if (rid) {
            const room = getSignedRoom(rid);
            if (room) signedRemoveJoinRequestFromRoom(room, signedUser.id);
            signedPumpJoinQueue(room);
          }
          signedUser.joinPendingRoomId = null;
          signedUser.joinPendingSessionId = null;
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinReject') {
          if (signedUser.controllingSessionId && String(signedUser.controllingSessionId) !== String(sid)) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          const from = typeof msg.from === 'string' ? msg.from : null;
          const rid = typeof msg.roomId === 'string' ? msg.roomId : null;
          const requester = from ? signedUsers.get(from) : null;
          const room = rid ? getSignedRoom(rid) : null;
          const joinSid = typeof requester?.joinPendingSessionId === 'string' ? requester.joinPendingSessionId : null;
          if (requester) {
            requester.joinPendingRoomId = null;
            requester.joinPendingSessionId = null;
          }
          if (room) signedRemoveJoinRequestFromRoom(room, from);
          if (from) {
            if (joinSid) sendToUserSession(from, joinSid, { type: 'callJoinResult', ok: false, reason: 'rejected' });
            else sendToUserAll(from, { type: 'callJoinResult', ok: false, reason: 'rejected' });
          }
          signedPumpJoinQueue(room);
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinAccept') {
          if (signedUser.controllingSessionId && String(signedUser.controllingSessionId) !== String(sid)) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          const from = typeof msg.from === 'string' ? msg.from : null;
          const rid = typeof msg.roomId === 'string' ? msg.roomId : null;
          const requester = from ? signedUsers.get(from) : null;
          const room = rid ? getSignedRoom(rid) : null;
          if (!requester || !room) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          if (room.joinActive !== requester.id) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          room.members.add(requester.id);
          requester.roomId = rid;
          requester.joinPendingRoomId = null;
          requester.controllingSessionId = typeof requester.joinPendingSessionId === 'string' ? requester.joinPendingSessionId : requester.controllingSessionId;
          requester.joinPendingSessionId = null;

          const peer = { id: requester.id, name: requester.name };
          for (const memberId of room.members) {
            if (memberId === requester.id) continue;
            sendToUserCallSession(memberId, { type: 'roomPeerJoined', roomId: rid, peer });
          }

          const peers = Array.from(room.members)
            .filter((id) => id !== requester.id)
            .map((id) => {
              const u2 = signedUsers.get(id);
              return u2 ? { id: u2.id, name: u2.name } : null;
            })
            .filter(Boolean);

          sendToUserCallSession(requester.id, { type: 'roomPeers', roomId: rid, peers });
          sendToUserCallSession(requester.id, { type: 'callJoinResult', ok: true });

          room.joinActive = null;
          signedPumpJoinQueue(room);
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'signal') {
          const to = typeof msg.to === 'string' ? msg.to : null;
          const payload = msg.payload;
          if (!to) return;
          const peer = signedUsers.get(to);
          if (!peer) return;
          if (!signedUser.roomId || signedUser.roomId !== peer.roomId) return;
          if (signedUser.controllingSessionId && String(signedUser.controllingSessionId) !== String(sid)) {
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }
          sendToUserCallSession(peer.id, { type: 'signal', from: signedUser.id, fromName: signedUser.name, payload });
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, false, 'UNKNOWN_TYPE');
      });

      ws.on('close', () => {
        removeSignedSocket(uid, sid, ws);

        const curUser = signedUsers.get(uid);

        // If the controlling call session for this user disappeared, treat as leaving the call.
        if (curUser?.controllingSessionId && String(curUser.controllingSessionId) === String(sid)) {
          if (curUser.roomId) signedLeaveRoom(curUser);
          curUser.controllingSessionId = null;
        }

        // If a pending join request session disappeared, cancel the join request.
        if (curUser?.joinPendingSessionId && String(curUser.joinPendingSessionId) === String(sid)) {
          const rid = curUser.joinPendingRoomId;
          if (rid) {
            const room = getSignedRoom(rid);
            if (room) {
              signedRemoveJoinRequestFromRoom(room, curUser.id);
              signedPumpJoinQueue(room);
            }
          }
          curUser.joinPendingRoomId = null;
          curUser.joinPendingSessionId = null;
        }

        // If this was the last live session for the user, clear RAM-only state.
        const stillHasSockets = signedSockets.has(String(uid));
        if (!stillHasSockets) {
          if (curUser?.roomId) signedLeaveRoom(curUser);
          signedUsers.delete(uid);
        }
      });

      ws.on('error', () => {
        // no-op (no logs)
      });

      return;
    }
  } catch {
    try { ws.close(); } catch { /* ignore */ }
    return;
  }

  // No anonymous/unsigned WS mode: reject anything not on /signed.
  try { ws.close(); } catch { /* ignore */ }
});

// Terminate dead signed sockets (e.g. laptop sleep / mobile drop) using server
// ping/pong heartbeat. This avoids disconnecting healthy-but-idle clients.
setInterval(() => {
  for (const m of signedSockets.values()) {
    for (const ws of m.values()) {
      try {
        if (!ws || ws.readyState !== 1) continue;
        if (ws.isAlive === false) {
          if (typeof ws.terminate === 'function') ws.terminate();
          else ws.close();
          continue;
        }
        ws.isAlive = false;
        if (typeof ws.ping === 'function') ws.ping();
      } catch {
        // ignore
      }
    }
  }
}, Math.max(5000, WS_HEARTBEAT_MS));

// Initialize database connection
async function start() {
  try {
    initDatabase();
    await runMigrations();
  } catch (error) {
    void error;
    process.exit(1);
  }

  if (PUSH_ENABLED) {
    const PUSH_QUEUE_INTERVAL_MS = Math.max(5_000, Number(process.env.PUSH_QUEUE_INTERVAL_MS ?? 15_000));
    const PUSH_CLEANUP_INTERVAL_MS = Math.max(30_000, Number(process.env.PUSH_CLEANUP_INTERVAL_MS ?? 5 * 60_000));

    let pushQueueRunning = false;
    const tickQueue = async () => {
      if (pushQueueRunning) return;
      pushQueueRunning = true;
      try {
        await processPushQueueOnce();
      } catch {
        // No logs (privacy policy)
      } finally {
        pushQueueRunning = false;
      }
    };

    const tickCleanup = async () => {
      try {
        await cleanupExpiredPushState();
      } catch {
        // No logs (privacy policy)
      }
    };

    try {
      setTimeout(() => {
        void tickCleanup();
        void tickQueue();
      }, 2000).unref?.();
    } catch {
      // ignore
    }

    try {
      setInterval(() => {
        void tickQueue();
      }, PUSH_QUEUE_INTERVAL_MS).unref?.();
      setInterval(() => {
        void tickCleanup();
      }, PUSH_CLEANUP_INTERVAL_MS).unref?.();
    } catch {
      // ignore
    }
  }

  if (SIGNED_CLEANUP_ENABLED) {
    const interval = Number.isFinite(SIGNED_CLEANUP_INTERVAL_MS)
      ? Math.max(60 * 1000, SIGNED_CLEANUP_INTERVAL_MS)
      : 24 * 60 * 60 * 1000;

    const initialDelay = Number.isFinite(SIGNED_CLEANUP_INITIAL_DELAY_MS)
      ? Math.max(0, SIGNED_CLEANUP_INITIAL_DELAY_MS)
      : 30 * 1000;

    const run = async () => {
      try {
        await signedCleanupExpiredUsers();
      } catch {
        // No logs (privacy policy)
      }
    };

    setTimeout(() => {
      void run();
      setInterval(() => {
        void run();
      }, interval);
    }, initialDelay);
  }

  server.listen(PORT, HOST, () => {
    // No logs (policy: no connection tracking, IPs, or device info)
  });
}

void start();
