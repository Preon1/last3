import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import path from 'path';
import express from 'express';
import webpush from 'web-push';
import { fileURLToPath } from 'url';
import { Oprf, VOPRFServer, generatePublicKey, randomPrivateKey, EvaluationRequest, Evaluation } from '@cloudflare/voprf-ts';
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
import { registerUser, findUserByNameTokenAndPublicKey, userTokenExists, getUserByNameToken } from './auth.js';
import { issueToken, rotateToken, getSessionForToken, requireAuthSession, parseAuthTokenFromReq, revokeAllTokensForUser, revokeToken } from './authSession.js';
import {
  authListChats,
  authListChatsWithLastMessage,
  authUnreadCounts,
  authCreatePersonalChat,
  authCreateGroupChat,
  authListChatMembers,
  authAddGroupMember,
  authRenameGroupChat,
  authGetLastMessagesForChatIds,
  authFetchMessages,
  authSendMessage,
  authMarkChatRead,
  authMarkMessagesRead,
  authUnreadMessageIds,
  authDeleteMessage,
  authUpdateMessage,
  authLeaveChat,
  authDeletePersonalChat,
  authCleanupExpiredUsers,
  authDeleteAccount,
} from './authDb.js';

const PORT = Number(process.env.PORT ?? 8443);
const HOST = process.env.HOST ?? '0.0.0.0';
const WEBTRANSPORT_ENABLED = (process.env.WEBTRANSPORT_ENABLED ?? '1') !== '0';
const WEBTRANSPORT_HOST = process.env.WEBTRANSPORT_HOST ?? HOST;
const WEBTRANSPORT_PORT = Number(process.env.WEBTRANSPORT_PORT ?? (PORT + 1));
const WEBTRANSPORT_PATH = String(process.env.WEBTRANSPORT_PATH ?? '/wt') || '/wt';
const WEBTRANSPORT_SECRET = String(process.env.WEBTRANSPORT_SECRET ?? '').trim();

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

const AUTH_CLEANUP_ENABLED = (process.env.AUTH_CLEANUP_ENABLED ?? process.env.SIGNED_CLEANUP_ENABLED ?? '1') !== '0';
// Expired-user cleanup: default every 10 minutes (configurable via env).
const AUTH_CLEANUP_INTERVAL_MS = Number(process.env.AUTH_CLEANUP_INTERVAL_MS ?? process.env.SIGNED_CLEANUP_INTERVAL_MS ?? 10 * 60 * 1000);
const AUTH_CLEANUP_INITIAL_DELAY_MS = Number(process.env.AUTH_CLEANUP_INITIAL_DELAY_MS ?? process.env.SIGNED_CLEANUP_INITIAL_DELAY_MS ?? 30 * 1000);

// Optional Web Push (background notifications). If keys are not provided, the app
// still supports in-tab notifications when the page is open.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY ?? '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY ?? '';
const PUSH_ENABLED = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);

const VAPID_SUBJECT = (process.env.VAPID_SUBJECT ?? '').trim() || 'mailto:admin@localhost';

// VOPRF: server holds secret key, client gets opaque name tokens.
// If VOPRF_PRIVATE_KEY_B64U is not provided, we generate a random key at startup.
// WARNING: changing this key invalidates all existing name tokens in DB.
const VOPRF_SUITE = Oprf.Suite.P256_SHA256;
const VOPRF_PRIVATE_KEY_B64U = (process.env.VOPRF_PRIVATE_KEY_B64U ?? '').trim();

function b64uToBytes(s) {
  const str = String(s || '');
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

function bytesToB64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

const voprfPrivateKey = VOPRF_PRIVATE_KEY_B64U
  ? b64uToBytes(VOPRF_PRIVATE_KEY_B64U)
  : await randomPrivateKey(VOPRF_SUITE);

const voprfPublicKey = generatePublicKey(VOPRF_SUITE, voprfPrivateKey);
const VOPRF_PUBLIC_KEY_B64U = bytesToB64u(voprfPublicKey);
const voprfServer = new VOPRFServer(VOPRF_SUITE, voprfPrivateKey);

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
    if (anyAuthSocketOpen(uid)) continue;

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

  // Note: WebRTC needs 'connect-src' for data channels to this origin.
  // WebTransport connects over HTTPS (same origin), no wss: needed.
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
      "connect-src 'self'",
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

// Auth session refresh: rotate bearer token without re-login.
app.post('/api/session/refresh', requireAuthSession, (req, res) => {
  try {
    const oldToken = parseAuthTokenFromReq(req);
    const rotated = rotateToken(oldToken);
    if (!rotated?.token) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ success: true, token: rotated.token, expiresAt: rotated.expiresAt });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/session/logout-other-devices', requireAuthSession, (req, res) => {
  try {
    const userId = String(req._authUserId);
    const keepSessionId = String(req._authSessionId);
    const { revoked } = revokeAllTokensForUser(userId, { keepSessionId });

    for (const s of revoked) {
      if (!s?.sessionId) continue;
      const ws = getAuthSocketForSession(userId, s.sessionId);
      if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) {
        sendReliable(ws, { type: 'authForceLogout', reason: 'logout_other_devices', wipeLocalKeys: false });
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

app.post('/api/session/logout-and-remove-key-other-devices', requireAuthSession, (req, res) => {
  try {
    const userId = String(req._authUserId);
    const keepSessionId = String(req._authSessionId);
    const { revoked } = revokeAllTokensForUser(userId, { keepSessionId });

    for (const s of revoked) {
      if (!s?.sessionId) continue;
      const ws = getAuthSocketForSession(userId, s.sessionId);
      if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) {
        sendReliable(ws, { type: 'authForceLogout', reason: 'logout_remove_key_other_devices', wipeLocalKeys: true });
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

// Auth push subscription registration (DB-persisted, privacy-minimal).
app.post('/api/push/subscribe', requireAuthSession, (req, res) => {
  (async () => {
    if (!PUSH_ENABLED) return res.status(503).json({ error: 'Push disabled' });
    const userId = String(req._authUserId);
    const sub = req.body?.subscription;
    const r = await upsertPushSubscriptionForUser({ userId, subscriptionJson: sub });
    if (!r.ok) return res.status(400).json({ error: r.error || 'Invalid subscription' });
    res.json({ success: true });
  })().catch(() => {
    res.status(500).json({ error: 'Server error' });
  });
});

// Auth push disable: wipe subscriptions and queue.
app.post('/api/push/disable', requireAuthSession, (req, res) => {
  (async () => {
    const userId = String(req._authUserId);
    await deletePushStateForUser(userId);
    res.json({ success: true });
  })().catch(() => {
    res.status(500).json({ error: 'Server error' });
  });
});

app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    appName: APP_NAME,
    voprf: { mode: 'VOPRF', suite: 'P256_SHA256', publicKeyB64u: VOPRF_PUBLIC_KEY_B64U },
  });
});

// VOPRF blind evaluation endpoint.
app.post('/api/voprf/eval', (req, res) => {
  (async () => {
    const evalReqB64u = typeof req.body?.evalReqB64u === 'string' ? req.body.evalReqB64u : '';
    if (!evalReqB64u) return res.status(400).json({ error: 'evalReqB64u required' });
    if (evalReqB64u.length > 200_000) return res.status(413).json({ error: 'Too large' });

    const reqBytes = b64uToBytes(evalReqB64u);
    const evalReq = EvaluationRequest.deserialize(VOPRF_SUITE, reqBytes);
    const evaluation = await voprfServer.blindEvaluate(evalReq);
    const evaluationB64u = bytesToB64u(evaluation.serialize());
    res.json({ success: true, evaluationB64u });
  })().catch(() => {
    res.status(400).json({ error: 'Bad request' });
  });
});

// Auth endpoints (password is local-only; server never sees it)
app.post('/api/auth/register', async (req, res) => {
  try {
    const nameToken = typeof req.body?.nameToken === 'string' ? req.body.nameToken : '';
    const publicKey = typeof req.body?.publicKey === 'string' ? req.body.publicKey : '';
    const removeDateIso = typeof req.body?.removeDate === 'string' ? req.body.removeDate : '';
    const vault = typeof req.body?.vault === 'string' ? req.body.vault : '';

    if (!nameToken || !publicKey || !removeDateIso || !vault) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const removeDate = new Date(removeDateIso);

    const user = await registerUser({ nameToken, publicKey, removeDate, vault });

    const { token, expiresAt, evicted } = issueToken(String(user.id));

    if (Array.isArray(evicted) && evicted.length) {
      for (const s of evicted) {
        if (!s?.sessionId) continue;
        const ws = getAuthSocketForSession(String(user.id), s.sessionId);
        if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) {
          sendReliable(ws, { type: 'authForceLogout', reason: 'session_evicted', wipeLocalKeys: false });
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
    const nameToken = typeof req.body?.nameToken === 'string' ? req.body.nameToken : '';
    const publicKey = typeof req.body?.publicKey === 'string' ? req.body.publicKey : '';
    if (!nameToken || !publicKey) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = await findUserByNameTokenAndPublicKey({ nameToken, publicKey });
    if (!user) {
      // Special case for account recreation: if the username does not exist at all,
      // allow the client to offer re-registering with an existing local key.
      const byToken = await getUserByNameToken(nameToken);
      if (!byToken) {
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
      'SELECT id, public_key, hidden_mode, introvert_mode, vault FROM users WHERE id = $1',
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
        const ws = getAuthSocketForSession(userId, s.sessionId);
        if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) {
          sendReliable(ws, { type: 'authForceLogout', reason: 'session_evicted', wipeLocalKeys: false });
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
      hiddenMode: Boolean(user.hidden_mode),
      introvertMode: Boolean(user.introvert_mode),
      vault: typeof user.vault === 'string' ? user.vault : '',
    });
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.post('/api/account/update', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const sessionId = String(req._authSessionId);

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
      type: 'authAccountUpdated',
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
app.post('/api/account/hidden-mode', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const sessionId = String(req._authSessionId);
    const hiddenMode = req.body?.hiddenMode;
    if (typeof hiddenMode !== 'boolean') return res.status(400).json({ error: 'hiddenMode boolean required' });
    await query('UPDATE users SET hidden_mode = $2 WHERE id = $1', [userId, hiddenMode]);
    sendToUserAllExceptSession(userId, sessionId, { type: 'authAccountUpdated', hiddenMode });
    res.json({ success: true, hiddenMode });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/account/introvert-mode', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const sessionId = String(req._authSessionId);
    const introvertMode = req.body?.introvertMode;
    if (typeof introvertMode !== 'boolean') return res.status(400).json({ error: 'introvertMode boolean required' });
    await query('UPDATE users SET introvert_mode = $2 WHERE id = $1', [userId, introvertMode]);
    sendToUserAllExceptSession(userId, sessionId, { type: 'authAccountUpdated', introvertMode });
    res.json({ success: true, introvertMode });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/check-name-token', async (req, res) => {
  try {
    const nameToken = typeof req.body?.nameToken === 'string' ? req.body.nameToken : '';
    
    if (!nameToken) {
      return res.status(400).json({ error: 'nameToken required' });
    }

    const exists = await userTokenExists(nameToken);

    res.json({
      exists,
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Auth-mode API (token auth; no cookies)
app.get('/api/chats', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chats = await authListChatsWithLastMessage(userId);
    const unread = await authUnreadCounts(userId);
    res.json({ success: true, chats, unread });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/chats/last-messages', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatIdsRaw = req.body?.chatIds;
    const chatIds = Array.isArray(chatIdsRaw) ? chatIdsRaw.map(String).filter(Boolean) : [];
    if (!chatIds.length) return res.status(400).json({ error: 'chatIds required' });

    const lastMessages = await authGetLastMessagesForChatIds(userId, chatIds, { enforceMembership: true });
    res.json({ success: true, lastMessages });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    if (e && e.code === 'bad_payload') return res.status(400).json({ error: 'Bad payload' });
    res.status(500).json({ error: 'Server error' });
  }
});

const MAX_PRESENCE_IDS = 25;

async function buildPresenceSnapshotForUser(userId, idsInput) {
  const me = String(userId ?? '');
  if (!me) {
    return {
      onlineUserIds: [],
      busyUserIds: [],
      serverVersion: String(SERVER_APP_VERSION),
    };
  }

  const idsRaw = Array.isArray(idsInput) ? idsInput.map(String).filter(Boolean) : [];
  const idsLimited = idsRaw.slice(0, MAX_PRESENCE_IDS);

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
    if (anyAuthSocketOpen(id)) online.push(id);
    const su = authUsers.get(id);
    if (su && su.roomId) busy.push(id);
  }

  return {
    onlineUserIds: online,
    busyUserIds: busy,
    serverVersion: String(SERVER_APP_VERSION),
  };
}

app.post('/api/chats/create-personal', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const otherUserId = typeof req.body?.otherUserId === 'string' ? req.body.otherUserId : '';
    const names = req.body?.names;
    if (!otherUserId || !names) return res.status(400).json({ error: 'otherUserId and names required' });

    const result = await authCreatePersonalChat(userId, otherUserId, names);
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
        const payload = { type: 'authChatsChanged' };
        for (const uid of [userId, otherUserId]) {
          forEachAuthSocket(String(uid), (ws) => {
            if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendReliable(ws, payload);
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

app.post('/api/chats/create-group', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatNameEnc = typeof req.body?.chatNameEnc === 'string' ? req.body.chatNameEnc : '';
    const names = req.body?.names;
    const result = await authCreateGroupChat(userId, chatNameEnc, names);
    if (!result.ok) return res.status(400).json({ error: result.reason });
    res.json({ success: true, chat: result.chat });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Auth user lookup by nameToken (VOPRF output). Returns userId+publicKey.
app.post('/api/users/lookup', requireAuthSession, async (req, res) => {
  try {
    const nameToken = typeof req.body?.nameToken === 'string' ? req.body.nameToken : '';
    if (!nameToken) return res.status(400).json({ error: 'nameToken required' });

    const r = await query(
      'SELECT id::text AS id, public_key, introvert_mode FROM users WHERE name_token = $1 LIMIT 1',
      [nameToken],
    );
    const row = r?.rows?.[0];
    if (!row?.id) return res.status(404).json({ error: 'not_found' });
    if (Boolean(row.introvert_mode)) {
      return res.status(403).json({
        error:
          'This is in introvert mode and he can not be added. If it your friend ask him to create a chat, or disaple introvert mode',
      });
    }

    res.json({ success: true, userId: String(row.id), publicKey: String(row.public_key ?? '') });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/chats/members', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.query?.chatId === 'string' ? req.query.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });

    const members = await authListChatMembers(userId, chatId);
    res.json({ success: true, members });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    if (e && e.code === 'not_group') return res.status(400).json({ error: 'not_group' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/chats/add-member', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const otherUserId = typeof req.body?.otherUserId === 'string' ? req.body.otherUserId : '';
    const chatNameEnc = typeof req.body?.chatNameEnc === 'string' ? req.body.chatNameEnc : '';
    const names = req.body?.names;
    if (!chatId || !otherUserId || !names || !chatNameEnc) {
      return res.status(400).json({ error: 'chatId, otherUserId, chatNameEnc, names required' });
    }

    const result = await authAddGroupMember(userId, chatId, otherUserId, names, chatNameEnc);
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
      const payload = { type: 'authChatsChanged' };
      for (const uid of targets) {
        forEachAuthSocket(String(uid), (ws) => {
          if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendReliable(ws, payload);
        });
      }
    } catch {
      // ignore
    }

    res.json({ success: true, member: result.member });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    if (e && e.code === 'bad_payload') return res.status(400).json({ error: 'Bad payload' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/chats/rename-group', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const chatNameEnc = typeof req.body?.chatNameEnc === 'string' ? req.body.chatNameEnc : '';
    if (!chatId || !chatNameEnc) return res.status(400).json({ error: 'chatId and chatNameEnc required' });

    const result = await authRenameGroupChat(userId, chatId, chatNameEnc);
    if (!result.ok) {
      const code = result.reason === 'not_found' ? 404 : 400;
      return res.status(code).json({ error: result.reason });
    }

    try {
      const payload = { type: 'authChatsChanged' };
      for (const uid of result.memberIds || []) {
        forEachAuthSocket(String(uid), (ws) => {
          if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendReliable(ws, payload);
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

app.get('/api/messages', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.query?.chatId === 'string' ? req.query.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });

    const limit = typeof req.query?.limit === 'string' ? Number(req.query.limit) : 50;
    const before = typeof req.query?.before === 'string' ? req.query.before : null;

    const messages = await authFetchMessages(userId, chatId, limit, before);
    res.json({ success: true, messages });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

// List unread message UUIDs for a chat (spec requirement).
app.get('/api/messages/unread', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.query?.chatId === 'string' ? req.query.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });
    const limit = typeof req.query?.limit === 'string' ? Number(req.query.limit) : 500;
    const messageIds = await authUnreadMessageIds(userId, chatId, limit);
    res.json({ success: true, chatId, messageIds });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

const MAX_ENCRYPTED_MESSAGE_BYTES = 50 * 1024;
const ERR_ENCRYPTED_TOO_LARGE = 'Encrypted message too large';

app.post('/api/messages/send', requireAuthSession, async (req, res) => {
  try {
    const senderId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const encryptedData = typeof req.body?.encryptedData === 'string' ? req.body.encryptedData : '';
    const signature = typeof req.body?.signature === 'string' ? req.body.signature : '';
    if (!chatId || !encryptedData) return res.status(400).json({ error: 'chatId and encryptedData required' });

    if (Buffer.byteLength(encryptedData, 'utf8') > MAX_ENCRYPTED_MESSAGE_BYTES) {
      return res.status(413).json({ error: ERR_ENCRYPTED_TOO_LARGE });
    }

    const { messageId, memberIds } = await authSendMessage({ senderId, chatId, encryptedData, signature });

    // Best-effort realtime notify to auth sockets.
    const payload = {
      type: 'authMessage',
      chatId,
      id: messageId,
      senderId,
      encryptedData,
      signature,
    };
    for (const uid of memberIds) {
      forEachAuthSocket(uid, (ws) => {
        if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, payload);
      });
    }

    // Best-effort Web Push notify for offline recipients (RAM-only subs).
    // Do not include message plaintext.
    for (const uid of memberIds) {
      if (String(uid) === String(senderId)) continue;
      if (anyAuthSocketOpen(uid)) continue;

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
    if (e && e.code === 'bad_payload') return res.status(400).json({ error: 'Bad payload' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages/delete', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const messageId = typeof req.body?.messageId === 'string' ? req.body.messageId : '';
    if (!chatId || !messageId) return res.status(400).json({ error: 'chatId and messageId required' });

    const r = await authDeleteMessage({ userId, chatId, messageId });
    if (!r.ok) {
      if (r.reason === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
      return res.status(404).json({ error: 'Not found' });
    }

    const payload = { type: 'authMessageDeleted', chatId, id: messageId };
    for (const uid of r.memberIds) {
      forEachAuthSocket(uid, (ws) => {
        if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, payload);
      });
    }

    res.json({ success: true });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages/update', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const messageId = typeof req.body?.messageId === 'string' ? req.body.messageId : '';
    const encryptedData = typeof req.body?.encryptedData === 'string' ? req.body.encryptedData : '';
    const signature = typeof req.body?.signature === 'string' ? req.body.signature : '';
    if (!chatId || !messageId || !encryptedData) {
      return res.status(400).json({ error: 'chatId, messageId, encryptedData required' });
    }

    if (Buffer.byteLength(encryptedData, 'utf8') > MAX_ENCRYPTED_MESSAGE_BYTES) {
      return res.status(413).json({ error: ERR_ENCRYPTED_TOO_LARGE });
    }

    const r = await authUpdateMessage({ userId, chatId, messageId, encryptedData, signature });
    if (!r.ok) {
      if (r.reason === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
      if (r.reason === 'bad_payload') return res.status(400).json({ error: 'Bad payload' });
      return res.status(404).json({ error: 'Not found' });
    }

    const payload = { type: 'authMessageUpdated', chatId, id: messageId, senderId: userId, encryptedData, signature };
    for (const uid of r.memberIds) {
      forEachAuthSocket(uid, (ws) => {
        if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, payload);
      });
    }

    res.json({ success: true });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages/mark-read', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });
    const messageIdsRaw = req.body?.messageIds;
    if (Array.isArray(messageIdsRaw) && messageIdsRaw.length) {
      const { unreadCount } = await authMarkMessagesRead(userId, chatId, messageIdsRaw);
      return res.json({ success: true, chatId, unreadCount });
    }

    await authMarkChatRead(userId, chatId);
    res.json({ success: true, chatId, unreadCount: 0 });
  } catch (e) {
    if (e && e.code === 'forbidden') return res.status(403).json({ error: 'Forbidden' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/chats/delete', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    if (!chatId) return res.status(400).json({ error: 'chatId required' });

    // Spec: in personal chats, deletion deletes the whole chat for both users.
    // For groups, this endpoint acts as "leave" (UI labels it accordingly).
    const del = await authDeletePersonalChat(userId, chatId);
    if (del && del.ok) {
      const payload = { type: 'authChatDeleted', chatId };
      for (const uid of del.memberIds) {
        forEachAuthSocket(uid, (ws) => {
          if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, payload);
        });
      }
    } else {
      const left = await authLeaveChat(userId, chatId);
      if (left && left.ok) {
        // Remaining members should refresh chat list (membership/messages changed).
        try {
          const payload = { type: 'authChatsChanged', chatId, reason: left.chatDeleted ? 'group_deleted' : 'member_left' };
          for (const uid of left.remainingMemberIds || []) {
            forEachAuthSocket(String(uid), (ws) => {
              if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, payload);
            });
          }
        } catch {
          // ignore
        }

        // Remove leaver's messages from remaining members' in-memory views.
        try {
          const ids = Array.isArray(left.deletedMessageIds) ? left.deletedMessageIds : [];
          if (ids.length) {
            // Avoid huge realtime payloads if someone deletes a lot of messages.
            const CHUNK = 500;
            for (let i = 0; i < ids.length; i += CHUNK) {
              const part = ids.slice(i, i + CHUNK);
              const payload = { type: 'authMessagesDeleted', chatId, ids: part };
              for (const uid of left.remainingMemberIds || []) {
                forEachAuthSocket(String(uid), (ws) => {
                  if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, payload);
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

app.post('/api/account/delete', requireAuthSession, async (req, res) => {
  try {
    const userId = String(req._authUserId);
    const token = parseAuthTokenFromReq(req);

    // Best-effort: force logout all sessions (online only).
    try {
      forEachAuthSocket(userId, (ws) => {
        if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendReliable(ws, { type: 'authForceLogout', reason: 'account_deleted', wipeLocalKeys: false });
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

    await authDeleteAccount(userId);

    // Revoke all tokens after deletion.
    try {
      revokeAllTokensForUser(userId);
    } catch {
      // ignore
    }

    // Close all auth sockets after revocation.
    try {
      closeAllAuthSockets(userId);
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

const authTransportSessions = new Map(); // userId -> Map(sessionId -> transportConn)

// Auth-mode: in-memory user state (presence + call state). Kept RAM-only.
const authUsers = new Map(); // userId -> { id, name, transportConn, roomId, ... }

// Auth-only: keep small client message receipt cache (for idempotency).
const CLIENT_MSGIDS_MAX = Number(process.env.CLIENT_MSGIDS_MAX ?? 2000);

// Reliable notifications (auth mode) for small control-plane events.
// We retry until the client ACKs, but only while the transport is open.
const TRANSPORT_NOTIFY_RETRY_MS = Number(process.env.TRANSPORT_NOTIFY_RETRY_MS ?? 5000);
const TRANSPORT_MAX_CTRL_PAYLOAD_BYTES = Number(process.env.TRANSPORT_MAX_CTRL_PAYLOAD_BYTES ?? 64 * 1024);
const TRANSPORT_MAX_DGRAM_PAYLOAD_BYTES = Number(process.env.TRANSPORT_MAX_DGRAM_PAYLOAD_BYTES ?? 1200);

function toTransportMessage(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  const hasEnvelopePayload = raw.payload && typeof raw.payload === 'object' && !Array.isArray(raw.payload);
  const envelopeType = typeof raw.type === 'string' ? String(raw.type) : '';

  let msg = null;

  if (hasEnvelopePayload) {
    msg = { ...raw.payload };
    if (typeof msg.type !== 'string') msg.type = envelopeType;
  } else {
    msg = { ...raw };
  }

  if (typeof msg?.type !== 'string' || !msg.type) return null;

  if (typeof raw.cMsgId === 'string' && raw.cMsgId) msg.cMsgId = raw.cMsgId;
  else if (typeof msg.cMsgId !== 'string') delete msg.cMsgId;

  if (typeof raw.msgId === 'string' && raw.msgId) msg.msgId = raw.msgId;
  else if (typeof msg.msgId !== 'string') delete msg.msgId;

  const chanRaw = typeof raw.chan === 'string' ? raw.chan : (typeof msg.chan === 'string' ? msg.chan : 'ctrl');
  const chan = chanRaw === 'dgram' ? 'dgram' : 'ctrl';
  msg.chan = chan;

  return msg;
}

function parseIncomingControlMessage(data) {
  let text = '';
  try {
    text = Buffer.isBuffer(data) ? data.toString('utf8') : String(data ?? '');
  } catch {
    return null;
  }

  const bytes = Buffer.byteLength(text, 'utf8');
  if (!Number.isFinite(bytes) || bytes <= 0 || bytes > TRANSPORT_MAX_CTRL_PAYLOAD_BYTES) return null;

  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }

  const msg = toTransportMessage(raw);
  if (!msg) return null;

  if (msg.chan === 'dgram' && bytes > TRANSPORT_MAX_DGRAM_PAYLOAD_BYTES) return null;
  return msg;
}

function getTransportRequestPathAndToken(transportSession) {
  let rawPath = '';

  const header = transportSession?.header ?? transportSession?.headers ?? null;
  if (header && typeof header === 'object') {
    if (typeof header.get === 'function') {
      rawPath = String(header.get(':path') ?? header.get('path') ?? '');
    } else {
      rawPath = String(header[':path'] ?? header.path ?? '');
    }
  }

  if (!rawPath && typeof transportSession?.path === 'string') rawPath = transportSession.path;
  if (!rawPath && typeof transportSession?.url === 'string') rawPath = transportSession.url;
  if (!rawPath) rawPath = WEBTRANSPORT_PATH;

  let pathname = WEBTRANSPORT_PATH;
  let token = '';
  try {
    const u = new URL(rawPath, 'https://localhost');
    pathname = String(u.pathname || WEBTRANSPORT_PATH);
    token = String(u.searchParams.get('token') ?? '');
  } catch {
    pathname = WEBTRANSPORT_PATH;
    token = '';
  }

  return { pathname, token };
}

function sendBestEffort(ws, obj) {
  if (!ws || typeof ws.sendJson !== 'function') return;
  try {
    ws.sendJson(obj);
  } catch {
    // ignore
  }
}

function createWebTransportSessionConn(params) {
  const sendControl = typeof params?.sendControl === 'function' ? params.sendControl : null;
  const closeConn = typeof params?.close === 'function' ? params.close : null;
  const isOpen = typeof params?.isOpen === 'function' ? params.isOpen : null;

  return {
    kind: 'webtransport',
    sessionId: typeof params?.sessionId === 'string' ? params.sessionId : '',
    userId: typeof params?.userId === 'string' ? params.userId : '',
    sendJson(obj) {
      if (!sendControl) return;
      sendControl(obj);
    },
    close() {
      if (!closeConn) return;
      closeConn();
    },
    isOpen() {
      if (!isOpen) return false;
      return Boolean(isOpen());
    },
  };
}

function getUserTransportSessionMap(userId) {
  const uid = String(userId ?? '');
  if (!uid) return null;
  let m = authTransportSessions.get(uid);
  if (!m) {
    m = new Map();
    authTransportSessions.set(uid, m);
  }
  return m;
}

function addTransportSession(userId, sessionId, transportConn) {
  const uid = String(userId ?? '');
  const sid = String(sessionId ?? '');
  if (!uid || !sid || !transportConn) return;
  const m = getUserTransportSessionMap(uid);
  if (!m) return;
  m.set(sid, transportConn);
}

function removeTransportSession(userId, sessionId, transportConn) {
  const uid = String(userId ?? '');
  const sid = String(sessionId ?? '');
  if (!uid || !sid) return;
  const m = authTransportSessions.get(uid);
  if (!m) return;
  const cur = m.get(sid);
  if (cur && transportConn && cur !== transportConn) return;
  m.delete(sid);
  if (m.size === 0) authTransportSessions.delete(uid);
}

function forEachTransportSession(userId, fn) {
  const uid = String(userId ?? '');
  if (!uid) return;
  const m = authTransportSessions.get(uid);
  if (!m) return;
  for (const transportConn of m.values()) {
    try {
      fn(transportConn);
    } catch {
      // ignore
    }
  }
}

function getTransportSessionForSessionId(userId, sessionId) {
  const uid = String(userId ?? '');
  const sid = String(sessionId ?? '');
  if (!uid || !sid) return null;
  const m = authTransportSessions.get(uid);
  return m ? m.get(sid) ?? null : null;
}

function closeAllTransportSessions(userId) {
  const uid = String(userId ?? '');
  if (!uid) return;
  const m = authTransportSessions.get(uid);
  if (!m) return;
  for (const transportConn of m.values()) {
    try {
      transportConn.close();
    } catch {
      // ignore
    }
  }
  authTransportSessions.delete(uid);
}

function hasAnyTransportSessions(userId) {
  const uid = String(userId ?? '');
  if (!uid) return false;
  return authTransportSessions.has(uid);
}

function getUserSocketMap(userId) {
  return getUserTransportSessionMap(userId);
}

function addAuthSocket(userId, sessionId, ws) {
  addTransportSession(userId, sessionId, ws);
}

function removeAuthSocket(userId, sessionId, ws) {
  removeTransportSession(userId, sessionId, ws);
}

function forEachAuthSocket(userId, fn) {
  forEachTransportSession(userId, fn);
}

function anyAuthSocketOpen(userId) {
  let open = false;
  forEachAuthSocket(userId, (ws) => {
    if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) open = true;
  });
  return open;
}

function closeAllAuthSockets(userId) {
  closeAllTransportSessions(userId);
}

function getAuthSocketForSession(userId, sessionId) {
  return getTransportSessionForSessionId(userId, sessionId);
}

function sendToUserAll(userId, obj) {
  forEachAuthSocket(userId, (ws) => {
    if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, obj);
  });
}

function sendToUserAllExceptSession(userId, exceptSessionId, obj) {
  const uid = String(userId ?? '');
  const sid = String(exceptSessionId ?? '');
  if (!uid) return;
  const m = authTransportSessions.get(uid);
  if (!m) return;
  for (const [s, ws] of m.entries()) {
    if (sid && s === sid) continue;
    if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, obj);
  }
}

function sendToUserSession(userId, sessionId, obj) {
  const ws = getAuthSocketForSession(userId, sessionId);
  if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) sendBestEffort(ws, obj);
}

function sendToUserCallSession(userId, obj) {
  const uid = String(userId ?? '');
  if (!uid) return;
  const u = authUsers.get(uid);
  const preferredSid = typeof u?.controllingSessionId === 'string' ? u.controllingSessionId : null;
  if (preferredSid) {
    const ws = getAuthSocketForSession(uid, preferredSid);
    if (ws && typeof ws.isOpen === 'function' && ws.isOpen()) {
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
      if (!ws || typeof ws.isOpen !== 'function' || !ws.isOpen()) {
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
  }, Math.max(1000, TRANSPORT_NOTIFY_RETRY_MS));
}

function sendReliable(ws, obj) {
  if (!ws || typeof ws.isOpen !== 'function' || !ws.isOpen()) return null;
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
// Auth-mode voice rooms
// ------------------------

// Keep auth call rooms separate from anonymous rooms.
const authRooms = new Map();

function getAuthRoom(roomId) {
  return roomId ? authRooms.get(roomId) : null;
}

function ensureAuthRoom(roomId) {
  if (!authRooms.has(roomId)) {
    authRooms.set(roomId, { id: roomId, members: new Set(), ownerId: null, joinQueue: [], joinActive: null });
  }
  return authRooms.get(roomId);
}

function authPickRoomOwner(room) {
  const ownerId = room.ownerId;
  if (ownerId && room.members.has(ownerId)) {
    if (anyAuthSocketOpen(ownerId)) return ownerId;
  }
  for (const memberId of room.members) {
    if (anyAuthSocketOpen(memberId)) return memberId;
  }
  return null;
}

function authRemoveJoinRequestFromRoom(room, requesterId) {
  if (!room) return;
  if (!requesterId) return;

  if (room.joinActive === requesterId) {
    room.joinActive = null;
  }

  if (Array.isArray(room.joinQueue)) {
    room.joinQueue = room.joinQueue.filter((id) => id !== requesterId);
  }
}

function authPumpJoinQueue(room) {
  if (!room) return;
  if (room.joinActive) return;
  if (!Array.isArray(room.joinQueue) || room.joinQueue.length === 0) return;

  while (room.joinQueue.length) {
    const nextId = room.joinQueue[0];
    const requester = authUsers.get(nextId);
    if (!requester) {
      room.joinQueue.shift();
      continue;
    }

    const ownerId = authPickRoomOwner(room);
    if (!ownerId) {
      // Nobody online to approve. Reject all pending requests.
      for (const rid of room.joinQueue.splice(0)) {
        const u = authUsers.get(rid);
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
    const owner = authUsers.get(ownerId);
    if (owner) sendToUserCallSession(ownerId, { type: 'joinRequest', from: requester.id, fromName: requester.name, roomId: room.id });
    return;
  }
}

function authLeaveRoom(user) {
  const rid = user?.roomId;
  if (!rid) return;

  const room = authRooms.get(rid);
  user.roomId = null;
  if (!room) return;

  room.members.delete(user.id);

  authRemoveJoinRequestFromRoom(room, user.id);
  if (room.ownerId === user.id) room.ownerId = authPickRoomOwner(room);

  for (const memberId of room.members) {
    sendToUserCallSession(memberId, { type: 'roomPeerLeft', roomId: rid, peerId: user.id });
  }

  if (room.members.size <= 1) {
    const lastId = Array.from(room.members)[0];
    if (lastId) {
      const last = authUsers.get(lastId);
      if (last) {
        last.roomId = null;
        last.controllingSessionId = null;
        sendToUserAll(lastId, { type: 'callEnded', reason: 'alone' });
      }
    }

    // Reject any pending joiners.
    if (Array.isArray(room.joinQueue)) {
      for (const jid of room.joinQueue) {
        const u = authUsers.get(jid);
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
      const u = authUsers.get(room.joinActive);
      const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
      if (u) {
        u.joinPendingRoomId = null;
        u.joinPendingSessionId = null;
      }
      if (joinSid) sendToUserSession(room.joinActive, joinSid, { type: 'callJoinResult', ok: false, reason: 'ended' });
      else sendToUserAll(room.joinActive, { type: 'callJoinResult', ok: false, reason: 'ended' });
    }

    authRooms.delete(rid);
    return;
  }

  authPumpJoinQueue(room);
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

async function handleAuthControlMessage(transportConn, authUser, sid, msg) {
  if (msg.type === 'ack') {
    const msgId = typeof msg.msgId === 'string' ? msg.msgId : null;
    if (msgId) ackReliable(transportConn, msgId);
    return;
  }

  const cMsgId = typeof msg.cMsgId === 'string' && msg.cMsgId ? msg.cMsgId : null;
  if (cMsgId) {
    const prev = getClientReceipt(authUser, cMsgId);
    if (prev) {
      sendBestEffort(transportConn, prev);
      return;
    }
  }

  if (msg.type === 'ping') {
    sendBestEffort(transportConn, { type: 'pong' });
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'presenceHeartbeat') {
    const raw = Array.isArray(msg.userIds) ? msg.userIds : [];
    const snapshot = await buildPresenceSnapshotForUser(authUser.id, raw);
    sendBestEffort(transportConn, { type: 'presenceSnapshot', ...snapshot });
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callStart') {
    const to = typeof msg.to === 'string' ? msg.to : null;
    if (!to) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, false, 'BAD_TO');
      return;
    }
    const callee = authUsers.get(to);
    if (!callee || !anyAuthSocketOpen(to)) {
      sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'offline' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    if (authUser.roomId) {
      sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'busy' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

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
        [authUser.id, String(to)],
      );
      authRow = auth?.rows?.[0] ?? null;
    } catch (err) {
      const msgText = typeof err?.message === 'string' ? err.message : '';
      const mayBeMissingIntrovertColumn = msgText.includes('introvert_mode');

      if (mayBeMissingIntrovertColumn) {
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
            [authUser.id, String(to)],
          );
          const row = auth?.rows?.[0] ?? null;
          authRow = row ? { ...row, introvert: false } : null;
        } catch (err2) {
          debugError('[auth callStart] auth query failed (fallback)', {
            from: authUser?.id,
            to,
            err: err2,
          });
          sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'server' });
          if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
          return;
        }
      } else {
        debugError('[auth callStart] auth query failed', {
          from: authUser?.id,
          to,
          err,
        });
        sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'server' });
        if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
        return;
      }
    }

    if (!authRow) {
      sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'server' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    const hasAny = Boolean(authRow?.has_any);
    const hasPersonal = Boolean(authRow?.has_personal);
    const introvert = Boolean(authRow?.introvert);

    if (!hasAny) {
      sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'not_allowed' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    if (introvert && !hasPersonal) {
      sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'introvert' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    if (callee.roomId) {
      sendBestEffort(transportConn, { type: 'callStartResult', ok: false, reason: 'busy' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    const rid = makeId();
    const room = ensureAuthRoom(rid);
    room.members.add(authUser.id);
    room.members.add(callee.id);
    room.ownerId = authUser.id;
    authUser.roomId = rid;
    authUser.controllingSessionId = String(sid);
    callee.roomId = rid;
    callee.controllingSessionId = null;

    sendBestEffort(transportConn, { type: 'callStartResult', ok: true, roomId: rid });
    sendToUserAll(callee.id, { type: 'incomingCall', from: authUser.id, fromName: authUser.name, roomId: rid });
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callAccept') {
    if (authUser.controllingSessionId && String(authUser.controllingSessionId) !== String(sid)) {
      sendBestEffort(transportConn, { type: 'incomingCallCancelled', roomId: typeof msg.roomId === 'string' ? msg.roomId : null, reason: 'accepted_elsewhere' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    const from = typeof msg.from === 'string' ? msg.from : null;
    const rid = typeof msg.roomId === 'string' ? msg.roomId : authUser.roomId;
    const caller = from ? authUsers.get(from) : null;
    if (!caller) {
      authUser.roomId = null;
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, false, 'NOT_FOUND');
      return;
    }

    if (!rid || caller.roomId !== rid || authUser.roomId !== rid) {
      authUser.roomId = null;
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, false, 'ROOM_MISMATCH');
      return;
    }

    const room = getAuthRoom(rid);
    if (!room) {
      authUser.roomId = null;
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, false, 'ROOM_MISSING');
      return;
    }

    authUser.controllingSessionId = String(sid);
    sendToUserAllExceptSession(authUser.id, sid, { type: 'incomingCallCancelled', roomId: rid, reason: 'accepted_elsewhere' });

    const peer = { id: authUser.id, name: authUser.name };
    for (const memberId of room.members) {
      if (memberId === authUser.id) continue;
      sendToUserCallSession(memberId, { type: 'roomPeerJoined', roomId: rid, peer });
    }

    const peers = Array.from(room.members)
      .filter((id) => id !== authUser.id)
      .map((id) => {
        const u2 = authUsers.get(id);
        return u2 ? { id: u2.id, name: u2.name } : null;
      })
      .filter(Boolean);

    sendBestEffort(transportConn, { type: 'roomPeers', roomId: rid, peers });
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callReject') {
    if (authUser.controllingSessionId && String(authUser.controllingSessionId) !== String(sid)) {
      sendBestEffort(transportConn, { type: 'incomingCallCancelled', roomId: typeof msg.roomId === 'string' ? msg.roomId : null, reason: 'rejected_elsewhere' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    const from = typeof msg.from === 'string' ? msg.from : null;
    const rid = typeof msg.roomId === 'string' ? msg.roomId : authUser.roomId;
    const caller = from ? authUsers.get(from) : null;
    if (caller) sendToUserCallSession(caller.id, { type: 'callRejected', reason: 'rejected' });
    if (rid) {
      sendToUserAllExceptSession(authUser.id, sid, { type: 'incomingCallCancelled', roomId: rid, reason: 'rejected' });

      const room = getAuthRoom(rid);
      if (room && room.members.size === 2) {
        for (const memberId of room.members) {
          const u = authUsers.get(memberId);
          if (u && u.roomId === rid) {
            u.roomId = null;
            u.controllingSessionId = null;
          }
        }

        if (Array.isArray(room.joinQueue)) {
          for (const jid of room.joinQueue) {
            const u = authUsers.get(jid);
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
          const u = authUsers.get(room.joinActive);
          const joinSid = typeof u?.joinPendingSessionId === 'string' ? u.joinPendingSessionId : null;
          if (u) {
            u.joinPendingRoomId = null;
            u.joinPendingSessionId = null;
          }
          if (joinSid) sendToUserSession(room.joinActive, joinSid, { type: 'callJoinResult', ok: false, reason: 'ended' });
          else sendToUserAll(room.joinActive, { type: 'callJoinResult', ok: false, reason: 'ended' });
        }

        authRooms.delete(rid);
      }
    }

    authUser.roomId = null;
    authUser.controllingSessionId = null;
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callHangup') {
    if (authUser.controllingSessionId && String(authUser.controllingSessionId) !== String(sid)) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    const rid = authUser.roomId;
    const room = rid ? getAuthRoom(rid) : null;
    if (rid && room && room.members.size === 2) {
      const otherId = Array.from(room.members).find((id) => id !== authUser.id) ?? null;
      const other = otherId ? authUsers.get(otherId) : null;
      const otherAccepted = Boolean(other?.controllingSessionId);
      if (otherId && !otherAccepted) {
        sendToUserAll(otherId, { type: 'incomingCallCancelled', roomId: rid, reason: 'hangup' });
        for (const memberId of room.members) {
          const u = authUsers.get(memberId);
          if (u && u.roomId === rid) {
            u.roomId = null;
            u.controllingSessionId = null;
          }
        }
        authRooms.delete(rid);
        if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
        return;
      }
    }

    authLeaveRoom(authUser);
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callJoinRequest') {
    const to = typeof msg.to === 'string' ? msg.to : null;
    const target = to ? authUsers.get(to) : null;
    if (!target || !target.roomId) {
      sendBestEffort(transportConn, { type: 'callJoinResult', ok: false, reason: 'not_in_call' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    const room = getAuthRoom(target.roomId);
    if (!room) {
      sendBestEffort(transportConn, { type: 'callJoinResult', ok: false, reason: 'ended' });
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    authUser.joinPendingRoomId = room.id;
    authUser.joinPendingSessionId = String(sid);
    if (!Array.isArray(room.joinQueue)) room.joinQueue = [];
    room.joinQueue.push(authUser.id);
    sendBestEffort(transportConn, { type: 'callJoinPending', roomId: room.id, toName: target.name });
    authPumpJoinQueue(room);
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callJoinCancel') {
    if (authUser.joinPendingSessionId && String(authUser.joinPendingSessionId) !== String(sid)) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    const rid = authUser.joinPendingRoomId;
    if (rid) {
      const room = getAuthRoom(rid);
      if (room) authRemoveJoinRequestFromRoom(room, authUser.id);
      authPumpJoinQueue(room);
    }
    authUser.joinPendingRoomId = null;
    authUser.joinPendingSessionId = null;
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callJoinReject') {
    if (authUser.controllingSessionId && String(authUser.controllingSessionId) !== String(sid)) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    const from = typeof msg.from === 'string' ? msg.from : null;
    const rid = typeof msg.roomId === 'string' ? msg.roomId : null;
    const requester = from ? authUsers.get(from) : null;
    const room = rid ? getAuthRoom(rid) : null;
    const joinSid = typeof requester?.joinPendingSessionId === 'string' ? requester.joinPendingSessionId : null;
    if (requester) {
      requester.joinPendingRoomId = null;
      requester.joinPendingSessionId = null;
    }
    if (room) authRemoveJoinRequestFromRoom(room, from);
    if (from) {
      if (joinSid) sendToUserSession(from, joinSid, { type: 'callJoinResult', ok: false, reason: 'rejected' });
      else sendToUserAll(from, { type: 'callJoinResult', ok: false, reason: 'rejected' });
    }
    authPumpJoinQueue(room);
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'callJoinAccept') {
    if (authUser.controllingSessionId && String(authUser.controllingSessionId) !== String(sid)) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    const from = typeof msg.from === 'string' ? msg.from : null;
    const rid = typeof msg.roomId === 'string' ? msg.roomId : null;
    const requester = from ? authUsers.get(from) : null;
    const room = rid ? getAuthRoom(rid) : null;
    if (!requester || !room) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }

    if (room.joinActive !== requester.id) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
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
        const u2 = authUsers.get(id);
        return u2 ? { id: u2.id, name: u2.name } : null;
      })
      .filter(Boolean);

    sendToUserCallSession(requester.id, { type: 'roomPeers', roomId: rid, peers });
    sendToUserCallSession(requester.id, { type: 'callJoinResult', ok: true });

    room.joinActive = null;
    authPumpJoinQueue(room);
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (msg.type === 'signal') {
    const to = typeof msg.to === 'string' ? msg.to : null;
    const payload = msg.payload;
    if (!to) return;
    const peer = authUsers.get(to);
    if (!peer) return;
    if (!authUser.roomId || authUser.roomId !== peer.roomId) return;
    if (authUser.controllingSessionId && String(authUser.controllingSessionId) !== String(sid)) {
      if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
      return;
    }
    sendToUserCallSession(peer.id, { type: 'signal', from: authUser.id, fromName: authUser.name, payload });
    if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, true);
    return;
  }

  if (cMsgId) sendClientReceipt(authUser, transportConn, cMsgId, false, 'UNKNOWN_TYPE');
}

function handleAuthSessionClose(uid, sid, transportConn) {
  removeAuthSocket(uid, sid, transportConn);

  const curUser = authUsers.get(uid);

  if (curUser?.controllingSessionId && String(curUser.controllingSessionId) === String(sid)) {
    if (curUser.roomId) authLeaveRoom(curUser);
    curUser.controllingSessionId = null;
  }

  if (curUser?.joinPendingSessionId && String(curUser.joinPendingSessionId) === String(sid)) {
    const rid = curUser.joinPendingRoomId;
    if (rid) {
      const room = getAuthRoom(rid);
      if (room) {
        authRemoveJoinRequestFromRoom(room, curUser.id);
        authPumpJoinQueue(room);
      }
    }
    curUser.joinPendingRoomId = null;
    curUser.joinPendingSessionId = null;
  }

  const stillHasSockets = hasAnyTransportSessions(String(uid));
  if (!stillHasSockets) {
    if (curUser?.roomId) authLeaveRoom(curUser);
    authUsers.delete(uid);
  }
}

function ensureAuthUserState(uid, authName = '') {
  const prev = authUsers.get(uid);
  const authUser = prev ?? {
    id: uid,
    name: authName,
    lastMsgAt: Date.now(),
    roomId: null,
    controllingSessionId: null,
    joinPendingRoomId: null,
    joinPendingSessionId: null,
    _clientReceipts: null,
    _clientReceiptQueue: null,
  };

  authUser.name = authName || authUser.name;
  authUser.lastMsgAt = Date.now();
  authUsers.set(uid, authUser);
  return authUser;
}

async function streamToTransportMessages(readable, onMessage) {
  if (!readable || typeof readable.getReader !== 'function') return;
  const reader = readable.getReader();
  const decoder = new TextDecoder();
  let acc = '';

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunkText = decoder.decode(value, { stream: true });
      acc += chunkText;

      while (true) {
        const idx = acc.indexOf('\n');
        if (idx < 0) break;
        const line = acc.slice(0, idx).trim();
        acc = acc.slice(idx + 1);
        if (!line) continue;
        const msg = parseIncomingControlMessage(line);
        if (!msg) continue;
        await onMessage(msg);
      }
    }

    const tail = acc.trim();
    if (tail) {
      const msg = parseIncomingControlMessage(tail);
      if (msg) await onMessage(msg);
    }
  } catch {
    // ignore
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
}

async function streamWebTransportSessions(sessionReadable) {
  if (!sessionReadable || typeof sessionReadable.getReader !== 'function') return;
  const reader = sessionReadable.getReader();
  while (true) {
    let step;
    try {
      step = await reader.read();
    } catch {
      break;
    }
    if (!step || step.done) break;
    const session = step.value;
    if (!session) continue;
    void handleWebTransportSession(session);
  }
}

async function handleWebTransportSession(session) {
  const req = getTransportRequestPathAndToken(session);
  if (!req?.token || req.pathname !== WEBTRANSPORT_PATH) {
    try { await session.close?.(); } catch { /* ignore */ }
    return;
  }

  const sess = getSessionForToken(req.token);
  if (!sess?.userId || !sess?.sessionId) {
    try { await session.close?.(); } catch { /* ignore */ }
    return;
  }

  const uid = String(sess.userId);
  const sid = String(sess.sessionId);
  const authUser = ensureAuthUserState(uid, '');

  let sessionOpen = true;
  let sessionClosedHandled = false;
  let controlWriter = null;
  let writerPumping = false;
  const queuedFrames = [];

  const cleanup = () => {
    if (sessionClosedHandled) return;
    sessionClosedHandled = true;
    sessionOpen = false;
    handleAuthSessionClose(uid, sid, transportConn);
  };

  const pumpWriter = () => {
    if (!sessionOpen || !controlWriter || writerPumping) return;
    writerPumping = true;
    void (async () => {
      try {
        while (sessionOpen && controlWriter && queuedFrames.length) {
          const frame = queuedFrames.shift();
          if (!frame) continue;
          await controlWriter.write(Buffer.from(frame, 'utf8'));
        }
      } catch {
        sessionOpen = false;
      } finally {
        writerPumping = false;
      }
    })();
  };

  const transportConn = createWebTransportSessionConn({
    sessionId: sid,
    userId: uid,
    sendControl(obj) {
      if (!sessionOpen) return;
      let frame = '';
      try {
        frame = `${JSON.stringify(obj)}\n`;
      } catch {
        return;
      }
      if (Buffer.byteLength(frame, 'utf8') > TRANSPORT_MAX_CTRL_PAYLOAD_BYTES) return;
      queuedFrames.push(frame);
      if (queuedFrames.length > 1024) queuedFrames.shift();
      pumpWriter();
    },
    close() {
      sessionOpen = false;
      try { controlWriter?.close?.(); } catch { /* ignore */ }
      try { session.close?.(); } catch { /* ignore */ }
    },
    isOpen() {
      return sessionOpen;
    },
  });

  addTransportSession(uid, sid, transportConn);
  sendBestEffort(transportConn, { type: 'authHello', userId: uid });

  void Promise.resolve(session.closed)
    .catch(() => null)
    .then(() => {
      cleanup();
    });

  try {
    const bidi = session.incomingBidirectionalStreams;
    if (!bidi || typeof bidi.getReader !== 'function') {
      transportConn.close();
      cleanup();
      return;
    }

    const bidiReader = bidi.getReader();
    const first = await bidiReader.read();
    if (!first || first.done || !first.value) {
      transportConn.close();
      cleanup();
      return;
    }

    const controlStream = first.value;
    if (controlStream?.writable && typeof controlStream.writable.getWriter === 'function') {
      controlWriter = controlStream.writable.getWriter();
      pumpWriter();
    }

    if (session?.datagrams?.readable) {
      void streamToTransportMessages(session.datagrams.readable, async (msg) => {
        if (!msg) return;
        authUser.lastMsgAt = Date.now();
        await handleAuthControlMessage(transportConn, authUser, sid, msg);
      });
    }

    await streamToTransportMessages(controlStream?.readable, async (msg) => {
      if (!msg) return;
      authUser.lastMsgAt = Date.now();
      await handleAuthControlMessage(transportConn, authUser, sid, msg);
    });

    sessionOpen = false;
    cleanup();
  } catch {
    sessionOpen = false;
    cleanup();
  }
}

async function startWebTransportServer() {
  if (!WEBTRANSPORT_ENABLED) return null;

  const mod = await import('@fails-components/webtransport');
  const Http3Server = mod?.Http3Server;
  if (typeof Http3Server !== 'function') {
    throw new Error('WebTransport runtime unavailable');
  }

  const wtServer = new Http3Server({
    host: WEBTRANSPORT_HOST,
    port: WEBTRANSPORT_PORT,
    cert: fs.readFileSync(TLS_CERT_PATH),
    privKey: fs.readFileSync(TLS_KEY_PATH),
    secret: WEBTRANSPORT_SECRET || crypto.randomBytes(16).toString('hex'),
  });

  if (typeof wtServer.startServer === 'function') {
    await wtServer.startServer();
  }

  const sessions = wtServer.sessionStream(WEBTRANSPORT_PATH);
  void streamWebTransportSessions(sessions);
  return wtServer;
}

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

  if (AUTH_CLEANUP_ENABLED) {
    const interval = Number.isFinite(AUTH_CLEANUP_INTERVAL_MS)
      ? Math.max(60 * 1000, AUTH_CLEANUP_INTERVAL_MS)
      : 24 * 60 * 60 * 1000;

    const initialDelay = Number.isFinite(AUTH_CLEANUP_INITIAL_DELAY_MS)
      ? Math.max(0, AUTH_CLEANUP_INITIAL_DELAY_MS)
      : 30 * 1000;

    const run = async () => {
      try {
        await authCleanupExpiredUsers();
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

  try {
    const wtServer = await startWebTransportServer();
    if (!wtServer) {
      process.exit(1);
      return;
    }
  } catch {
    process.exit(1);
    return;
  }

  server.listen(PORT, HOST, () => {
    // No logs (policy: no connection tracking, IPs, or device info)
  });
}

void start();
