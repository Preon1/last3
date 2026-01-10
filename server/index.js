import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import path from 'path';
import express from 'express';
import { WebSocketServer } from 'ws';
import webpush from 'web-push';
import { fileURLToPath } from 'url';
import { debugError } from './logger.js';
import { initDatabase, query } from './db.js';
import { registerUser, loginUser, getUserByUsername } from './auth.js';
import { issueToken, getUserIdForToken, requireSignedAuth, parseAuthTokenFromReq, revokeToken } from './signedSession.js';
import {
  signedListChats,
  signedUnreadCounts,
  signedCreatePersonalChat,
  signedCreateGroupChat,
  signedListChatMembers,
  signedAddGroupMember,
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
const SIGNED_CLEANUP_INTERVAL_MS = Number(process.env.SIGNED_CLEANUP_INTERVAL_MS ?? 24 * 60 * 60 * 1000);
const SIGNED_CLEANUP_INITIAL_DELAY_MS = Number(process.env.SIGNED_CLEANUP_INITIAL_DELAY_MS ?? 30 * 1000);

// Optional Web Push (background notifications). If keys are not provided, the app
// still supports in-tab notifications when the page is open.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY ?? '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY ?? '';
const VAPID_SUBJECT = process.env.VAPID_SUBJECT ?? 'mailto:lrcom@localhost';
const PUSH_ENABLED = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);

// Visual branding
const APP_NAME = (process.env.APP_NAME ?? 'Last').trim() || 'Last';


if (PUSH_ENABLED) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
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

app.use(express.static(PUBLIC_DIR, {
  etag: false,
  lastModified: false,
  setHeaders(res) {
    // Avoid caching to reduce "traces"; browsers may still keep memory caches transiently.
    res.setHeader('Cache-Control', 'no-store');
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

app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ appName: APP_NAME });
});

// Auth endpoints for authenticated mode
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, publicKey, expirationDays } = req.body;
    
    if (!username || !password || !publicKey || !expirationDays) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const user = await registerUser({
      username,
      password,
      publicKey,
      expirationDays: parseInt(expirationDays, 10),
    });

    const { token } = issueToken(String(user.id));

    res.json({
      success: true,
      token,
      userId: user.id,
      username: user.username,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;
    
    if (!username || !password || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const result = await loginUser({ username, password, publicKey });

    const { token } = issueToken(String(result.userId));

    res.json({
      success: true,
      token,
      ...result,
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid credentials' });
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
      publicKey: user ? user.public_key : null,
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signed-mode API (token auth; no cookies)
app.get('/api/signed/chats', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const chats = await signedListChats(userId);
    const unread = await signedUnreadCounts(userId);
    res.json({ success: true, chats, unread });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signed presence (privacy-preserving): caller provides a list of userIds; response
// only indicates which of those are currently connected to signed WS.
app.post('/api/signed/presence', requireSignedAuth, async (req, res) => {
  try {
    const me = String(req._signedUserId);
    const raw = req.body?.userIds;
    const ids = Array.isArray(raw) ? raw.map(String).filter(Boolean) : [];
    const online = [];
    const busy = [];
    for (const id of ids) {
      if (!id || id === me) continue;
      const ws = signedSockets.get(id);
      if (ws && ws.readyState === 1) online.push(id);
      const su = signedUsers.get(id);
      if (su && su.roomId) busy.push(id);
    }
    res.json({ success: true, onlineUserIds: online, busyUserIds: busy });
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
      return res.status(code).json({ error: result.reason });
    }

    // Ensure the chat appears immediately for both members (if online) without
    // requiring the other user to also create it.
    try {
      const chatId = String(result?.chat?.id ?? '');
      const otherUserId = String(result?.chat?.otherUserId ?? '');
      if (chatId && otherUserId) {
        const payload = { type: 'signedChatsChanged', chatId, reason: 'personal_created' };
        for (const uid of [userId, otherUserId]) {
          const ws = signedSockets.get(String(uid));
          if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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
      return res.status(code).json({ error: result.reason });
    }

    res.json({ success: true, member: result.member });
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

app.post('/api/signed/messages/send', requireSignedAuth, async (req, res) => {
  try {
    const senderId = String(req._signedUserId);
    const chatId = typeof req.body?.chatId === 'string' ? req.body.chatId : '';
    const encryptedData = typeof req.body?.encryptedData === 'string' ? req.body.encryptedData : '';
    if (!chatId || !encryptedData) return res.status(400).json({ error: 'chatId and encryptedData required' });

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
      const ws = signedSockets.get(uid);
      if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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
      const ws = signedSockets.get(uid);
      if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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
      const ws = signedSockets.get(uid);
      if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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
        const ws = signedSockets.get(uid);
        if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
      }
    } else {
      await signedLeaveChat(userId, chatId);
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

    // Best-effort: close signed websocket for this user.
    try {
      const sock = signedSockets.get(userId);
      if (sock) {
        try {
          sock.close();
        } catch {
          // ignore
        }
      }
    } catch {
      // ignore
    }

    await signedDeleteAccount(userId);

    // Revoke token after deletion.
    try {
      revokeToken(token);
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

function safeName(input) {
  if (typeof input !== 'string') return null;

  const trimmed = input.trim();
  if (!trimmed) return null;

  // Normalize to keep uniqueness stable across equivalent forms.
  const normalized = typeof trimmed.normalize === 'function' ? trimmed.normalize('NFC') : trimmed;

  // Max 20 Unicode code points (not UTF-16 code units).
  if (Array.from(normalized).length > 20) return null;

  // Disallow control characters (incl. newlines/tabs) for safety.
  if (/\p{Cc}/u.test(normalized)) return null;

  return normalized;
}

function safeChatText(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (trimmed.length < 1 || trimmed.length > 500) return null;
  // Avoid control characters (but allow newlines for multiline chat)
  // Allow: LF (\n) and CR (\r). Disallow everything else in C0 controls.
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(trimmed)) return null;
  return trimmed;
}

function makeId() {
  return crypto.randomBytes(12).toString('hex');
}

function makeMsgId() {
  // Used for client-side reply references and scroll/flash targeting.
  // crypto.randomUUID is available on modern Node (incl. Node 20).
  return crypto.randomUUID();
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

/**
 * Ephemeral state only (memory); no persistence.
 * users: id -> { id, name, ws, lastMsgAt, roomId }
 */
const users = new Map();
const nameToId = new Map();

/**
 * rooms: roomId -> { id, members:Set<string> }
 */
const rooms = new Map();

// Signed-mode: in-memory sockets keyed by authenticated userId.
const signedSockets = new Map(); // userId -> ws

// Signed-mode: in-memory user state (presence + call state). Kept RAM-only.
const signedUsers = new Map(); // userId -> { id, name, ws, roomId, ... }

// Reliable delivery (RAM-only): message id + client ack + limited retries.
// Enabled per-client after it sends {type:'clientHello', features:{ack:true}}.
const pendingReliable = new Map(); // userId -> Map<msgId, { json: string, attempts: number, nextAt: number }>
const RELIABLE_MAX_ATTEMPTS = Number(process.env.RELIABLE_MAX_ATTEMPTS ?? 5);
const RELIABLE_BASE_DELAY_MS = Number(process.env.RELIABLE_BASE_DELAY_MS ?? 800);
const RELIABLE_MAX_DELAY_MS = Number(process.env.RELIABLE_MAX_DELAY_MS ?? 8000);
const RELIABLE_PUMP_MS = Number(process.env.RELIABLE_PUMP_MS ?? 500);
const PRESENCE_TICK_MS = Number(process.env.PRESENCE_TICK_MS ?? 10000);
const STALE_WS_MS = Number(process.env.STALE_WS_MS ?? 45000);
const CLIENT_MSGIDS_MAX = Number(process.env.CLIENT_MSGIDS_MAX ?? 2000);

function calcRetryDelayMs(attempts) {
  // attempts starts at 1 for the initial send.
  const exp = Math.max(0, attempts - 1);
  const delay = RELIABLE_BASE_DELAY_MS * Math.pow(2, exp);
  return Math.min(RELIABLE_MAX_DELAY_MS, Math.max(RELIABLE_BASE_DELAY_MS, delay));
}

function calcRetryDelayMsWithPolicy(attempts, policy) {
  if (policy?.fixedDelayMs) return Math.max(0, Number(policy.fixedDelayMs) || 0);
  const base = Number(policy?.baseDelayMs ?? RELIABLE_BASE_DELAY_MS);
  const max = Number(policy?.maxDelayMs ?? RELIABLE_MAX_DELAY_MS);
  const exp = Math.max(0, attempts - 1);
  const delay = base * Math.pow(2, exp);
  return Math.min(max, Math.max(base, delay));
}

function queueReliable(userId, key, msgId, json, policy = null, meta = null) {
  if (!pendingReliable.has(userId)) pendingReliable.set(userId, new Map());
  const perUser = pendingReliable.get(userId);
  const maxAttempts = Number(policy?.maxAttempts ?? RELIABLE_MAX_ATTEMPTS);
  perUser.set(key, {
    msgId,
    json,
    attempts: 1,
    maxAttempts,
    policy,
    meta,
    nextAt: Date.now() + calcRetryDelayMsWithPolicy(1, policy),
  });
}

function ackReliable(userId, msgId) {
  const perUser = pendingReliable.get(userId);
  if (!perUser) return;

  // msgId isn't necessarily the map key when we coalesce state messages.
  for (const [key, entry] of perUser) {
    if (entry.msgId === msgId) {
      perUser.delete(key);
      break;
    }
  }
  if (perUser.size === 0) pendingReliable.delete(userId);
}

function flushReliableForUser(user) {
  if (!user?.id) return;
  if (!user?.ws || user.ws.readyState !== 1) return;
  if (!user.supportsAck) return;

  const perUser = pendingReliable.get(user.id);
  if (!perUser || perUser.size === 0) return;

  const now = Date.now();
  for (const [key, entry] of perUser) {
    if (entry.nextAt > now) continue;

    if (entry.attempts >= (entry.maxAttempts ?? RELIABLE_MAX_ATTEMPTS)) {
      perUser.delete(key);
      if (entry?.meta) {
        try {
          handleReliableDeliveryFailure(entry.meta);
        } catch {
          // ignore
        }
      }
      continue;
    }

    try {
      user.ws.send(entry.json);
      entry.attempts += 1;
      entry.nextAt = now + calcRetryDelayMsWithPolicy(entry.attempts, entry.policy);
    } catch {
      // If send throws, we'll try again later.
      entry.attempts += 1;
      entry.nextAt = now + calcRetryDelayMsWithPolicy(entry.attempts, entry.policy);
    }
  }

  if (perUser.size === 0) pendingReliable.delete(user.id);
}

function handleReliableDeliveryFailure(meta) {
  // Only used for private message delivery failure notifications.
  if (!meta || meta.kind !== 'pmDelivery' || !meta.fromUserId || !meta.toName) return;

  const fromUser = users.get(meta.fromUserId);
  if (!fromUser || !fromUser.name || !fromUser.ws || fromUser.ws.readyState !== 1) return;

  const atIso = new Date().toISOString();
  const id = makeMsgId();
  const text = `Delivery failed: ${meta.toName} is offline or unreachable.`;

  const msg = {
    type: 'chat',
    id,
    atIso,
    from: null,
    fromName: 'System',
    to: fromUser.id,
    toName: meta.toName,
    text,
    private: true,
    msgId: id,
  };

  send(fromUser.ws, msg, { maxAttempts: 5, fixedDelayMs: 1000, coalesceKey: `pmfail:${id}` });
}

function sendBestEffort(ws, obj) {
  if (!ws || ws.readyState !== 1) return;
  try {
    ws.send(JSON.stringify(obj));
  } catch {
    // ignore
  }
}

function sendReliableToUser(user, obj, opts = null) {
  if (!user?.ws || user.ws.readyState !== 1) return;
  if (!user.supportsAck) {
    sendBestEffort(user.ws, obj);
    return;
  }

  const msgId = typeof obj.msgId === 'string' && obj.msgId ? obj.msgId : makeMsgId();
  const coalesceKey = opts && typeof opts.coalesceKey === 'string' ? opts.coalesceKey : null;
  const key = coalesceKey ?? msgId;
  const payload = { ...obj, msgId, reliable: true };
  const json = JSON.stringify(payload);

  // Best-effort immediate send + queue for retry until ack.
  try {
    user.ws.send(json);
  } catch {
    // ignore immediate failures; retry loop will handle.
  }
  const policy = {
    maxAttempts: opts?.maxAttempts,
    fixedDelayMs: opts?.fixedDelayMs,
    baseDelayMs: opts?.baseDelayMs,
    maxDelayMs: opts?.maxDelayMs,
  };
  const meta = opts?.meta ?? null;
  queueReliable(user.id, key, msgId, json, policy, meta);
}

function send(ws, obj, opts = null) {
  if (!ws || ws.readyState !== 1) return;

  // Default: reliable for everything once the client supports acks.
  const reliable = !(opts && opts.reliable === false);

  const userId = ws && ws._lrcomUserId ? String(ws._lrcomUserId) : null;
  const u = userId ? users.get(userId) : null;

  if (reliable && u) {
    sendReliableToUser(u, obj, opts);
    return;
  }

  sendBestEffort(ws, obj);
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
  // Coalesce per cMsgId so re-sends don't grow the reliable queue.
  send(ws, receipt, { coalesceKey: `receipt:${cMsgId}` });
}

function pickRoomOwner(room) {
  // Prefer existing owner if still present and connected.
  const ownerId = room.ownerId;
  if (ownerId && room.members.has(ownerId)) {
    const u = users.get(ownerId);
    if (u?.ws?.readyState === 1) return ownerId;
  }

  // Otherwise pick the first connected member.
  for (const memberId of room.members) {
    const u = users.get(memberId);
    if (u?.ws?.readyState === 1) return memberId;
  }
  return null;
}

function removeJoinRequestFromRoom(room, requesterId) {
  if (!room) return;

  if (room.joinActive === requesterId) {
    room.joinActive = null;
  }

  if (Array.isArray(room.joinQueue)) {
    room.joinQueue = room.joinQueue.filter((id) => id !== requesterId);
  }
}

function pumpJoinQueue(room) {
  if (!room) return;
  if (room.joinActive) return;
  if (!Array.isArray(room.joinQueue) || room.joinQueue.length === 0) return;

  // Drop stale requests.
  while (room.joinQueue.length) {
    const nextId = room.joinQueue[0];
    const requester = users.get(nextId);
    if (!requester || !requester.name) {
      room.joinQueue.shift();
      continue;
    }

    const ownerId = pickRoomOwner(room);
    if (!ownerId) {
      // Nobody online to approve. Reject all pending requests.
      for (const rid of room.joinQueue.splice(0)) {
        const u = users.get(rid);
        if (u) u.joinPendingRoomId = null;
        if (u?.ws?.readyState === 1) send(u.ws, { type: 'callJoinResult', ok: false, reason: 'no_approver' });
      }
      return;
    }

    room.ownerId = ownerId;
    room.joinActive = nextId;
    const owner = users.get(ownerId);
    if (owner?.ws?.readyState === 1) {
      send(owner.ws, { type: 'joinRequest', from: requester.id, fromName: requester.name, roomId: room.id });
    }
    return;
  }
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
    const u = signedUsers.get(ownerId);
    if (u?.ws?.readyState === 1) return ownerId;
  }
  for (const memberId of room.members) {
    const u = signedUsers.get(memberId);
    if (u?.ws?.readyState === 1) return memberId;
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
        if (u) u.joinPendingRoomId = null;
        if (u?.ws?.readyState === 1) sendBestEffort(u.ws, { type: 'callJoinResult', ok: false, reason: 'no_approver' });
      }
      return;
    }

    room.ownerId = ownerId;
    room.joinActive = nextId;
    const owner = signedUsers.get(ownerId);
    if (owner?.ws?.readyState === 1) {
      sendBestEffort(owner.ws, { type: 'joinRequest', from: requester.id, fromName: requester.name, roomId: room.id });
    }
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
    const m = signedUsers.get(memberId);
    if (!m?.ws || m.ws.readyState !== 1) continue;
    sendBestEffort(m.ws, { type: 'roomPeerLeft', roomId: rid, peerId: user.id });
  }

  if (room.members.size <= 1) {
    const lastId = Array.from(room.members)[0];
    if (lastId) {
      const last = signedUsers.get(lastId);
      if (last) {
        last.roomId = null;
        if (last.ws?.readyState === 1) sendBestEffort(last.ws, { type: 'callEnded', reason: 'alone' });
      }
    }

    // Reject any pending joiners.
    if (Array.isArray(room.joinQueue)) {
      for (const jid of room.joinQueue) {
        const u = signedUsers.get(jid);
        if (u) u.joinPendingRoomId = null;
        if (u?.ws?.readyState === 1) sendBestEffort(u.ws, { type: 'callJoinResult', ok: false, reason: 'ended' });
      }
    }
    if (room.joinActive) {
      const u = signedUsers.get(room.joinActive);
      if (u) u.joinPendingRoomId = null;
      if (u?.ws?.readyState === 1) sendBestEffort(u.ws, { type: 'callJoinResult', ok: false, reason: 'ended' });
    }

    signedRooms.delete(rid);
    return;
  }

  signedPumpJoinQueue(room);
}

/**
 * Web Push subscriptions (ephemeral server-side; memory only): userId -> subscription
 * NOTE: browsers persist subscriptions client-side until they expire or are revoked.
 */
const pushSubscriptions = new Map();

async function sendPushToUser(userId, payload) {
  if (!PUSH_ENABLED) return;
  const sub = pushSubscriptions.get(userId);
  if (!sub) return;
  try {
    await webpush.sendNotification(sub, JSON.stringify(payload));
  } catch (err) {
    const statusCode = err?.statusCode;
    if (statusCode === 404 || statusCode === 410) {
      pushSubscriptions.delete(userId);
    }
  }
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

function getActiveCallCount() {
  // Room with 2+ members counts as an active call.
  let calls = 0;
  for (const r of rooms.values()) {
    if ((r.members?.size ?? 0) >= 2) calls++;
  }
  return calls;
}

function getPeerLinksEstimate() {
  // Mesh conference: number of peer connections ~= sum over rooms of k choose 2.
  let links = 0;
  for (const r of rooms.values()) {
    const k = r.members?.size ?? 0;
    if (k >= 2) links += (k * (k - 1)) / 2;
  }
  return links;
}

function getVoiceStats() {
  const turnHost = getTurnHostLabel();

  const hasRelayRange = Number.isFinite(TURN_RELAY_MIN_PORT)
    && Number.isFinite(TURN_RELAY_MAX_PORT)
    && TURN_RELAY_MIN_PORT > 0
    && TURN_RELAY_MAX_PORT >= TURN_RELAY_MIN_PORT;

  const relayPortsTotal = hasRelayRange
    ? (TURN_RELAY_MAX_PORT - TURN_RELAY_MIN_PORT + 1)
    : null;

  const activeCalls = getActiveCallCount();

  // Estimation (worst-case): mesh conference
  // - each peer link is one RTCPeerConnection between two participants
  // - if both sides relay, that's ~2 relay allocations (ports)
  const peerLinks = getPeerLinksEstimate();
  const relayPortsUsedEstimateRaw = Math.floor(peerLinks * 2);
  const relayPortsUsedEstimate = relayPortsTotal == null
    ? relayPortsUsedEstimateRaw
    : Math.min(relayPortsUsedEstimateRaw, relayPortsTotal);

  // Keep this as a simple reference number: max 2-party calls if every participant needs relay.
  const capacityCallsEstimate = relayPortsTotal == null ? null : Math.floor(relayPortsTotal / 2);

  // Estimate max conference users (mesh) under worst-case relaying:
  // linkBudget = floor(relayPortsTotal / 2) because ~2 relay ports per peer-link
  // find max k such that k*(k-1)/2 <= linkBudget
  let maxConferenceUsersEstimate = null;
  if (typeof relayPortsTotal === 'number') {
    const linkBudget = Math.floor(relayPortsTotal / 2);
    const disc = 1 + 8 * linkBudget;
    maxConferenceUsersEstimate = Math.floor((1 + Math.sqrt(disc)) / 2);
  }

  return {
    turnHost,
    relayPortsTotal,
    relayPortsUsedEstimate,
    capacityCallsEstimate,
    maxConferenceUsersEstimate,
    activeCalls,
  };
}

function broadcastPresence() {
  const list = Array.from(users.values()).map((u) => ({ id: u.id, name: u.name, busy: Boolean(u.roomId) }));

  // Presence is state, not an event: refresh periodically best-effort.
  // (This avoids coalescing/ack edge-cases and self-heals quickly.)
  const msg = JSON.stringify({ type: 'presence', users: list, voice: getVoiceStats() });
  for (const u of users.values()) {
    if (u.ws.readyState === 1) u.ws.send(msg);
  }
}

function getRoom(roomId) {
  return roomId ? rooms.get(roomId) : null;
}

function ensureRoom(roomId) {
  if (!rooms.has(roomId)) rooms.set(roomId, { id: roomId, members: new Set(), ownerId: null, joinQueue: [], joinActive: null });
  return rooms.get(roomId);
}

function leaveRoom(user) {
  const rid = user.roomId;
  if (!rid) return;
  const room = rooms.get(rid);
  user.roomId = null;
  if (!room) return;
  room.members.delete(user.id);

  // If this user was involved in join requests, remove them.
  removeJoinRequestFromRoom(room, user.id);
  if (room.ownerId === user.id) room.ownerId = pickRoomOwner(room);

  for (const memberId of room.members) {
    const m = users.get(memberId);
    if (!m) continue;
    send(m.ws, { type: 'roomPeerLeft', roomId: rid, peerId: user.id });
  }
  if (room.members.size <= 1) {
    // If one user remains, end the room for them.
    const lastId = Array.from(room.members)[0];
    if (lastId) {
      const last = users.get(lastId);
      if (last) {
        last.roomId = null;
        send(last.ws, { type: 'callEnded', reason: 'alone' });
      }
    }

    // Reject any pending joiners.
    if (Array.isArray(room.joinQueue)) {
      for (const jid of room.joinQueue) {
        const u = users.get(jid);
        if (u) u.joinPendingRoomId = null;
        if (u?.ws?.readyState === 1) send(u.ws, { type: 'callJoinResult', ok: false, reason: 'ended' });
      }
    }
    if (room.joinActive) {
      const u = users.get(room.joinActive);
      if (u) u.joinPendingRoomId = null;
      if (u?.ws?.readyState === 1) send(u.ws, { type: 'callJoinResult', ok: false, reason: 'ended' });
    }

    rooms.delete(rid);
    return;
  }

  pumpJoinQueue(room);
}

function broadcastChat(fromUser, text) {
  const atIso = new Date().toISOString();
  const id = makeMsgId();
  const base = {
    type: 'chat',
    id,
    atIso,
    from: fromUser.id,
    fromName: fromUser.name,
    text,
    private: false,
    msgId: id,
  };

  for (const u of users.values()) {
    if (!u.name) continue;
    send(u.ws, base, { maxAttempts: 5, fixedDelayMs: 1000 });

    if (u.id !== fromUser.id) {
      void sendPushToUser(u.id, {
        title: `${APP_NAME} message`,
        body: `${fromUser.name}: ${text}`,
        tag: 'lrcom-chat',
        url: '/',
      });
    }
  }
}

function broadcastSystem(text) {
  const atIso = new Date().toISOString();
  const id = makeMsgId();
  const base = {
    type: 'chat',
    id,
    atIso,
    from: null,
    fromName: 'System',
    text,
    private: false,
    msgId: id,
  };

  for (const u of users.values()) {
    if (!u.name) continue;
    send(u.ws, base, { maxAttempts: 5, fixedDelayMs: 1000 });
  }
}

function sendPrivateChat(fromUser, toUser, text) {
  const atIso = new Date().toISOString();
  const id = makeMsgId();
  const base = {
    type: 'chat',
    id,
    atIso,
    from: fromUser.id,
    fromName: fromUser.name,
    to: toUser.id,
    toName: toUser.name,
    text,
    private: true,
    msgId: id,
  };

  // Sender always gets their local echo reliably.
  send(fromUser.ws, base, { maxAttempts: 5, fixedDelayMs: 1000 });

  // Recipient delivery: retry 1s x 5, then notify sender via System message.
  send(toUser.ws, base, {
    maxAttempts: 5,
    fixedDelayMs: 1000,
    meta: { kind: 'pmDelivery', fromUserId: fromUser.id, toName: toUser.name },
  });

  void sendPushToUser(toUser.id, {
    title: `${APP_NAME} private message`,
    body: `${fromUser.name}: ${text}`,
    tag: 'lrcom-pm',
    url: '/',
  });
}

function parsePrivatePrefix(text) {
  // Supports:
  //   @Alice hello
  //   @"Alice Doe" hello
  if (typeof text !== 'string' || !text.startsWith('@')) return null;

  if (text.startsWith('@"')) {
    const closing = text.indexOf('"', 2);
    if (closing === -1) return null;
    const toName = text.slice(2, closing);
    const rest = text.slice(closing + 1);
    if (!rest.startsWith(' ')) return null;
    const body = rest.trim();
    if (!toName || !body) return null;
    return { toName, body };
  }

  const firstSpace = text.indexOf(' ');
  if (firstSpace === -1) return null;
  const toName = text.slice(1, firstSpace);
  const body = text.slice(firstSpace + 1).trim();
  if (!toName || !body) return null;
  return { toName, body };
}

// NOTE: send() is defined above (reliable-aware).

function closeUser(userId) {
  const u = users.get(userId);
  if (!u) return;

  const name = u.name;

  // If in room, leave room and notify others
  if (u.roomId) {
    leaveRoom(u);
  }

  users.delete(userId);
  // If this user had pending reliable messages (as a recipient), notify senders
  // for private-message deliveries that were still awaiting ack.
  try {
    const perUser = pendingReliable.get(userId);
    if (perUser) {
      for (const entry of perUser.values()) {
        if (entry?.meta) handleReliableDeliveryFailure(entry.meta);
      }
    }
  } catch {
    // ignore
  }
  pendingReliable.delete(userId);
  pushSubscriptions.delete(userId);
  if (name && nameToId.get(name) === userId) nameToId.delete(name);

  if (name) broadcastSystem(`${name} left.`);
  broadcastPresence();
}

function rateLimit(user, nowMs) {
  // Kept for compatibility; replaced by rateLimitBucket().
  if (!user._rl) user._rl = { windowStart: nowMs, count: 0 };
  const win = user._rl;
  if (nowMs - win.windowStart > 2000) {
    win.windowStart = nowMs;
    win.count = 0;
  }
  win.count++;
  return win.count <= 20;
}

function rateLimitBucket(user, bucket, nowMs, limit, windowMs) {
  const key = bucket === 'signal' ? '_rlSignal' : '_rlCtrl';
  if (!user[key]) user[key] = { windowStart: nowMs, count: 0 };
  const win = user[key];
  if (nowMs - win.windowStart > windowMs) {
    win.windowStart = nowMs;
    win.count = 0;
  }
  win.count++;
  return win.count <= limit;
}

wss.on('connection', async (ws, req) => {
  // Signed-mode WS: separate world; requires token in querystring.
  try {
    const rawUrl = typeof req?.url === 'string' ? req.url : '/';
    if (rawUrl.startsWith('/signed')) {
      const u = new URL(rawUrl, 'http://localhost');
      const token = u.searchParams.get('token');
      const signedUserId = getUserIdForToken(token);
      if (!signedUserId) {
        try { ws.close(); } catch { /* ignore */ }
        return;
      }

      let signedName = '';
      try {
        const r = await query('SELECT username FROM users WHERE id = $1', [String(signedUserId)]);
        signedName = String(r?.rows?.[0]?.username ?? '') || '';
      } catch {
        signedName = '';
      }

      const signedUser = {
        id: String(signedUserId),
        name: signedName,
        ws,
        roomId: null,
        joinPendingRoomId: null,
        _clientReceipts: null,
        _clientReceiptQueue: null,
      };

      ws._lrcomSignedUserId = String(signedUserId);
      signedSockets.set(String(signedUserId), ws);
      signedUsers.set(String(signedUserId), signedUser);
      sendBestEffort(ws, { type: 'signedHello', userId: String(signedUserId) });

      ws.on('message', async (data) => {
        let msg;
        try {
          msg = JSON.parse(String(data));
        } catch {
          return;
        }
        if (!msg || typeof msg.type !== 'string') return;

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
          if (!callee || !callee.ws || callee.ws.readyState !== 1) {
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'offline' });
            if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
            return;
          }

          // Authorization: only allow calling users who share a signed chat.
          try {
            const ok = await query(
              `SELECT 1
               FROM chat_members cm1
               INNER JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
               WHERE cm1.user_id::text = $1 AND cm2.user_id::text = $2
               LIMIT 1`,
              [signedUser.id, String(to)],
            );
            if (!ok?.rows?.length) {
              sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'not_allowed' });
              if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
              return;
            }
          } catch (err) {
            debugError('[signed callStart] auth query failed', {
              from: signedUser?.id,
              to,
              err,
            });
            sendBestEffort(ws, { type: 'callStartResult', ok: false, reason: 'server' });
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
          callee.roomId = rid;

          sendBestEffort(ws, { type: 'callStartResult', ok: true, roomId: rid });
          sendBestEffort(callee.ws, { type: 'incomingCall', from: signedUser.id, fromName: signedUser.name, roomId: rid });
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callAccept') {
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

          const peer = { id: signedUser.id, name: signedUser.name };
          for (const memberId of room.members) {
            if (memberId === signedUser.id) continue;
            const m = signedUsers.get(memberId);
            if (!m) continue;
            sendBestEffort(m.ws, { type: 'roomPeerJoined', roomId: rid, peer });
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
          const from = typeof msg.from === 'string' ? msg.from : null;
          const rid = typeof msg.roomId === 'string' ? msg.roomId : signedUser.roomId;
          const caller = from ? signedUsers.get(from) : null;
          if (caller) sendBestEffort(caller.ws, { type: 'callRejected', reason: 'rejected' });
          if (rid && signedUser.roomId === rid) {
            signedLeaveRoom(signedUser);
          } else {
            signedUser.roomId = null;
          }
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callHangup') {
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
          if (!Array.isArray(room.joinQueue)) room.joinQueue = [];
          room.joinQueue.push(signedUser.id);
          sendBestEffort(ws, { type: 'callJoinPending', roomId: room.id, toName: target.name });
          signedPumpJoinQueue(room);
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinCancel') {
          const rid = signedUser.joinPendingRoomId;
          if (rid) {
            const room = getSignedRoom(rid);
            if (room) signedRemoveJoinRequestFromRoom(room, signedUser.id);
          }
          signedUser.joinPendingRoomId = null;
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinReject') {
          const from = typeof msg.from === 'string' ? msg.from : null;
          const rid = typeof msg.roomId === 'string' ? msg.roomId : null;
          const requester = from ? signedUsers.get(from) : null;
          const room = rid ? getSignedRoom(rid) : null;
          if (requester) requester.joinPendingRoomId = null;
          if (room) signedRemoveJoinRequestFromRoom(room, from);
          if (requester?.ws?.readyState === 1) sendBestEffort(requester.ws, { type: 'callJoinResult', ok: false, reason: 'rejected' });
          signedPumpJoinQueue(room);
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (msg.type === 'callJoinAccept') {
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

          const peer = { id: requester.id, name: requester.name };
          for (const memberId of room.members) {
            if (memberId === requester.id) continue;
            const m = signedUsers.get(memberId);
            if (!m) continue;
            sendBestEffort(m.ws, { type: 'roomPeerJoined', roomId: rid, peer });
          }

          const peers = Array.from(room.members)
            .filter((id) => id !== requester.id)
            .map((id) => {
              const u2 = signedUsers.get(id);
              return u2 ? { id: u2.id, name: u2.name } : null;
            })
            .filter(Boolean);

          sendBestEffort(requester.ws, { type: 'roomPeers', roomId: rid, peers });
          if (requester.ws?.readyState === 1) sendBestEffort(requester.ws, { type: 'callJoinResult', ok: true });

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
          sendBestEffort(peer.ws, { type: 'signal', from: signedUser.id, fromName: signedUser.name, payload });
          if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, true);
          return;
        }

        if (cMsgId) sendClientReceipt(signedUser, ws, cMsgId, false, 'UNKNOWN_TYPE');
      });

      ws.on('close', () => {
        signedSockets.delete(String(signedUserId));
        const u = signedUsers.get(String(signedUserId));
        if (u) {
          if (u.roomId) signedLeaveRoom(u);
        }
        signedUsers.delete(String(signedUserId));
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

  const userId = makeId();
  const user = {
    id: userId,
    name: null,
    ws,
    lastMsgAt: Date.now(),
    roomId: null,
    joinPendingRoomId: null,
    supportsAck: false,
    _helloPayload: null,
    _rl: null,
  };
  users.set(userId, user);

  // Attach for send(ws, ...) to find the corresponding user.
  ws._lrcomUserId = userId;

  const clientIp = req?.socket?.remoteAddress ?? null;
  const turnConfig = makeTurnConfig();

  // Common failure: TURN URLs set to localhost, which only works on the server machine.
  const badTurn = TURN_URLS.some((u) => /\b(localhost|127\.0\.0\.1|::1)\b/i.test(u));
  const isRemoteClient = clientIp && !/^::1$|^127\.|^::ffff:127\./.test(clientIp);
  const turnWarning = badTurn && isRemoteClient
    ? 'TURN is configured for localhost; set LRCOM_TURN_HOST to your public domain/IP for Internet calls.'
    : null;

  user._helloPayload = { type: 'hello', id: userId, turn: turnConfig, https: true, clientIp, turnWarning, voice: getVoiceStats() };
  send(ws, user._helloPayload);

  ws.on('message', (data) => {
    const now = Date.now();
    // Keep a last-seen timestamp to support presence health.
    user.lastMsgAt = now;

    let msg;
    try {
      msg = JSON.parse(String(data));
    } catch {
      send(ws, { type: 'error', code: 'BAD_JSON' });
      return;
    }

    if (!msg || typeof msg.type !== 'string') {
      send(ws, { type: 'error', code: 'BAD_MESSAGE' });
      return;
    }

    const cMsgId = typeof msg.cMsgId === 'string' && msg.cMsgId ? msg.cMsgId : null;
    if (cMsgId) {
      const prev = getClientReceipt(user, cMsgId);
      if (prev) {
        send(ws, prev, { coalesceKey: `receipt:${cMsgId}` });
        return;
      }
    }

    const type = msg.type;
    const isSignal = type === 'signal';
    const isCritical = type === 'callHangup' || type === 'ack' || type === 'ping' || type === 'clientHello';

    // Separate limits: signaling can be bursty; control traffic should stay responsive.
    const okRate = isSignal
      ? rateLimitBucket(user, 'signal', now, 250, 2000)
      : rateLimitBucket(user, 'ctrl', now, 40, 2000);

    if (!okRate && !isCritical) {
      send(ws, { type: 'error', code: 'RATE_LIMIT' });
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'RATE_LIMIT');
      return;
    }

    // Push subscription can arrive before a name is set.
    if (msg.type === 'pushSubscribe') {
      if (!PUSH_ENABLED) return;
      if (msg.subscription && typeof msg.subscription === 'object') {
        pushSubscriptions.set(userId, msg.subscription);
      }
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'pushUnsubscribe') {
      pushSubscriptions.delete(userId);
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'clientHello') {
      // Feature negotiation; safe to accept before name is set.
      const f = msg.features && typeof msg.features === 'object' ? msg.features : null;
      const ack = f && f.ack === true;
      user.supportsAck = Boolean(ack);

      // If ack support is enabled, re-send the hello payload as reliable so the
      // client can recover it even if it missed the initial one-shot send.
      if (user.supportsAck && user._helloPayload) {
        send(ws, user._helloPayload, { coalesceKey: 'hello' });
      }
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'ack') {
      // Ack for reliable messages; safe before name is set.
      const msgId = typeof msg.msgId === 'string' ? msg.msgId : null;
      if (msgId) ackReliable(userId, msgId);
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'ping') {
      // App-level ping to keep online status fresh.
      // (We still rely on ws 'close' for definitive disconnect.)
      send(ws, { type: 'pong', at: now });
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'setName') {
      const name = safeName(msg.name);
      if (!name) {
        send(ws, { type: 'nameResult', ok: false, reason: 'invalid' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'INVALID_NAME');
        return;
      }
      const existing = nameToId.get(name);
      if (existing && existing !== userId) {
        send(ws, { type: 'nameResult', ok: false, reason: 'taken' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NAME_TAKEN');
        return;
      }

      // Release old name
      if (user.name && nameToId.get(user.name) === userId) nameToId.delete(user.name);

      user.name = name;
      nameToId.set(name, userId);
      send(ws, { type: 'nameResult', ok: true, name });
      broadcastSystem(`${name} joined.`);
      broadcastPresence();
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    // Require name for any other operations
    if (!user.name) {
      send(ws, { type: 'error', code: 'NO_NAME' });
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NO_NAME');
      return;
    }

    if (msg.type === 'callStart') {
      const to = typeof msg.to === 'string' ? msg.to : null;
      if (!to || !users.has(to)) {
        send(ws, { type: 'callStartResult', ok: false, reason: 'not_found' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_FOUND');
        return;
      }
      if (to === userId) {
        send(ws, { type: 'callStartResult', ok: false, reason: 'self' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'SELF');
        return;
      }

      const callee = users.get(to);
      if (!callee.name) {
        send(ws, { type: 'callStartResult', ok: false, reason: 'not_ready' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_READY');
        return;
      }
      if (callee.roomId) {
        send(ws, { type: 'callStartResult', ok: false, reason: 'busy' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'BUSY');
        return;
      }

      // New room or invite into existing room
      const rid = user.roomId ?? makeId();
      const room = ensureRoom(rid);
      room.members.add(user.id);
      room.members.add(callee.id);

      if (!room.ownerId) room.ownerId = user.id;

      user.roomId = rid;
      callee.roomId = rid;

      sendReliableToUser(callee, { type: 'incomingCall', from: user.id, fromName: user.name, roomId: rid });

      void sendPushToUser(callee.id, {
        title: 'Incoming call',
        body: `From ${user.name}`,
        tag: 'lrcom-call',
        url: '/',
        requireInteraction: true,
      });
      send(ws, { type: 'callStartResult', ok: true });
      broadcastPresence();
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'callJoinRequest') {
      const to = typeof msg.to === 'string' ? msg.to : null;
      if (!to || !users.has(to)) {
        send(ws, { type: 'callJoinResult', ok: false, reason: 'not_found' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_FOUND');
        return;
      }
      if (to === userId) {
        send(ws, { type: 'callJoinResult', ok: false, reason: 'self' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'SELF');
        return;
      }
      if (user.roomId) {
        send(ws, { type: 'callJoinResult', ok: false, reason: 'already_in_call' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'ALREADY_IN_CALL');
        return;
      }
      if (user.joinPendingRoomId) {
        send(ws, { type: 'callJoinResult', ok: false, reason: 'already_pending' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'ALREADY_PENDING');
        return;
      }

      const callee = users.get(to);
      if (!callee?.name) {
        send(ws, { type: 'callJoinResult', ok: false, reason: 'not_ready' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_READY');
        return;
      }
      const rid = callee.roomId;
      const room = getRoom(rid);
      if (!rid || !room) {
        send(ws, { type: 'callJoinResult', ok: false, reason: 'not_in_call' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_IN_CALL');
        return;
      }

      // Enqueue join request for this room.
      if (!Array.isArray(room.joinQueue)) room.joinQueue = [];
      if (!room.joinQueue.includes(user.id) && room.joinActive !== user.id) {
        room.joinQueue.push(user.id);
      }
      user.joinPendingRoomId = rid;

      send(ws, { type: 'callJoinPending', roomId: rid, toName: callee.name });
      pumpJoinQueue(room);
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'callJoinCancel') {
      const rid = user.joinPendingRoomId;
      if (!rid) return;
      const room = getRoom(rid);
      if (room) {
        removeJoinRequestFromRoom(room, user.id);
        pumpJoinQueue(room);
      }
      user.joinPendingRoomId = null;
      send(ws, { type: 'callJoinResult', ok: false, reason: 'canceled' });
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'callJoinAccept' || msg.type === 'callJoinReject') {
      const from = typeof msg.from === 'string' ? msg.from : null;
      const rid = typeof msg.roomId === 'string' ? msg.roomId : null;
      if (!from || !rid) return;
      const room = getRoom(rid);
      if (!room) return;

      // Only the current room owner can approve.
      const ownerId = pickRoomOwner(room);
      room.ownerId = ownerId;
      if (!ownerId || ownerId !== userId) return;
      if (!room.members.has(userId)) return;
      if (room.joinActive !== from) return;

      const requester = users.get(from);
      if (!requester || !requester.name) {
        room.joinActive = null;
        pumpJoinQueue(room);
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_FOUND');
        return;
      }

      if (msg.type === 'callJoinReject') {
        requester.joinPendingRoomId = null;
        if (requester.ws.readyState === 1) send(requester.ws, { type: 'callJoinResult', ok: false, reason: 'rejected' });
        room.joinActive = null;
        pumpJoinQueue(room);
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
        return;
      }

      // Accept: add requester to the room.
      room.members.add(requester.id);
      requester.roomId = rid;
      requester.joinPendingRoomId = null;

      const peer = { id: requester.id, name: requester.name };
      for (const memberId of room.members) {
        if (memberId === requester.id) continue;
        const m = users.get(memberId);
        if (!m) continue;
        sendReliableToUser(m, { type: 'roomPeerJoined', roomId: rid, peer });
      }

      const peers = Array.from(room.members)
        .filter((id) => id !== requester.id)
        .map((id) => {
          const u2 = users.get(id);
          return u2 ? { id: u2.id, name: u2.name } : null;
        })
        .filter(Boolean);

      sendReliableToUser(requester, { type: 'roomPeers', roomId: rid, peers });
      broadcastPresence();

      room.joinActive = null;
      pumpJoinQueue(room);
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'callReject') {
      const from = typeof msg.from === 'string' ? msg.from : null;
      const rid = typeof msg.roomId === 'string' ? msg.roomId : user.roomId;
      const caller = from ? users.get(from) : null;
      if (caller) send(caller.ws, { type: 'callRejected', reason: 'rejected' });

      // Remove rejecter from the room; if room collapses, last member gets callEnded.
      if (rid && user.roomId === rid) {
        leaveRoom(user);
      } else {
        user.roomId = null;
      }
      broadcastPresence();
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'callAccept') {
      const from = typeof msg.from === 'string' ? msg.from : null;
      const caller = from ? users.get(from) : null;
      const rid = typeof msg.roomId === 'string' ? msg.roomId : user.roomId;
      if (!caller) {
        user.roomId = null;
        broadcastPresence();
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'NOT_FOUND');
        return;
      }

      if (!rid || caller.roomId !== rid || user.roomId !== rid) {
        user.roomId = null;
        broadcastPresence();
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'ROOM_MISMATCH');
        return;
      }

      const room = getRoom(rid);
      if (!room) {
        user.roomId = null;
        broadcastPresence();
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'ROOM_MISSING');
        return;
      }

      // Notify existing members to connect to the new joiner
      const peer = { id: user.id, name: user.name };
      for (const memberId of room.members) {
        if (memberId === user.id) continue;
        const m = users.get(memberId);
        if (!m) continue;
        sendReliableToUser(m, { type: 'roomPeerJoined', roomId: rid, peer });
      }

      // Send the joiner a list of existing members to prepare for offers
      const peers = Array.from(room.members)
        .filter((id) => id !== user.id)
        .map((id) => {
          const u2 = users.get(id);
          return u2 ? { id: u2.id, name: u2.name } : null;
        })
        .filter(Boolean);

      sendReliableToUser(user, { type: 'roomPeers', roomId: rid, peers });

      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'signal') {
      const to = typeof msg.to === 'string' ? msg.to : null;
      const payload = msg.payload;
      if (!to || !users.has(to)) return;

      // Only allow signaling between users in the same room
      const peer = users.get(to);
      if (!peer) return;
      if (!user.roomId || user.roomId !== peer.roomId) return;

      // WebRTC signaling is intentionally NOT made reliable to avoid duplicate
      // offers/candidates causing side effects.
      send(peer.ws, { type: 'signal', from: user.id, fromName: user.name, payload }, { reliable: false });
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'callHangup') {
      leaveRoom(user);
      broadcastPresence();
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    if (msg.type === 'chatSend') {
      const raw = safeChatText(msg.text);
      if (!raw) {
        send(ws, { type: 'error', code: 'BAD_CHAT' });
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'BAD_CHAT');
        return;
      }

      const toName = typeof msg.toName === 'string' ? safeName(msg.toName) : null;
      if (toName) {
        const toId = nameToId.get(toName);
        const toUser = toId ? users.get(toId) : null;
        if (!toUser || !toUser.name) {
          send(ws, { type: 'error', code: 'PM_NOT_FOUND' });
          if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'PM_NOT_FOUND');
          try {
            handleReliableDeliveryFailure({ kind: 'pmDelivery', fromUserId: user.id, toName });
          } catch {
            // ignore
          }
          return;
        }
        if (toUser.id === user.id) {
          send(ws, { type: 'error', code: 'PM_SELF' });
          if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'PM_SELF');
          return;
        }
        sendPrivateChat(user, toUser, raw);
        if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
        return;
      }

      broadcastChat(user, raw);
      if (cMsgId) sendClientReceipt(user, ws, cMsgId, true);
      return;
    }

    send(ws, { type: 'error', code: 'UNKNOWN_TYPE' });
    if (cMsgId) sendClientReceipt(user, ws, cMsgId, false, 'UNKNOWN_TYPE');
  });

  ws.on('close', () => {
    closeUser(userId);
  });

  ws.on('error', () => {
    closeUser(userId);
  });
});

// Periodic presence refresh (RAM-only, low overhead).
setInterval(() => {
  try {
    broadcastPresence();
  } catch {
    // ignore
  }
}, PRESENCE_TICK_MS);

// Terminate stale sockets (e.g. mobile network drop without close event).
setInterval(() => {
  const now = Date.now();
  for (const u of users.values()) {
    try {
      if (!u?.ws || u.ws.readyState !== 1) continue;
      const last = typeof u.lastMsgAt === 'number' ? u.lastMsgAt : now;
      if (now - last > STALE_WS_MS) {
        if (typeof u.ws.terminate === 'function') u.ws.terminate();
        else u.ws.close();
      }
    } catch {
      // ignore
    }
  }
}, Math.min(10000, Math.max(1000, Math.floor(STALE_WS_MS / 3))));

// Frequent pump for reliable retries.
setInterval(() => {
  try {
    for (const u of users.values()) {
      flushReliableForUser(u);
    }
  } catch {
    // ignore
  }
}, RELIABLE_PUMP_MS);

// Initialize database connection
try {
  initDatabase();
} catch (error) {
  void error;
  process.exit(1);
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
