import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import path from 'path';
import express from 'express';
import webpush from 'web-push';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import { debugError } from './logger.js';
import { initDatabase, query, runMigrations } from './db.js';
import { registerUser, loginUser, getUserByUsername } from './auth.js';
import { issueToken, getUserIdForToken, requireSignedAuth, parseAuthTokenFromReq, revokeToken } from './signedSession.js';
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

if (PUSH_ENABLED) {
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  } catch {
    // No logs (privacy policy).
  }
}

// Push subscriptions are RAM-only: no DB traces. Server restart => re-subscribe.
// userId -> Map(endpoint -> subscriptionJson)
const pushSubsByUserId = new Map();

function storePushSubscription(userId, sub) {
  if (!userId) return false;
  const endpoint = typeof sub?.endpoint === 'string' ? sub.endpoint : '';
  const p256dh = typeof sub?.keys?.p256dh === 'string' ? sub.keys.p256dh : '';
  const auth = typeof sub?.keys?.auth === 'string' ? sub.keys.auth : '';
  if (!endpoint || !p256dh || !auth) return false;

  let m = pushSubsByUserId.get(String(userId));
  if (!m) {
    m = new Map();
    pushSubsByUserId.set(String(userId), m);
  }

  m.set(endpoint, { endpoint, keys: { p256dh, auth } });
  return true;
}

async function sendPushToUserId(userId, payload) {
  if (!PUSH_ENABLED) return;
  const m = pushSubsByUserId.get(String(userId));
  if (!m || !m.size) return;

  const body = JSON.stringify(payload ?? {});
  const stale = [];

  for (const [endpoint, sub] of m.entries()) {
    try {
      await webpush.sendNotification(sub, body, { TTL: 60 * 60 });
    } catch (e) {
      const code = e?.statusCode;
      if (code === 404 || code === 410) stale.push(endpoint);
    }
  }

  if (stale.length) {
    for (const ep of stale) m.delete(ep);
    if (!m.size) pushSubsByUserId.delete(String(userId));
  }
}

// Visual branding
const APP_NAME = (process.env.APP_NAME ?? 'Last').trim() || 'Last';


// Note: Push subscriptions are not persisted (RAM-only by design).

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

// Signed session refresh: rotate bearer token without re-login.
app.post('/api/signed/session/refresh', requireSignedAuth, (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const { token, expiresAt } = issueToken(userId);
    res.json({ success: true, token, expiresAt });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signed push subscription registration (RAM-only).
app.post('/api/signed/push/subscribe', requireSignedAuth, (req, res) => {
  if (!PUSH_ENABLED) return res.status(503).json({ error: 'Push disabled' });
  const userId = String(req._signedUserId);
  const sub = req.body?.subscription;
  const ok = storePushSubscription(userId, sub);
  if (!ok) return res.status(400).json({ error: 'Invalid subscription' });
  res.json({ success: true });
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

    const { token, expiresAt } = issueToken(String(user.id));

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

    const { token, expiresAt } = issueToken(String(result.userId));

    res.json({
      success: true,
      token,
      expiresAt,
      ...result,
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/signed/account/hidden-mode', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const hiddenMode = req.body?.hiddenMode;
    if (typeof hiddenMode !== 'boolean') return res.status(400).json({ error: 'hiddenMode boolean required' });

    await query('UPDATE users SET hidden_mode = $2 WHERE id = $1', [userId, hiddenMode]);

    res.json({ success: true, hiddenMode });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/signed/account/introvert-mode', requireSignedAuth, async (req, res) => {
  try {
    const userId = String(req._signedUserId);
    const introvertMode = req.body?.introvertMode;
    if (typeof introvertMode !== 'boolean') return res.status(400).json({ error: 'introvertMode boolean required' });

    await query('UPDATE users SET introvert_mode = $2 WHERE id = $1', [userId, introvertMode]);

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

    // Refresh account expiration on activity (presence poll).
    // Add random jitter (0..86400s) to reduce ability to infer exact activity time.
    try {
      const jitterSeconds = crypto.randomInt(0, 86401);
      await query(
        `UPDATE users
         SET remove_date = NOW() + (expiration_days * INTERVAL '1 day') + ($2::int * INTERVAL '1 second')
         WHERE id = $1`,
        [me, jitterSeconds],
      );
    } catch {
      // ignore
    }

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
           INNER JOIN chat_members me_cm ON me_cm.chat_id = c.id AND me_cm.user_id = $1
           INNER JOIN chat_members other ON other.chat_id = c.id AND other.user_id <> $1
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
      const payload = { type: 'signedChatsChanged', chatId, reason: 'group_renamed', name: String(result.chat?.name ?? '') };
      for (const uid of result.memberIds || []) {
        const ws = signedSockets.get(String(uid));
        if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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
      const ws = signedSockets.get(uid);
      if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
    }

    // Best-effort Web Push notify for offline recipients (RAM-only subs).
    // Do not include message plaintext.
    for (const uid of memberIds) {
      if (String(uid) === String(senderId)) continue;
      const ws = signedSockets.get(uid);
      if (ws && ws.readyState === 1) continue;
      void sendPushToUserId(uid, {
        title: 'Last',
        body: senderUsername ? `New message from ${senderUsername}` : 'New message',
        tag: `lrcom-chat-${String(chatId)}`,
        url: `/?chatId=${encodeURIComponent(String(chatId))}`,
        data: { chatId: String(chatId), messageId: String(messageId) },
      });
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
      const left = await signedLeaveChat(userId, chatId);
      if (left && left.ok) {
        // Remaining members should refresh chat list (membership/messages changed).
        try {
          const payload = { type: 'signedChatsChanged', chatId, reason: left.chatDeleted ? 'group_deleted' : 'member_left' };
          for (const uid of left.remainingMemberIds || []) {
            const ws = signedSockets.get(String(uid));
            if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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
                const ws = signedSockets.get(String(uid));
                if (ws && ws.readyState === 1) sendBestEffort(ws, payload);
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

    // Clear RAM-only state.
    try {
      pushSubsByUserId.delete(String(userId));
    } catch {
      // ignore
    }

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

// Signed-mode: in-memory sockets keyed by authenticated userId.
const signedSockets = new Map(); // userId -> ws

// Signed-mode: in-memory user state (presence + call state). Kept RAM-only.
const signedUsers = new Map(); // userId -> { id, name, ws, roomId, ... }

// Signed-only: keep small client message receipt cache (for idempotency).
const STALE_WS_MS = Number(process.env.STALE_WS_MS ?? 45000);
const CLIENT_MSGIDS_MAX = Number(process.env.CLIENT_MSGIDS_MAX ?? 2000);

// WS heartbeat (server ping/pong) to detect dead TCP connections without
// requiring the client to actively send WS messages.
const WS_HEARTBEAT_MS = Number(process.env.WS_HEARTBEAT_MS ?? 30000);

function sendBestEffort(ws, obj) {
  if (!ws || ws.readyState !== 1) return;
  try {
    ws.send(JSON.stringify(obj));
  } catch {
    // ignore
  }
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
      const signedUserId = getUserIdForToken(token);
      if (!signedUserId) {
        try { ws.close(); } catch { /* ignore */ }
        return;
      }

      const uid = String(signedUserId);

      // Mark alive; updated via 'pong'.
      ws.isAlive = true;
      ws.on('pong', () => {
        ws.isAlive = true;
      });

      let signedName = '';
      try {
        const r = await query('SELECT username FROM users WHERE id = $1', [String(signedUserId)]);
        signedName = String(r?.rows?.[0]?.username ?? '') || '';
      } catch {
        signedName = '';
      }

      const prev = signedUsers.get(uid);
      const prevWs = prev?.ws;

      // Reuse the existing per-user state on reconnect (preserves call state,
      // receipts, etc), but replace the socket reference.
      const signedUser = prev ?? {
        id: uid,
        name: signedName,
        ws,
        lastMsgAt: Date.now(),
        roomId: null,
        joinPendingRoomId: null,
        _clientReceipts: null,
        _clientReceiptQueue: null,
      };

      signedUser.name = signedName || signedUser.name;
      signedUser.ws = ws;
      signedUser.lastMsgAt = Date.now();

      ws._lrcomSignedUserId = uid;
      signedSockets.set(uid, ws);
      signedUsers.set(uid, signedUser);

      // Close any prior socket for this user to avoid stacking.
      if (prevWs && prevWs !== ws) {
        try { prevWs.close(); } catch { /* ignore */ }
      }

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
        // Guard against an older socket closing after a newer socket has
        // connected for the same user.
        const curSock = signedSockets.get(uid);
        if (curSock === ws) {
          signedSockets.delete(uid);
        }

        const curUser = signedUsers.get(uid);
        if (curUser && curUser.ws === ws) {
          if (curUser.roomId) signedLeaveRoom(curUser);
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
  for (const ws of signedSockets.values()) {
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

  if (SIGNED_CLEANUP_ENABLED) {
    const interval = Number.isFinite(SIGNED_CLEANUP_INTERVAL_MS)
      ? Math.max(60 * 1000, SIGNED_CLEANUP_INTERVAL_MS)
      : 24 * 60 * 60 * 1000;

    const initialDelay = Number.isFinite(SIGNED_CLEANUP_INITIAL_DELAY_MS)
      ? Math.max(0, SIGNED_CLEANUP_INITIAL_DELAY_MS)
      : 30 * 1000;

    const run = async () => {
      try {
        const r = await signedCleanupExpiredUsers();

        // Clear RAM-only state for deleted users.
        try {
          const ids = Array.isArray(r?.deletedUserIds) ? r.deletedUserIds : [];
          for (const id of ids) pushSubsByUserId.delete(String(id));
        } catch {
          // ignore
        }
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
