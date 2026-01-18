import crypto from 'crypto';
import webpush from 'web-push';
import { query } from './db.js';

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function randomSecondsBetween(minSeconds, maxSeconds) {
  const lo = Math.min(minSeconds, maxSeconds);
  const hi = Math.max(minSeconds, maxSeconds);
  const span = hi - lo + 1;
  // crypto.randomInt is inclusive of min and exclusive of max.
  return lo + crypto.randomInt(span);
}

function daysToSeconds(days) {
  return Math.floor(days * 86400);
}

export async function upsertPushSubscriptionForUser({ userId, subscriptionJson }) {
  const sub = subscriptionJson;
  const endpoint = typeof sub?.endpoint === 'string' ? sub.endpoint : '';
  const p256dh = typeof sub?.keys?.p256dh === 'string' ? sub.keys.p256dh : '';
  const auth = typeof sub?.keys?.auth === 'string' ? sub.keys.auth : '';
  if (!endpoint || !p256dh || !auth) return { ok: false, error: 'Invalid subscription' };

  const userRes = await query('SELECT remove_date FROM users WHERE id = $1 LIMIT 1', [String(userId)]);
  if (!userRes?.rows?.length) return { ok: false, error: 'Not found' };

  const userRemoveDate = new Date(userRes.rows[0].remove_date);

  // Random deletion: 21–90 days after last refresh.
  const sec = randomSecondsBetween(daysToSeconds(21), daysToSeconds(90));
  const candidateMs = Date.now() + sec * 1000;

  // Must always be < user.remove_date.
  const capMs = userRemoveDate.getTime() - 60_000; // 1 minute safety.
  const removalMs = Math.min(candidateMs, capMs);
  const removeDate = new Date(removalMs);

  await query(
    `INSERT INTO push_subscriptions (endpoint, user_id, p256dh, auth, remove_date)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (endpoint) DO UPDATE SET
       user_id = EXCLUDED.user_id,
       p256dh = EXCLUDED.p256dh,
       auth = EXCLUDED.auth,
       remove_date = EXCLUDED.remove_date`,
    [endpoint, String(userId), p256dh, auth, removeDate.toISOString()],
  );

  return { ok: true };
}

export async function deletePushStateForUser(userId) {
  // Wipe both subscriptions and queue (privacy requirement).
  await query('DELETE FROM push_send_queue WHERE user_id = $1', [String(userId)]);
  await query('DELETE FROM push_subscriptions WHERE user_id = $1', [String(userId)]);
}

export async function cleanupExpiredPushState(now = new Date()) {
  const ts = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  // Remove expired subs and queue entries.
  await query('DELETE FROM push_send_queue WHERE remove_date <= $1', [ts]);
  await query('DELETE FROM push_subscriptions WHERE remove_date <= $1', [ts]);

  // Drop queue entries that are no longer unread (delivered/read/deleted).
  await query(
    `DELETE FROM push_send_queue q
     WHERE NOT EXISTS (
       SELECT 1 FROM unread_messages u
       WHERE u.user_id = q.user_id AND u.message_id = q.message_id
     )`,
    [],
  );
}

export async function enqueuePushForUnreadMessage({ userId, messageId }) {
  // If the user has no stored push subscriptions, do not create queue state.
  // (Push is off-by-default and should be zero-footprint until enabled.)
  const has = await query('SELECT 1 FROM push_subscriptions WHERE user_id = $1 LIMIT 1', [String(userId)]);
  if (!has?.rows?.length) return;

  // Random retention: 7–30 days (seconds).
  const sec = randomSecondsBetween(daysToSeconds(7), daysToSeconds(30));
  const removeDate = new Date(Date.now() + sec * 1000);

  await query(
    `INSERT INTO push_send_queue (user_id, message_id, attempts, sent, remove_date)
     VALUES ($1, $2, 0, FALSE, $3)
     ON CONFLICT (user_id, message_id) DO NOTHING`,
    [String(userId), String(messageId), removeDate.toISOString()],
  );
}

export async function listPushSubscriptionsForUser(userId) {
  const r = await query(
    'SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = $1',
    [String(userId)],
  );
  return (r?.rows ?? []).map((row) => ({
    endpoint: String(row.endpoint),
    keys: { p256dh: String(row.p256dh), auth: String(row.auth) },
  }));
}

export async function markPushAttempt({ userId, messageId, setSent }) {
  const uid = String(userId);
  const mid = String(messageId);
  if (setSent === true) {
    await query(
      'UPDATE push_send_queue SET attempts = attempts + 1, sent = TRUE WHERE user_id = $1 AND message_id = $2',
      [uid, mid],
    );
    return;
  }
  await query(
    'UPDATE push_send_queue SET attempts = attempts + 1 WHERE user_id = $1 AND message_id = $2',
    [uid, mid],
  );
}

export async function pickPushQueueBatch({ limit = 50 }) {
  const lim = clamp(Number(limit) || 50, 1, 200);
  // Only consider rows that are still unread.
  const r = await query(
    `SELECT q.user_id::text AS user_id, q.message_id::text AS message_id, q.attempts::int AS attempts,
            m.chat_id::text AS chat_id
     FROM push_send_queue q
     INNER JOIN unread_messages u ON u.user_id = q.user_id AND u.message_id = q.message_id
     INNER JOIN messages m ON m.id = q.message_id
     WHERE q.remove_date > NOW() AND q.sent = FALSE
     ORDER BY q.remove_date ASC
     LIMIT $1`,
    [lim],
  );
  return r?.rows ?? [];
}

export async function sendWebPushToSubscriptions({ subscriptions, payload, ttlSeconds }) {
  const staleEndpoints = [];
  let okCount = 0;
  const body = JSON.stringify(payload ?? {});

  for (const sub of subscriptions) {
    try {
      await webpush.sendNotification(sub, body, { TTL: Number(ttlSeconds) || 3600 });
      okCount += 1;
    } catch (e) {
      const code = e?.statusCode;
      if (code === 404 || code === 410) {
        try {
          const ep = typeof sub?.endpoint === 'string' ? sub.endpoint : '';
          if (ep) staleEndpoints.push(ep);
        } catch {
          // ignore
        }
        continue;
      }
      // Other errors are treated as transient; caller handles retry.
    }
  }

  return { staleEndpoints, okCount };
}

export async function deleteSubscriptionsByEndpoint(endpoints) {
  const list = Array.isArray(endpoints) ? endpoints.map(String).filter(Boolean) : [];
  if (!list.length) return;
  await query('DELETE FROM push_subscriptions WHERE endpoint = ANY($1::text[])', [list]);
}
