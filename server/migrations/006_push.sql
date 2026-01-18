BEGIN;

-- Persistent Web Push subscriptions.
-- Note: keep schema minimal (privacy). Deletion is enforced by FK cascades.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  endpoint TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  remove_date TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_remove_date ON push_subscriptions(remove_date);

-- Push send queue.
-- We do NOT store payload here; it can be derived from messages/chats at send-time.
-- remove_date is randomized to obscure exact send time.
CREATE TABLE IF NOT EXISTS push_send_queue (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  attempts INT NOT NULL DEFAULT 0,
  sent BOOLEAN NOT NULL DEFAULT FALSE,
  remove_date TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_push_send_queue_remove_date ON push_send_queue(remove_date);
CREATE INDEX IF NOT EXISTS idx_push_send_queue_user ON push_send_queue(user_id);

COMMIT;
