BEGIN;

-- Replace message_recipients join table with a per-member visibility border.
-- Messages are UUIDv7 and remain opaque ciphertext on the server.

ALTER TABLE chat_members
  ADD COLUMN IF NOT EXISTS visible_after_message_id UUID NULL;

-- No backward compatibility required.
DROP TABLE IF EXISTS message_recipients;

COMMIT;
