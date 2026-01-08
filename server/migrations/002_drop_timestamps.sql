BEGIN;

-- Drop any old updated_at triggers/function
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_messages_updated_at ON messages;
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Remove timestamp columns to minimize plaintext metadata footprint
ALTER TABLE users
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS updated_at;

ALTER TABLE chats
  DROP COLUMN IF EXISTS created_at;

ALTER TABLE chat_members
  DROP COLUMN IF EXISTS joined_at;

ALTER TABLE messages
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS updated_at;

ALTER TABLE unread_messages
  DROP COLUMN IF EXISTS created_at;

-- Fix index that previously used created_at
DROP INDEX IF EXISTS idx_messages_chat;
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id);

COMMIT;
