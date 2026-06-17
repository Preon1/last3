-- Binary envelope cutover (no backward compatibility).
-- Drop incompatible ciphertext payloads and enforce BYTEA storage.

BEGIN;

TRUNCATE TABLE unread_messages, messages, chat_members, chats, users CASCADE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'messages' AND column_name = 'encrypted_data'
  ) THEN
    EXECUTE 'ALTER TABLE messages DROP COLUMN encrypted_data';
  END IF;

  EXECUTE 'ALTER TABLE messages ADD COLUMN IF NOT EXISTS encrypted_data BYTEA NOT NULL';
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'chats' AND column_name = 'names'
  ) THEN
    EXECUTE 'ALTER TABLE chats DROP COLUMN names';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'chats' AND column_name = 'chat_name_enc'
  ) THEN
    EXECUTE 'ALTER TABLE chats DROP COLUMN chat_name_enc';
  END IF;

  EXECUTE 'ALTER TABLE chats ADD COLUMN IF NOT EXISTS chat_name_enc BYTEA NOT NULL DEFAULT ''''::bytea';
END $$;

DROP TABLE IF EXISTS chat_names_enc;

CREATE TABLE chat_names_enc (
  chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  subject_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  enc BYTEA NOT NULL,
  PRIMARY KEY (chat_id, subject_user_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_names_chat ON chat_names_enc(chat_id);
CREATE INDEX IF NOT EXISTS idx_chat_names_subject ON chat_names_enc(subject_user_id);

COMMIT;
