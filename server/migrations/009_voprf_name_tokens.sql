-- VOPRF upgrade: remove plaintext usernames and plaintext group chat names.
-- No backward compatibility: wipe existing signed-mode data.

TRUNCATE TABLE unread_messages, messages, chat_members, chats, users CASCADE;

-- Users: remove username and replace with opaque VOPRF-derived token.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'users' AND column_name = 'username'
  ) THEN
    -- Drop legacy username index if present.
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_users_username') THEN
      EXECUTE 'DROP INDEX idx_users_username';
    END IF;

    EXECUTE 'ALTER TABLE users DROP COLUMN username';
  END IF;
END $$;

-- Add name_token (VOPRF output, base64url string).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'users' AND column_name = 'name_token'
  ) THEN
    EXECUTE 'ALTER TABLE users ADD COLUMN name_token TEXT UNIQUE NOT NULL';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_users_name_token') THEN
    EXECUTE 'CREATE INDEX idx_users_name_token ON users(name_token)';
  END IF;
END $$;

-- Chats: remove plaintext group name; add encrypted group name and per-member encrypted name blobs.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'chats' AND column_name = 'chat_name'
  ) THEN
    EXECUTE 'ALTER TABLE chats DROP COLUMN chat_name';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'chats' AND column_name = 'chat_name_enc'
  ) THEN
    EXECUTE 'ALTER TABLE chats ADD COLUMN chat_name_enc TEXT NOT NULL DEFAULT ''''';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'chats' AND column_name = 'names'
  ) THEN
    EXECUTE 'ALTER TABLE chats ADD COLUMN names JSONB NOT NULL DEFAULT ''{}''::jsonb';
  END IF;
END $$;
