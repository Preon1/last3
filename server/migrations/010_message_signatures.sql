-- Signed-message origin: store client signatures alongside encrypted payloads.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'messages' AND column_name = 'signature'
  ) THEN
    EXECUTE 'ALTER TABLE messages ADD COLUMN signature TEXT NOT NULL DEFAULT ''''';
  END IF;
END $$;
