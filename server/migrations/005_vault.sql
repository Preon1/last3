BEGIN;

-- Replace password-based auth metadata with encrypted vault blob.
-- NOTE: This is a breaking migration for existing deployments.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS vault TEXT NOT NULL DEFAULT '';

-- Drop legacy fields (no longer used).
ALTER TABLE users
  DROP COLUMN IF EXISTS password_hash;

ALTER TABLE users
  DROP COLUMN IF EXISTS expiration_days;

COMMIT;
