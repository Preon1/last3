-- LRCom Database Schema for Authenticated Users (minimal unencrypted metadata)

-- Needed for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name_token TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  vault TEXT NOT NULL DEFAULT '',
  remove_date TIMESTAMP NOT NULL,
  hidden_mode BOOLEAN NOT NULL DEFAULT FALSE,
  introvert_mode BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_users_name_token ON users(name_token);
CREATE INDEX idx_users_remove_date ON users(remove_date);

-- Chats table
CREATE TABLE IF NOT EXISTS chats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chat_type VARCHAR(10) NOT NULL CHECK (chat_type IN ('personal', 'group')),
  chat_name_enc BYTEA NOT NULL DEFAULT ''::bytea
);

CREATE INDEX idx_chats_type ON chats(chat_type);

-- Chat members (users in chats)
CREATE TABLE IF NOT EXISTS chat_members (
  chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  visible_after_message_id UUID NULL,
  PRIMARY KEY (chat_id, user_id)
);

CREATE INDEX idx_chat_members_user ON chat_members(user_id);
CREATE INDEX idx_chat_members_chat ON chat_members(chat_id);

-- Per-subject encrypted display names for chat members.
CREATE TABLE IF NOT EXISTS chat_names_enc (
  chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  subject_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  enc BYTEA NOT NULL,
  PRIMARY KEY (chat_id, subject_user_id)
);

CREATE INDEX idx_chat_names_chat ON chat_names_enc(chat_id);
CREATE INDEX idx_chat_names_subject ON chat_names_enc(subject_user_id);

-- Messages table (UUIDv7 for chronological ordering)
CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY,
  chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  encrypted_data BYTEA NOT NULL,
  signature TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_messages_chat ON messages(chat_id);
CREATE INDEX idx_messages_sender ON messages(sender_id);

-- Unread messages tracking
CREATE TABLE IF NOT EXISTS unread_messages (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, message_id)
);

CREATE INDEX idx_unread_user ON unread_messages(user_id);
CREATE INDEX idx_unread_chat ON unread_messages(user_id, chat_id);
