import { query, transaction } from './db.js'
import { v7 as uuidv7 } from 'uuid'

export async function signedCleanupExpiredUsers(now = new Date()) {
  const asDate = now instanceof Date ? now : new Date(now)

  const result = await transaction(async (client) => {
    const deletedUsers = await client.query(
      `DELETE FROM users
       WHERE remove_date <= $1
       RETURNING id`,
      [asDate],
    )

    // Clean up chats that can no longer function:
    // - personal chats with <2 members
    // - group chats with 0 members
    const deletedPersonalChats = await client.query(
      `DELETE FROM chats c
       WHERE c.chat_type = 'personal'
         AND (SELECT COUNT(*)::int FROM chat_members cm WHERE cm.chat_id = c.id) < 2
       RETURNING id`,
    )

    const deletedEmptyGroupChats = await client.query(
      `DELETE FROM chats c
       WHERE c.chat_type = 'group'
         AND NOT EXISTS (SELECT 1 FROM chat_members cm WHERE cm.chat_id = c.id)
       RETURNING id`,
    )

    return {
      deletedUsers: deletedUsers.rowCount || 0,
      deletedChats: (deletedPersonalChats.rowCount || 0) + (deletedEmptyGroupChats.rowCount || 0),
    }
  })

  return result
}

export async function signedDeleteAccount(userId) {
  if (!userId) throw new Error('userId required')

  const result = await transaction(async (client) => {
    const deletedUsers = await client.query(
      `DELETE FROM users
       WHERE id = $1
       RETURNING id`,
      [String(userId)],
    )

    const deletedPersonalChats = await client.query(
      `DELETE FROM chats c
       WHERE c.chat_type = 'personal'
         AND (SELECT COUNT(*)::int FROM chat_members cm WHERE cm.chat_id = c.id) < 2
       RETURNING id`,
    )

    const deletedEmptyGroupChats = await client.query(
      `DELETE FROM chats c
       WHERE c.chat_type = 'group'
         AND NOT EXISTS (SELECT 1 FROM chat_members cm WHERE cm.chat_id = c.id)
       RETURNING id`,
    )

    return {
      deletedUsers: deletedUsers.rowCount || 0,
      deletedChats: (deletedPersonalChats.rowCount || 0) + (deletedEmptyGroupChats.rowCount || 0),
    }
  })

  return result
}

export async function signedListChats(userId) {
  const chats = await query(
    `SELECT c.id, c.chat_type, c.chat_name
     FROM chats c
     INNER JOIN chat_members cm ON cm.chat_id = c.id
     WHERE cm.user_id = $1
     ORDER BY c.id DESC`,
    [userId],
  )

  const personal = await query(
    `SELECT c.id AS chat_id,
            u.id AS other_user_id,
            u.username AS other_username,
            u.public_key AS other_public_key
     FROM chats c
     INNER JOIN chat_members me ON me.chat_id = c.id AND me.user_id = $1
     INNER JOIN chat_members other ON other.chat_id = c.id AND other.user_id <> $1
     INNER JOIN users u ON u.id = other.user_id
     WHERE c.chat_type = 'personal'`,
    [userId],
  )

  const personalByChatId = new Map(personal.rows.map((r) => [String(r.chat_id), r]))

  return chats.rows.map((c) => {
    const id = String(c.id)
    const type = String(c.chat_type)
    const base = { id, type, ...(c.chat_name ? { name: String(c.chat_name) } : {}) }

    if (type === 'personal') {
      const p = personalByChatId.get(id)
      if (p) {
        return {
          ...base,
          otherUserId: String(p.other_user_id),
          otherUsername: String(p.other_username),
          otherPublicKey: String(p.other_public_key),
        }
      }
    }

    return base
  })
}

export async function signedUnreadCounts(userId) {
  const result = await query(
    `SELECT chat_id, COUNT(*)::int AS count
     FROM unread_messages
     WHERE user_id = $1
     GROUP BY chat_id`,
    [userId],
  )

  return result.rows.map((r) => ({ chatId: String(r.chat_id), count: Number(r.count) || 0 }))
}

export async function signedCreatePersonalChat(userId, otherUsername) {
  const otherRes = await query('SELECT id, username, public_key, introvert_mode FROM users WHERE username = $1', [otherUsername])
  if (otherRes.rows.length === 0) {
    return { ok: false, reason: 'not_found' }
  }

  const other = otherRes.rows[0]
  const otherUserId = String(other.id)

  if (otherUserId === String(userId)) {
    return { ok: false, reason: 'self' }
  }

  // Check existing personal chat with exactly these two members
  const existing = await query(
    `SELECT c.id
     FROM chats c
     INNER JOIN chat_members cm1 ON cm1.chat_id = c.id AND cm1.user_id = $1
     INNER JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id = $2
     WHERE c.chat_type = 'personal'
     LIMIT 1`,
    [userId, otherUserId],
  )

  if (existing.rows.length) {
    return {
      ok: true,
      chat: {
        id: String(existing.rows[0].id),
        type: 'personal',
        otherUserId,
        otherUsername: String(other.username),
        otherPublicKey: String(other.public_key),
      },
    }
  }

  // Introvert mode: user cannot be added to new chats by others.
  // Does not affect already existing chats (handled above).
  if (Boolean(other.introvert_mode)) {
    return { ok: false, reason: 'introvert' }
  }

  const created = await transaction(async (client) => {
    const chatRes = await client.query(
      `INSERT INTO chats (chat_type, chat_name)
       VALUES ('personal', NULL)
       RETURNING id`,
    )

    const chatId = String(chatRes.rows[0].id)

    await client.query(
      `INSERT INTO chat_members (chat_id, user_id)
       VALUES ($1, $2), ($1, $3)`,
      [chatId, userId, otherUserId],
    )

    return chatId
  })

  return {
    ok: true,
    chat: {
      id: String(created),
      type: 'personal',
      otherUserId,
      otherUsername: String(other.username),
      otherPublicKey: String(other.public_key),
    },
  }
}

export async function signedCreateGroupChat(userId, chatName) {
  const name = typeof chatName === 'string' ? chatName.trim() : ''
  if (!name) return { ok: false, reason: 'bad_name' }
  if (name.length > 64) return { ok: false, reason: 'bad_name' }

  const chatId = await transaction(async (client) => {
    const chatRes = await client.query(
      `INSERT INTO chats (chat_type, chat_name)
       VALUES ('group', $1)
       RETURNING id`,
      [name],
    )

    const id = String(chatRes.rows[0].id)
    await client.query(
      `INSERT INTO chat_members (chat_id, user_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [id, String(userId)],
    )
    return id
  })

  return { ok: true, chat: { id: String(chatId), type: 'group', name } }
}

export async function signedListChatMembers(userId, chatId) {
  await assertChatMember(userId, chatId)

  const r = await query(
    `SELECT u.id, u.username, u.public_key
     FROM chat_members cm
     INNER JOIN users u ON u.id = cm.user_id
     WHERE cm.chat_id = $1
     ORDER BY u.username ASC`,
    [chatId],
  )

  return r.rows.map((row) => ({
    userId: String(row.id),
    username: String(row.username),
    publicKey: String(row.public_key),
  }))
}

export async function signedAddGroupMember(userId, chatId, username) {
  await assertChatMember(userId, chatId)

  const chat = await query(
    `SELECT chat_type
     FROM chats
     WHERE id = $1
     LIMIT 1`,
    [chatId],
  )
  if (chat.rows.length === 0) return { ok: false, reason: 'not_found' }
  if (String(chat.rows[0].chat_type) !== 'group') return { ok: false, reason: 'not_group' }

  const u = typeof username === 'string' ? username.trim() : ''
  if (!u) return { ok: false, reason: 'bad_username' }

  const otherRes = await query('SELECT id, username, public_key, introvert_mode FROM users WHERE username = $1', [u])
  if (otherRes.rows.length === 0) return { ok: false, reason: 'not_found' }

  const other = otherRes.rows[0]
  const otherUserId = String(other.id)

  // Introvert mode: user cannot be added to chats by others.
  if (Boolean(other.introvert_mode)) return { ok: false, reason: 'introvert' }

  await query(
    `INSERT INTO chat_members (chat_id, user_id)
     VALUES ($1, $2)
     ON CONFLICT DO NOTHING`,
    [chatId, otherUserId],
  )

  return {
    ok: true,
    member: { userId: otherUserId, username: String(other.username), publicKey: String(other.public_key) },
  }
}

async function assertChatMember(userId, chatId) {
  const r = await query(
    `SELECT 1
     FROM chat_members
     WHERE chat_id = $1 AND user_id = $2
     LIMIT 1`,
    [chatId, userId],
  )
  if (r.rows.length === 0) {
    const err = new Error('Forbidden')
    err.code = 'forbidden'
    throw err
  }
}

export async function signedFetchMessages(userId, chatId, limit = 50, beforeId = null) {
  await assertChatMember(userId, chatId)

  const lim = Math.max(1, Math.min(200, Number(limit) || 50))

  const params = beforeId ? [chatId, userId, beforeId, lim] : [chatId, userId, lim]
  const sql = beforeId
     ? `SELECT m.id, m.encrypted_data, m.sender_id, u.username AS sender_username
       FROM messages m
       INNER JOIN message_recipients mr ON mr.message_id = m.id AND mr.user_id = $2
       INNER JOIN users u ON u.id = m.sender_id
       WHERE m.chat_id = $1 AND m.id < $3
       ORDER BY m.id DESC
       LIMIT $4`
     : `SELECT m.id, m.encrypted_data, m.sender_id, u.username AS sender_username
       FROM messages m
       INNER JOIN message_recipients mr ON mr.message_id = m.id AND mr.user_id = $2
       INNER JOIN users u ON u.id = m.sender_id
       WHERE m.chat_id = $1
       ORDER BY m.id DESC
       LIMIT $3`

  const r = await query(sql, params)
  return r.rows.map((row) => ({
    id: String(row.id),
    chatId: String(chatId),
    senderId: String(row.sender_id),
    senderUsername: String(row.sender_username ?? ''),
    encryptedData: String(row.encrypted_data),
  }))
}

export async function signedSendMessage({ senderId, chatId, encryptedData }) {
  await assertChatMember(senderId, chatId)

  const messageId = uuidv7()

  const result = await transaction(async (client) => {
    await client.query(
      `INSERT INTO messages (id, chat_id, encrypted_data, sender_id)
       VALUES ($1, $2, $3, $4)`,
      [messageId, chatId, encryptedData, senderId],
    )

    const members = await client.query(
      `SELECT user_id
       FROM chat_members
       WHERE chat_id = $1`,
      [chatId],
    )

    const memberIds = members.rows.map((m) => String(m.user_id))

    // Recipients mapping: all members can see the message.
    if (memberIds.length) {
      const values = memberIds.map((_, i) => `($1, $${i + 2})`).join(',')
      await client.query(
        `INSERT INTO message_recipients (message_id, user_id)
         VALUES ${values}
         ON CONFLICT DO NOTHING`,
        [messageId, ...memberIds],
      )

      // Unread: everyone except sender.
      const others = memberIds.filter((id) => id !== String(senderId))
      if (others.length) {
        // NOTE: unread_messages columns are (user_id, message_id, chat_id)
        // Params are [messageId, ...others, chatId].
        // So each row is (otherUserId, messageId, chatId).
        const v2 = others.map((_, i) => `($${i + 2}, $1, $${others.length + 2})`).join(',')
        await client.query(
          `INSERT INTO unread_messages (user_id, message_id, chat_id)
           VALUES ${v2}
           ON CONFLICT DO NOTHING`,
          [messageId, ...others, chatId],
        )
      }
    }

    return { messageId, memberIds }
  })

  return result
}

export async function signedMarkChatRead(userId, chatId) {
  await assertChatMember(userId, chatId)
  await query(
    `DELETE FROM unread_messages
     WHERE user_id = $1 AND chat_id = $2`,
    [userId, chatId],
  )
}

export async function signedMarkMessagesRead(userId, chatId, messageIds) {
  await assertChatMember(userId, chatId)

  const ids = Array.isArray(messageIds) ? messageIds.map(String).filter(Boolean) : []
  if (!ids.length) return { unreadCount: null }

  await query(
    `DELETE FROM unread_messages
     WHERE user_id = $1 AND chat_id = $2 AND message_id = ANY($3::uuid[])`,
    [userId, chatId, ids],
  )

  const r = await query(
    `SELECT COUNT(*)::int AS count
     FROM unread_messages
     WHERE user_id = $1 AND chat_id = $2`,
    [userId, chatId],
  )

  const unreadCount = Number(r.rows?.[0]?.count) || 0
  return { unreadCount }
}

export async function signedUnreadMessageIds(userId, chatId, limit = 500) {
  await assertChatMember(userId, chatId)
  const lim = Math.max(1, Math.min(5000, Number(limit) || 500))
  const r = await query(
    `SELECT message_id
     FROM unread_messages
     WHERE user_id = $1 AND chat_id = $2
     ORDER BY message_id DESC
     LIMIT $3`,
    [String(userId), String(chatId), lim],
  )
  return r.rows.map((x) => String(x.message_id))
}

export async function signedDeleteMessage({ userId, chatId, messageId }) {
  await assertChatMember(userId, chatId)

  const result = await transaction(async (client) => {
    const m = await client.query(
      `SELECT sender_id
       FROM messages
       WHERE id = $1 AND chat_id = $2
       LIMIT 1`,
      [String(messageId), String(chatId)],
    )
    if (!m.rows.length) return { ok: false, reason: 'not_found' }
    if (String(m.rows[0].sender_id) !== String(userId)) return { ok: false, reason: 'forbidden' }

    const members = await client.query(
      `SELECT user_id
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const memberIds = members.rows.map((r) => String(r.user_id))

    await client.query(
      `DELETE FROM messages
       WHERE id = $1 AND chat_id = $2`,
      [String(messageId), String(chatId)],
    )

    return { ok: true, memberIds }
  })

  return result
}

export async function signedUpdateMessage({ userId, chatId, messageId, encryptedData }) {
  await assertChatMember(userId, chatId)
  const enc = typeof encryptedData === 'string' ? encryptedData : ''
  if (!enc) return { ok: false, reason: 'bad_payload' }

  const result = await transaction(async (client) => {
    const m = await client.query(
      `SELECT sender_id
       FROM messages
       WHERE id = $1 AND chat_id = $2
       LIMIT 1`,
      [String(messageId), String(chatId)],
    )
    if (!m.rows.length) return { ok: false, reason: 'not_found' }
    if (String(m.rows[0].sender_id) !== String(userId)) return { ok: false, reason: 'forbidden' }

    const members = await client.query(
      `SELECT user_id
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const memberIds = members.rows.map((r) => String(r.user_id))

    await client.query(
      `UPDATE messages
       SET encrypted_data = $1
       WHERE id = $2 AND chat_id = $3`,
      [enc, String(messageId), String(chatId)],
    )

    return { ok: true, memberIds }
  })

  return result
}

export async function signedLeaveChat(userId, chatId) {
  await assertChatMember(userId, chatId)

  const result = await transaction(async (client) => {
    await client.query(
      `DELETE FROM chat_members
       WHERE chat_id = $1 AND user_id = $2`,
      [String(chatId), String(userId)],
    )

    await client.query(
      `DELETE FROM unread_messages
       WHERE chat_id = $1 AND user_id = $2`,
      [String(chatId), String(userId)],
    )

    const left = await client.query(
      `SELECT COUNT(*)::int AS n
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const n = Number(left.rows?.[0]?.n) || 0
    if (n === 0) {
      await client.query(
        `DELETE FROM chats
         WHERE id = $1`,
        [String(chatId)],
      )
    }
    return { ok: true, remainingMembers: n }
  })

  return result
}

export async function signedDeletePersonalChat(userId, chatId) {
  await assertChatMember(userId, chatId)

  const result = await transaction(async (client) => {
    const chat = await client.query(
      `SELECT chat_type
       FROM chats
       WHERE id = $1
       LIMIT 1`,
      [String(chatId)],
    )
    if (!chat.rows.length) return { ok: false, reason: 'not_found' }
    if (String(chat.rows[0].chat_type) !== 'personal') return { ok: false, reason: 'not_personal' }

    const members = await client.query(
      `SELECT user_id
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const memberIds = members.rows.map((r) => String(r.user_id))

    // Cascade deletes messages, recipients, unread, memberships.
    await client.query(
      `DELETE FROM chats
       WHERE id = $1`,
      [String(chatId)],
    )

    return { ok: true, memberIds }
  })

  return result
}
