import { query, transaction } from './db.js'
import { v7 as uuidv7 } from 'uuid'

function scrubRecipientFromEncryptedData(encryptedData, recipientUserId) {
  const enc = typeof encryptedData === 'string' ? encryptedData : ''
  const uid = typeof recipientUserId === 'string' ? recipientUserId : ''
  if (!enc || !uid) return enc

  // Fast-path: if the user id string isn't present, don't parse.
  if (!enc.includes(uid)) return enc

  try {
    const obj = JSON.parse(enc)
    if (!obj || obj.v !== 1) return enc
    if (!obj.keys || typeof obj.keys !== 'object') return enc
    if (!Object.prototype.hasOwnProperty.call(obj.keys, uid)) return enc

    // Remove only the recipient key wrapper; keep ciphertext intact.
    delete obj.keys[uid]
    return JSON.stringify(obj)
  } catch {
    return enc
  }
}

async function scrubRecipientFromChatMessages(client, chatId, recipientUserId) {
  const cid = String(chatId || '')
  const uid = String(recipientUserId || '')
  if (!cid || !uid) return

  // Only touch rows that likely contain the userId in the envelope.
  const rows = await client.query(
    `SELECT id, encrypted_data
     FROM messages
     WHERE chat_id = $1 AND encrypted_data LIKE '%' || $2 || '%'`,
    [cid, uid],
  )

  for (const r of rows.rows) {
    const id = String(r.id)
    const cur = String(r.encrypted_data ?? '')
    const next = scrubRecipientFromEncryptedData(cur, uid)
    if (next !== cur) {
      await client.query(
        `UPDATE messages
         SET encrypted_data = $1
         WHERE id = $2`,
        [next, id],
      )
    }
  }
}

function scrubUserFromChatNamesJson(names, userId) {
  const uid = typeof userId === 'string' ? userId : ''
  if (!uid) return names
  if (!names || typeof names !== 'object') return names

  // names is a JSONB object mapping subjectUserId -> encryptedBlobString
  const out = { ...names }

  // Remove the leaving/deleted user's own entry.
  if (Object.prototype.hasOwnProperty.call(out, uid)) {
    delete out[uid]
  }

  // Remove them as a recipient from everyone else's blob.
  for (const [subjectUserId, enc] of Object.entries(out)) {
    if (!subjectUserId) continue
    if (typeof enc !== 'string') continue
    const next = scrubRecipientFromEncryptedData(enc, uid)
    if (next !== enc) out[subjectUserId] = next
  }

  return out
}

async function scrubUserFromChatMetadata(client, chatId, userId) {
  const cid = String(chatId || '')
  const uid = String(userId || '')
  if (!cid || !uid) return

  const r = await client.query(
    `SELECT chat_name_enc, names
     FROM chats
     WHERE id = $1
     LIMIT 1`,
    [cid],
  )
  const row = r?.rows?.[0]
  if (!row) return

  const curChatNameEnc = typeof row.chat_name_enc === 'string' ? row.chat_name_enc : ''
  const nextChatNameEnc = scrubRecipientFromEncryptedData(curChatNameEnc, uid)

  const curNames = row.names ?? {}
  const nextNames = scrubUserFromChatNamesJson(curNames, uid)

  const changed = (nextChatNameEnc !== curChatNameEnc) || (JSON.stringify(nextNames) !== JSON.stringify(curNames))
  if (!changed) return

  await client.query(
    `UPDATE chats
     SET chat_name_enc = $1,
         names = $2
     WHERE id = $3`,
    [nextChatNameEnc, nextNames, cid],
  )
}

export async function signedCleanupExpiredUsers(now = new Date()) {
  const asDate = now instanceof Date ? now : new Date(now)

  const result = await transaction(async (client) => {
    // Capture affected users so we can scrub their IDs from ciphertext envelopes
    // before deleting the users (which would cascade chat_members).
    const toDelete = await client.query(
      `SELECT id
       FROM users
       WHERE remove_date <= $1`,
      [asDate],
    )
    const toDeleteIds = toDelete.rows.map((r) => String(r.id)).filter(Boolean)

    for (const uid of toDeleteIds) {
      const chats = await client.query(
        `SELECT chat_id
         FROM chat_members
         WHERE user_id = $1`,
        [uid],
      )
      for (const row of chats.rows) {
        await scrubRecipientFromChatMessages(client, String(row.chat_id), uid)
        await scrubUserFromChatMetadata(client, String(row.chat_id), uid)
      }
    }

    const deletedUsers = await client.query(
      `DELETE FROM users
       WHERE remove_date <= $1
       RETURNING id`,
      [asDate],
    )

    const deletedUserIds = deletedUsers.rows.map((r) => String(r.id))

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
      deletedUserIds,
      deletedChats: (deletedPersonalChats.rowCount || 0) + (deletedEmptyGroupChats.rowCount || 0),
    }
  })

  return result
}

export async function signedDeleteAccount(userId) {
  if (!userId) throw new Error('userId required')

  const result = await transaction(async (client) => {
    // Scrub this user's ID from ciphertext envelopes in all chats they are a member of
    // before deleting the user (which would cascade chat_members).
    const chats = await client.query(
      `SELECT chat_id
       FROM chat_members
       WHERE user_id = $1`,
      [String(userId)],
    )
    for (const row of chats.rows) {
      await scrubRecipientFromChatMessages(client, String(row.chat_id), String(userId))
      await scrubUserFromChatMetadata(client, String(row.chat_id), String(userId))
    }

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
    `SELECT c.id, c.chat_type, c.chat_name_enc, c.names
     FROM chats c
     INNER JOIN chat_members cm ON cm.chat_id = c.id
     WHERE cm.user_id = $1
     ORDER BY c.id DESC`,
    [userId],
  )

  const personal = await query(
    `SELECT c.id AS chat_id,
            u.id AS other_user_id,
            u.public_key AS other_public_key
     FROM chats c
     INNER JOIN chat_members me ON me.chat_id = c.id AND me.user_id = $1
     INNER JOIN chat_members other ON other.chat_id = c.id AND other.user_id <> $1
     INNER JOIN users u ON u.id = other.user_id
     WHERE c.chat_type = 'personal'`,
    [userId],
  )

  const personalByChatId = new Map(personal.rows.map((r) => [String(r.chat_id), r]))

  return chats.rows
    .map((c) => {
    const id = String(c.id)
    const type = String(c.chat_type)
    const chatNameEnc = typeof c.chat_name_enc === 'string' ? String(c.chat_name_enc) : ''
    const names = c.names ?? {}
    const base = { id, type, chatNameEnc, names }

    if (type === 'personal') {
      const p = personalByChatId.get(id)
      if (p) {
        return {
          ...base,
          otherUserId: String(p.other_user_id),
          otherPublicKey: String(p.other_public_key),
        }
      }

      // Malformed personal chats (e.g. legacy self-chat with no counterpart).
      return null
    }

    return base
  })
    .filter(Boolean)
}

async function signedLastMessagesForUserByChatIds(userId, chatIds) {
  const ids = Array.isArray(chatIds) ? chatIds.map(String).filter(Boolean) : []
  if (!ids.length) return []

  // Only return messages visible to the caller (membership + visibility border).
  const r = await query(
    `SELECT DISTINCT ON (m.chat_id) m.chat_id, m.id, m.sender_id, m.encrypted_data, m.signature
     FROM messages m
     INNER JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.user_id = $1
     WHERE m.chat_id = ANY($2::uuid[])
       AND (cm.visible_after_message_id IS NULL OR m.id > cm.visible_after_message_id)
     ORDER BY m.chat_id, m.id DESC`,
    [String(userId), ids],
  )

  return r.rows.map((row) => ({
    chatId: String(row.chat_id),
    id: String(row.id),
    senderId: String(row.sender_id),
    encryptedData: String(row.encrypted_data),
    signature: typeof row.signature === 'string' ? String(row.signature) : '',
  }))
}

export async function signedGetLastMessagesForChatIds(userId, chatIds, opts = {}) {
  const enforceMembership = opts?.enforceMembership !== false
  const list = Array.isArray(chatIds) ? chatIds.map(String).filter(Boolean) : []
  if (!list.length) return []

  const unique = Array.from(new Set(list))

  if (enforceMembership) {
    const memberRows = await query(
      `SELECT chat_id
       FROM chat_members
       WHERE user_id = $1 AND chat_id = ANY($2::uuid[])`,
      [String(userId), unique],
    )

    const memberSet = new Set(memberRows.rows.map((r) => String(r.chat_id)))
    const allOk = unique.every((id) => memberSet.has(String(id)))
    if (!allOk) {
      const err = new Error('Forbidden')
      err.code = 'forbidden'
      throw err
    }
  }

  const rows = await signedLastMessagesForUserByChatIds(userId, unique)
  const byChatId = new Map(rows.map((m) => [String(m.chatId), m]))

  // Preserve caller order; chats with no messages get null.
  return list.map((cid) => byChatId.get(String(cid)) ?? null)
}

export async function signedListChatsWithLastMessage(userId) {
  const chats = await signedListChats(userId)
  const chatIds = chats.map((c) => c.id)
  const last = await signedGetLastMessagesForChatIds(userId, chatIds, { enforceMembership: false })
  const lastByChatId = new Map(
    chatIds.map((cid, i) => [String(cid), last[i]]),
  )

  return chats.map((c) => ({
    ...c,
    lastMessage: lastByChatId.get(String(c.id)) ?? null,
  }))
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

export async function signedCreatePersonalChat(userId, otherUserId, names) {
  const otherRes = await query('SELECT id, public_key, introvert_mode FROM users WHERE id = $1', [String(otherUserId)])
  if (otherRes.rows.length === 0) return { ok: false, reason: 'not_found' }

  const other = otherRes.rows[0]
  const otherId = String(other.id)

  if (otherId === String(userId)) {
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
    [userId, otherId],
  )

  if (existing.rows.length) {
    return {
      ok: true,
      chat: {
        id: String(existing.rows[0].id),
        type: 'personal',
        otherUserId: otherId,
        otherPublicKey: String(other.public_key),
      },
    }
  }

  // Introvert mode: user cannot be added to new chats by others.
  // Does not affect already existing chats (handled above).
  if (Boolean(other.introvert_mode)) {
    return { ok: false, reason: 'introvert' }
  }

  const namesJson = (names && typeof names === 'object') ? names : {}

  const created = await transaction(async (client) => {
    const chatRes = await client.query(
      `INSERT INTO chats (chat_type, chat_name_enc, names)
       VALUES ('personal', '', $1)
       RETURNING id`,
      [namesJson],
    )

    const chatId = String(chatRes.rows[0].id)

    await client.query(
      `INSERT INTO chat_members (chat_id, user_id)
       VALUES ($1, $2), ($1, $3)`,
      [chatId, userId, otherId],
    )

    return chatId
  })

  return {
    ok: true,
    chat: {
      id: String(created),
      type: 'personal',
      otherUserId: otherId,
      otherPublicKey: String(other.public_key),
    },
  }
}

export async function signedCreateGroupChat(userId, chatNameEnc, names) {
  const enc = typeof chatNameEnc === 'string' ? chatNameEnc : ''
  if (!enc) return { ok: false, reason: 'bad_name' }
  if (enc.length > 100_000) return { ok: false, reason: 'bad_name' }
  const namesJson = (names && typeof names === 'object') ? names : {}

  const chatId = await transaction(async (client) => {
    const chatRes = await client.query(
      `INSERT INTO chats (chat_type, chat_name_enc, names)
       VALUES ('group', $1, $2)
       RETURNING id`,
      [enc, namesJson],
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

  return { ok: true, chat: { id: String(chatId), type: 'group', chatNameEnc: enc, names: namesJson } }
}

export async function signedListChatMembers(userId, chatId) {
  await assertChatMember(userId, chatId)

  const chat = await query(
    `SELECT chat_type
     FROM chats
     WHERE id = $1
     LIMIT 1`,
    [chatId],
  )
  if (chat.rows.length === 0) return []
  if (String(chat.rows[0].chat_type) !== 'group') {
    const err = new Error('Not a group')
    err.code = 'not_group'
    throw err
  }

  const r = await query(
    `SELECT u.id, u.public_key
     FROM chat_members cm
     INNER JOIN users u ON u.id = cm.user_id
     WHERE cm.chat_id = $1
     ORDER BY u.id ASC`,
    [chatId],
  )

  return r.rows.map((row) => ({
    userId: String(row.id),
    publicKey: String(row.public_key),
  }))
}

export async function signedAddGroupMember(userId, chatId, otherUserId, names, chatNameEnc) {
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

  const otherRes = await query('SELECT id, public_key, introvert_mode FROM users WHERE id = $1', [String(otherUserId)])
  if (otherRes.rows.length === 0) return { ok: false, reason: 'not_found' }

  const other = otherRes.rows[0]
  const otherId = String(other.id)

  if (String(otherId) === String(userId)) return { ok: false, reason: 'self' }

  // Introvert mode: user cannot be added to chats by others.
  if (Boolean(other.introvert_mode)) return { ok: false, reason: 'introvert' }

  const namesJson = (names && typeof names === 'object') ? names : {}
  const nextChatNameEnc = typeof chatNameEnc === 'string' ? chatNameEnc : null

  const ins = await query(
    `INSERT INTO chat_members (chat_id, user_id, visible_after_message_id)
     VALUES (
       $1,
       $2,
       $3
     )
     ON CONFLICT DO NOTHING
     RETURNING user_id`,
    [chatId, otherId, uuidv7()],
  )
  if (!ins.rows.length) return { ok: false, reason: 'already_member' }

  await query(
    `UPDATE chats
     SET names = $1,
         chat_name_enc = COALESCE($2, chat_name_enc)
     WHERE id = $3`,
    [namesJson, nextChatNameEnc, String(chatId)],
  )

  return {
    ok: true,
    member: { userId: otherId, publicKey: String(other.public_key) },
  }
}

export async function signedRenameGroupChat(userId, chatId, chatNameEnc) {
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

  const enc = typeof chatNameEnc === 'string' ? chatNameEnc : ''
  if (!enc) return { ok: false, reason: 'bad_name' }
  if (enc.length > 100_000) return { ok: false, reason: 'bad_name' }

  await query(
    `UPDATE chats
     SET chat_name_enc = $1
     WHERE id = $2`,
    [enc, chatId],
  )

  const members = await query(
    `SELECT user_id
     FROM chat_members
     WHERE chat_id = $1`,
    [chatId],
  )

  return {
    ok: true,
    chat: { id: String(chatId), type: 'group', chatNameEnc: enc },
    memberIds: members.rows.map((r) => String(r.user_id)),
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
     ? `SELECT m.id, m.encrypted_data, m.signature, m.sender_id
       FROM messages m
       INNER JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.user_id = $2
       WHERE m.chat_id = $1
         AND (cm.visible_after_message_id IS NULL OR m.id > cm.visible_after_message_id)
         AND m.id < $3
       ORDER BY m.id DESC
       LIMIT $4`
     : `SELECT m.id, m.encrypted_data, m.signature, m.sender_id
       FROM messages m
       INNER JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.user_id = $2
       WHERE m.chat_id = $1
         AND (cm.visible_after_message_id IS NULL OR m.id > cm.visible_after_message_id)
       ORDER BY m.id DESC
       LIMIT $3`

  const r = await query(sql, params)
  return r.rows.map((row) => ({
    id: String(row.id),
    chatId: String(chatId),
    senderId: String(row.sender_id),
    encryptedData: String(row.encrypted_data),
    signature: typeof row.signature === 'string' ? String(row.signature) : '',
  }))
}

export async function signedSendMessage({ senderId, chatId, encryptedData, signature = '' }) {
  await assertChatMember(senderId, chatId)

  const messageId = uuidv7()

  const result = await transaction(async (client) => {
    await client.query(
      `INSERT INTO messages (id, chat_id, encrypted_data, signature, sender_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [messageId, chatId, encryptedData, String(signature || ''), senderId],
    )

    const members = await client.query(
      `SELECT user_id
       FROM chat_members
       WHERE chat_id = $1`,
      [chatId],
    )

    const memberIds = members.rows.map((m) => String(m.user_id))

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

export async function signedUpdateMessage({ userId, chatId, messageId, encryptedData, signature = '' }) {
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
       SET encrypted_data = $1,
           signature = $2
       WHERE id = $3 AND chat_id = $4`,
      [enc, String(signature || ''), String(messageId), String(chatId)],
    )

    return { ok: true, memberIds }
  })

  return result
}

export async function signedLeaveChat(userId, chatId) {
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
    if (String(chat.rows[0].chat_type) !== 'group') return { ok: false, reason: 'not_group' }

    const before = await client.query(
      `SELECT COUNT(*)::int AS n
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const beforeN = Number(before.rows?.[0]?.n) || 0
    const isLast = beforeN <= 1

    let deletedMessageIds = []
    if (!isLast) {
      const del = await client.query(
        `DELETE FROM messages
         WHERE chat_id = $1 AND sender_id = $2
         RETURNING id`,
        [String(chatId), String(userId)],
      )
      deletedMessageIds = del.rows.map((r) => String(r.id))
    }

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

    // If the chat remains, scrub this user's ID from the ciphertext envelopes
    // so their userId does not remain as a recipient-key entry.
    // If the chat is deleted (last member), messages are deleted by cascade.
    try {
      await scrubRecipientFromChatMessages(client, String(chatId), String(userId))
    } catch {
      // ignore (best-effort privacy cleanup)
    }

    // Option A: also scrub this user's ID from chat metadata (names + chat name)
    // so the server can remove user-specific encrypted blobs without client help.
    try {
      await scrubUserFromChatMetadata(client, String(chatId), String(userId))
    } catch {
      // ignore (best-effort privacy cleanup)
    }

    const left = await client.query(
      `SELECT COUNT(*)::int AS n
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const n = Number(left.rows?.[0]?.n) || 0

    let chatDeleted = false
    if (n === 0) {
      // If you were the last member, delete the chat. This cascades messages,
      // recipients, unread, and memberships.
      await client.query(
        `DELETE FROM chats
         WHERE id = $1`,
        [String(chatId)],
      )
      chatDeleted = true
    }

    const remaining = await client.query(
      `SELECT user_id
       FROM chat_members
       WHERE chat_id = $1`,
      [String(chatId)],
    )
    const remainingMemberIds = remaining.rows.map((r) => String(r.user_id))

    return { ok: true, remainingMembers: n, remainingMemberIds, deletedMessageIds, chatDeleted }
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
