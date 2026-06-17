import { query, transaction } from './db.js'
import { v7 as uuidv7 } from 'uuid'

const AES_GCM_TAG_BYTES = 16
const ENVELOPE_IV_BYTES = 12
const ENVELOPE_RECIPIENT_COUNT_BYTES = 2
const ENVELOPE_RECIPIENT_ID_BYTES = 16
const ENVELOPE_WRAPPED_KEY_BYTES = 512
const ENVELOPE_ENTRY_BYTES = ENVELOPE_RECIPIENT_ID_BYTES + ENVELOPE_WRAPPED_KEY_BYTES
const ENVELOPE_MIN_CT_BYTES = AES_GCM_TAG_BYTES

function b64UrlDecode(str) {
  const raw = String(str ?? '').replace(/-/g, '+').replace(/_/g, '/')
  const padLen = (4 - (raw.length % 4)) % 4
  return Buffer.from(`${raw}${'='.repeat(padLen)}`, 'base64')
}

function b64UrlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function parseUuidToBytes(uuid) {
  const raw = String(uuid ?? '').trim().toLowerCase().replace(/-/g, '')
  if (!/^[0-9a-f]{32}$/.test(raw)) throw new Error('Invalid user id in envelope')
  const out = Buffer.alloc(ENVELOPE_RECIPIENT_ID_BYTES)
  for (let i = 0; i < ENVELOPE_RECIPIENT_ID_BYTES; i++) {
    out[i] = Number.parseInt(raw.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function parseEnvelopeBlob(encryptedData) {
  const all = b64UrlDecode(encryptedData)
  const min = ENVELOPE_IV_BYTES + ENVELOPE_RECIPIENT_COUNT_BYTES + ENVELOPE_MIN_CT_BYTES
  if (all.byteLength < min) throw new Error('Unsupported message format')

  let off = 0
  const iv = all.subarray(off, off + ENVELOPE_IV_BYTES)
  off += ENVELOPE_IV_BYTES

  const recipientCount = (all[off] << 8) | all[off + 1]
  off += ENVELOPE_RECIPIENT_COUNT_BYTES
  if (recipientCount <= 0) throw new Error('Unsupported message format')

  const neededForKeys = recipientCount * ENVELOPE_ENTRY_BYTES
  if (off + neededForKeys + ENVELOPE_MIN_CT_BYTES > all.byteLength) throw new Error('Unsupported message format')

  const keyEntries = []
  for (let i = 0; i < recipientCount; i++) {
    const userIdBytes = all.subarray(off, off + ENVELOPE_RECIPIENT_ID_BYTES)
    off += ENVELOPE_RECIPIENT_ID_BYTES
    const wrappedKeyBytes = all.subarray(off, off + ENVELOPE_WRAPPED_KEY_BYTES)
    off += ENVELOPE_WRAPPED_KEY_BYTES
    keyEntries.push({ userIdBytes, wrappedKeyBytes })
  }

  const ct = all.subarray(off)
  if (ct.byteLength < ENVELOPE_MIN_CT_BYTES) throw new Error('Unsupported message format')

  return { iv, keyEntries, ct }
}

function packEnvelopeBlob(parts) {
  const iv = Buffer.from(parts?.iv ?? [])
  const ct = Buffer.from(parts?.ct ?? [])
  const keyEntries = Array.isArray(parts?.keyEntries) ? parts.keyEntries : []
  if (iv.byteLength !== ENVELOPE_IV_BYTES) throw new Error('Unsupported message format')
  if (ct.byteLength < ENVELOPE_MIN_CT_BYTES) throw new Error('Unsupported message format')
  if (keyEntries.length <= 0 || keyEntries.length > 0xffff) throw new Error('Unsupported message format')

  const out = Buffer.alloc(ENVELOPE_IV_BYTES + ENVELOPE_RECIPIENT_COUNT_BYTES + keyEntries.length * ENVELOPE_ENTRY_BYTES + ct.byteLength)
  let off = 0
  iv.copy(out, off)
  off += ENVELOPE_IV_BYTES
  out[off] = (keyEntries.length >> 8) & 0xff
  out[off + 1] = keyEntries.length & 0xff
  off += ENVELOPE_RECIPIENT_COUNT_BYTES

  for (const entry of keyEntries) {
    const userIdBytes = Buffer.from(entry.userIdBytes)
    const wrappedKeyBytes = Buffer.from(entry.wrappedKeyBytes)
    if (userIdBytes.byteLength !== ENVELOPE_RECIPIENT_ID_BYTES) throw new Error('Unsupported message format')
    if (wrappedKeyBytes.byteLength !== ENVELOPE_WRAPPED_KEY_BYTES) throw new Error('Unsupported message format')
    userIdBytes.copy(out, off)
    off += ENVELOPE_RECIPIENT_ID_BYTES
    wrappedKeyBytes.copy(out, off)
    off += ENVELOPE_WRAPPED_KEY_BYTES
  }

  ct.copy(out, off)
  return b64UrlEncode(out)
}

function dbBlobToWireEnvelope(blob) {
  if (!blob) return ''
  const b = Buffer.isBuffer(blob) ? blob : Buffer.from(blob)
  if (!b.byteLength) return ''
  return b64UrlEncode(b)
}

function wireEnvelopeToDbBlob(encryptedData) {
  const wire = String(encryptedData ?? '')
  if (!wire) {
    const err = new Error('bad_payload')
    err.code = 'bad_payload'
    throw err
  }
  try {
    // Strict format validation (no backward compatibility).
    parseEnvelopeBlob(wire)
    return b64UrlDecode(wire)
  } catch {
    const err = new Error('bad_payload')
    err.code = 'bad_payload'
    throw err
  }
}

function normalizeChatNamesPayload(names) {
  if (!names || typeof names !== 'object' || Array.isArray(names)) return []

  const out = []
  for (const [subjectUserIdRaw, encRaw] of Object.entries(names)) {
    const subjectUserId = String(subjectUserIdRaw ?? '')
    const enc = typeof encRaw === 'string' ? encRaw : ''
    if (!subjectUserId || !enc) continue
    // Validate UUID shape used in compact envelope recipient entries.
    parseUuidToBytes(subjectUserId)
    out.push({ subjectUserId, enc: wireEnvelopeToDbBlob(enc) })
  }
  return out
}

function mapRowsToNamesObject(rows) {
  const out = {}
  for (const row of rows ?? []) {
    const chatId = String(row.chat_id ?? '')
    const subjectUserId = String(row.subject_user_id ?? '')
    if (!chatId || !subjectUserId) continue
    if (!out[chatId]) out[chatId] = {}
    out[chatId][subjectUserId] = dbBlobToWireEnvelope(row.enc)
  }
  return out
}

async function replaceChatNamesForChat(client, chatId, nameRows) {
  const cid = String(chatId || '')
  if (!cid) return

  await client.query(
    `DELETE FROM chat_names_enc
     WHERE chat_id = $1`,
    [cid],
  )

  const rows = Array.isArray(nameRows) ? nameRows : []
  if (!rows.length) return

  const values = []
  const params = [cid]
  for (const row of rows) {
    const subjectUserId = String(row?.subjectUserId ?? '')
    const enc = row?.enc
    if (!subjectUserId || !enc) continue
    params.push(subjectUserId, enc)
    const i = params.length
    values.push(`($1, $${i - 1}, $${i})`)
  }
  if (!values.length) return

  await client.query(
    `INSERT INTO chat_names_enc (chat_id, subject_user_id, enc)
     VALUES ${values.join(',')}`,
    params,
  )
}

async function loadChatNamesByChatIds(chatIds) {
  const ids = Array.isArray(chatIds) ? chatIds.map(String).filter(Boolean) : []
  if (!ids.length) return {}

  const r = await query(
    `SELECT chat_id, subject_user_id, enc
     FROM chat_names_enc
     WHERE chat_id = ANY($1::uuid[])`,
    [ids],
  )
  return mapRowsToNamesObject(r.rows)
}

function scrubRecipientFromEncryptedData(encryptedData, recipientUserId) {
  const enc = typeof encryptedData === 'string' ? encryptedData : ''
  const uid = typeof recipientUserId === 'string' ? recipientUserId : ''
  if (!enc || !uid) return enc

  try {
    const parsed = parseEnvelopeBlob(enc)
    const target = parseUuidToBytes(uid)
    const nextKeyEntries = parsed.keyEntries.filter((k) => !Buffer.from(k.userIdBytes).equals(target))
    if (!nextKeyEntries.length || nextKeyEntries.length === parsed.keyEntries.length) return enc
    return packEnvelopeBlob({ iv: parsed.iv, ct: parsed.ct, keyEntries: nextKeyEntries })
  } catch {
    return enc
  }
}

async function scrubRecipientFromChatMessages(client, chatId, recipientUserId) {
  const cid = String(chatId || '')
  const uid = String(recipientUserId || '')
  if (!cid || !uid) return

  const rows = await client.query(
    `SELECT id, encrypted_data
     FROM messages
     WHERE chat_id = $1`,
    [cid],
  )

  for (const r of rows.rows) {
    const id = String(r.id)
    const cur = dbBlobToWireEnvelope(r.encrypted_data)
    const next = scrubRecipientFromEncryptedData(cur, uid)
    if (next !== cur) {
      await client.query(
        `UPDATE messages
         SET encrypted_data = $1
         WHERE id = $2`,
        [wireEnvelopeToDbBlob(next), id],
      )
    }
  }
}

async function scrubUserFromChatMetadata(client, chatId, userId) {
  const cid = String(chatId || '')
  const uid = String(userId || '')
  if (!cid || !uid) return

  const r = await client.query(`SELECT chat_name_enc FROM chats WHERE id = $1 LIMIT 1`, [cid])
  const row = r?.rows?.[0]
  if (!row) return

  const curChatNameEnc = dbBlobToWireEnvelope(row.chat_name_enc)
  const nextChatNameEnc = scrubRecipientFromEncryptedData(curChatNameEnc, uid)
  if (nextChatNameEnc !== curChatNameEnc) {
    await client.query(
      `UPDATE chats
       SET chat_name_enc = $1
       WHERE id = $2`,
      [wireEnvelopeToDbBlob(nextChatNameEnc), cid],
    )
  }

  const namesRows = await client.query(
    `SELECT subject_user_id, enc
     FROM chat_names_enc
     WHERE chat_id = $1`,
    [cid],
  )

  for (const n of namesRows.rows) {
    const subjectUserId = String(n.subject_user_id ?? '')
    if (!subjectUserId) continue

    if (subjectUserId === uid) {
      await client.query(
        `DELETE FROM chat_names_enc
         WHERE chat_id = $1 AND subject_user_id = $2`,
        [cid, subjectUserId],
      )
      continue
    }

    const cur = dbBlobToWireEnvelope(n.enc)
    const next = scrubRecipientFromEncryptedData(cur, uid)
    if (next !== cur) {
      await client.query(
        `UPDATE chat_names_enc
         SET enc = $1
         WHERE chat_id = $2 AND subject_user_id = $3`,
        [wireEnvelopeToDbBlob(next), cid, subjectUserId],
      )
    }
  }
}

export async function authCleanupExpiredUsers(now = new Date()) {
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

export async function authDeleteAccount(userId) {
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

export async function authListChats(userId) {
  const chats = await query(
    `SELECT c.id, c.chat_type, c.chat_name_enc
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
  const namesByChatId = await loadChatNamesByChatIds(chats.rows.map((c) => String(c.id)))

  return chats.rows
    .map((c) => {
    const id = String(c.id)
    const type = String(c.chat_type)
    const chatNameEnc = dbBlobToWireEnvelope(c.chat_name_enc)
    const names = namesByChatId[id] ?? {}
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

async function authLastMessagesForUserByChatIds(userId, chatIds) {
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
    encryptedData: dbBlobToWireEnvelope(row.encrypted_data),
    signature: typeof row.signature === 'string' ? String(row.signature) : '',
  }))
}

export async function authGetLastMessagesForChatIds(userId, chatIds, opts = {}) {
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

  const rows = await authLastMessagesForUserByChatIds(userId, unique)
  const byChatId = new Map(rows.map((m) => [String(m.chatId), m]))

  // Preserve caller order; chats with no messages get null.
  return list.map((cid) => byChatId.get(String(cid)) ?? null)
}

export async function authListChatsWithLastMessage(userId) {
  const chats = await authListChats(userId)
  const chatIds = chats.map((c) => c.id)
  const last = await authGetLastMessagesForChatIds(userId, chatIds, { enforceMembership: false })
  const lastByChatId = new Map(
    chatIds.map((cid, i) => [String(cid), last[i]]),
  )

  return chats.map((c) => ({
    ...c,
    lastMessage: lastByChatId.get(String(c.id)) ?? null,
  }))
}

export async function authUnreadCounts(userId) {
  const result = await query(
    `SELECT chat_id, COUNT(*)::int AS count
     FROM unread_messages
     WHERE user_id = $1
     GROUP BY chat_id`,
    [userId],
  )

  return result.rows.map((r) => ({ chatId: String(r.chat_id), count: Number(r.count) || 0 }))
}

export async function authCreatePersonalChat(userId, otherUserId, names) {
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

  let nameRows = []
  try {
    nameRows = normalizeChatNamesPayload(names)
  } catch {
    return { ok: false, reason: 'bad_payload' }
  }

  const created = await transaction(async (client) => {
    const chatRes = await client.query(
      `INSERT INTO chats (chat_type, chat_name_enc)
       VALUES ('personal', $1)
       RETURNING id`,
      [Buffer.alloc(0)],
    )

    const chatId = String(chatRes.rows[0].id)

    await client.query(
      `INSERT INTO chat_members (chat_id, user_id)
       VALUES ($1, $2), ($1, $3)`,
      [chatId, userId, otherId],
    )

    await replaceChatNamesForChat(client, chatId, nameRows)

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

export async function authCreateGroupChat(userId, chatNameEnc, names) {
  const enc = typeof chatNameEnc === 'string' ? chatNameEnc : ''
  if (!enc) return { ok: false, reason: 'bad_name' }
  if (enc.length > 100_000) return { ok: false, reason: 'bad_name' }
  let encBlob
  let nameRows = []
  try {
    encBlob = wireEnvelopeToDbBlob(enc)
    nameRows = normalizeChatNamesPayload(names)
  } catch {
    return { ok: false, reason: 'bad_payload' }
  }

  const chatId = await transaction(async (client) => {
    const chatRes = await client.query(
      `INSERT INTO chats (chat_type, chat_name_enc)
       VALUES ('group', $1)
       RETURNING id`,
      [encBlob],
    )

    const id = String(chatRes.rows[0].id)
    await client.query(
      `INSERT INTO chat_members (chat_id, user_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [id, String(userId)],
    )

    await replaceChatNamesForChat(client, id, nameRows)
    return id
  })

  return { ok: true, chat: { id: String(chatId), type: 'group', chatNameEnc: enc, names: (names && typeof names === 'object') ? names : {} } }
}

export async function authListChatMembers(userId, chatId) {
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

export async function authAddGroupMember(userId, chatId, otherUserId, names, chatNameEnc) {
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

  let nameRows = []
  let nextChatNameEnc = null
  try {
    nameRows = normalizeChatNamesPayload(names)
    nextChatNameEnc = typeof chatNameEnc === 'string' ? wireEnvelopeToDbBlob(chatNameEnc) : null
  } catch {
    return { ok: false, reason: 'bad_payload' }
  }

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

  await transaction(async (client) => {
    await client.query(
      `UPDATE chats
       SET chat_name_enc = COALESCE($1, chat_name_enc)
       WHERE id = $2`,
      [nextChatNameEnc, String(chatId)],
    )
    await replaceChatNamesForChat(client, String(chatId), nameRows)
  })

  return {
    ok: true,
    member: { userId: otherId, publicKey: String(other.public_key) },
  }
}

export async function authRenameGroupChat(userId, chatId, chatNameEnc) {
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
  let encBlob
  try {
    encBlob = wireEnvelopeToDbBlob(enc)
  } catch {
    return { ok: false, reason: 'bad_payload' }
  }

  await query(
    `UPDATE chats
     SET chat_name_enc = $1
     WHERE id = $2`,
    [encBlob, chatId],
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

export async function authFetchMessages(userId, chatId, limit = 50, beforeId = null) {
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
    encryptedData: dbBlobToWireEnvelope(row.encrypted_data),
    signature: typeof row.signature === 'string' ? String(row.signature) : '',
  }))
}

export async function authSendMessage({ senderId, chatId, encryptedData, signature = '' }) {
  await assertChatMember(senderId, chatId)
  let encBlob
  try {
    encBlob = wireEnvelopeToDbBlob(encryptedData)
  } catch (e) {
    const err = new Error('bad_payload')
    err.code = 'bad_payload'
    throw err
  }

  const messageId = uuidv7()

  const result = await transaction(async (client) => {
    await client.query(
      `INSERT INTO messages (id, chat_id, encrypted_data, signature, sender_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [messageId, chatId, encBlob, String(signature || ''), senderId],
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

export async function authMarkChatRead(userId, chatId) {
  await assertChatMember(userId, chatId)
  await query(
    `DELETE FROM unread_messages
     WHERE user_id = $1 AND chat_id = $2`,
    [userId, chatId],
  )
}

export async function authMarkMessagesRead(userId, chatId, messageIds) {
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

export async function authUnreadMessageIds(userId, chatId, limit = 500) {
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

export async function authDeleteMessage({ userId, chatId, messageId }) {
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

export async function authUpdateMessage({ userId, chatId, messageId, encryptedData, signature = '' }) {
  await assertChatMember(userId, chatId)
  const enc = typeof encryptedData === 'string' ? encryptedData : ''
  if (!enc) return { ok: false, reason: 'bad_payload' }
  let encBlob
  try {
    encBlob = wireEnvelopeToDbBlob(enc)
  } catch {
    return { ok: false, reason: 'bad_payload' }
  }

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
      [encBlob, String(signature || ''), String(messageId), String(chatId)],
    )

    return { ok: true, memberIds }
  })

  return result
}

export async function authLeaveChat(userId, chatId) {
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

export async function authDeletePersonalChat(userId, chatId) {
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
