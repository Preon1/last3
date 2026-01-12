import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { notify } from '../utils/notify'
import { tryGetWebPushSubscriptionJson } from '../utils/push'
import {
  broadcastAppStateToServiceWorker,
  closeAllNotifications,
  closeNotificationsByTag,
  getNotificationsEnabled,
  setNotificationsEnabled,
} from '../utils/notificationPrefs'
import {
  decryptPrivateKeyJwk,
  decryptSignedMessage,
  decryptStringWithPassword,
  encryptPrivateKeyJwk,
  encryptSignedMessage,
  encryptStringWithPassword,
  generateRsaKeyPair,
  importRsaPrivateKeyJwk,
  publicJwkFromPrivateJwk,
} from '../utils/signedCrypto'

export type SignedChat = {
  id: string
  type: 'personal' | 'group'
  name?: string
  otherUserId?: string
  otherUsername?: string
  otherPublicKey?: string
}

export type SignedLastMessageWire = {
  id: string
  chatId: string
  senderId: string
  senderUsername?: string
  encryptedData: string
}

export type SignedLastMessagePreview = {
  id: string
  chatId: string
  senderId: string
  senderUsername: string
  tsMs: number
  text: string
}

export type SignedChatMember = {
  userId: string
  username: string
  publicKey: string
}

export type SignedMessage = {
  id: string
  chatId: string
  senderId: string
  senderUsername?: string
  encryptedData: string
}

export type SignedDecryptedMessage = {
  id: string
  chatId: string
  senderId: string
  atIso: string
  modifiedAtIso?: string | null
  fromUsername: string
  text: string
  replyToId?: string | null
}

function apiBase() {
  return ''
}

function wsSignedUrl(token: string) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}/signed?token=${encodeURIComponent(token)}`
}

const LS_KEYS = 'lrcom-signed-keys'
const LS_LEGACY_KEY = 'lrcom-signed-key'
const SS_TOKEN = 'lrcom-signed-token'
const SS_USER = 'lrcom-signed-user'
const SS_EXPIRES_AT = 'lrcom-signed-expires-at'
const SS_LAST_USERNAME = 'lrcom-signed-last-username'
const SS_ADD_USERNAME = 'lrcom-add-username'

const MAX_PASSWORD_LEN = 512

const MAX_ENCRYPTED_MESSAGE_BYTES = 50 * 1024
const ERR_ENCRYPTED_TOO_LARGE = 'Encrypted message too large'

function uuidV7ToUnixMs(id: string): number | null {
  const hex = String(id).replace(/-/g, '')
  if (hex.length < 12) return null
  const tsHex = hex.slice(0, 12)
  if (!/^[0-9a-fA-F]{12}$/.test(tsHex)) return null
  const ms = Number.parseInt(tsHex, 16)
  return Number.isFinite(ms) ? ms : null
}

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length
}

type StoredKeyV2 = {
  v: 2
  encryptedUsername: string
  encryptedPrivateKey: string
}

type LegacyStoredKeyV1 = {
  username: string
  publicKeyJwk: string
  encryptedPrivateKey: string
}

type StoredUser = {
  userId: string
  username: string
  hiddenMode?: boolean
  introvertMode?: boolean
}

export const useSignedStore = defineStore('signed', () => {
  const token = ref<string | null>(null)
  const expiresAtMs = ref<number | null>(null)
  const userId = ref<string | null>(null)
  const username = ref<string | null>(null)
  const hiddenMode = ref<boolean>(false)
  const introvertMode = ref<boolean>(false)
  const publicKeyJwk = ref<string | null>(null)
  const privateKey = ref<CryptoKey | null>(null)

  const notificationsEnabled = ref<boolean>(getNotificationsEnabled())

  const lastUsername = ref<string>('')

  const pendingAddUsername = ref<string>('')

  const ws = ref<WebSocket | null>(null)
  const wsShouldReconnect = ref(false)
  const wsReconnectAttempt = ref(0)
  let wsReconnectTimer: number | null = null

  const turnConfig = ref<any | null>(null)

  const inboundHandlers: Array<(type: string, obj: Record<string, unknown>) => void> = []
  const disconnectHandlers: Array<() => void> = []

  const view = ref<'contacts' | 'chat' | 'settings'>('contacts')
  const activeChatId = ref<string | null>(null)

  const chats = ref<SignedChat[]>([])
  const unreadByChatId = ref<Record<string, number>>({})

  const lastMessageByChatId = ref<Record<string, SignedLastMessageWire | null>>({})
  const lastMessagePreviewByChatId = ref<Record<string, SignedLastMessagePreview>>({})

  const membersByChatId = ref<Record<string, SignedChatMember[]>>({})

  const messagesByChatId = ref<Record<string, SignedDecryptedMessage[]>>({})

  const messagesOldestIdByChatId = ref<Record<string, string>>({})
  const messagesHasMoreByChatId = ref<Record<string, boolean>>({})
  const messagesLoadingMoreByChatId = ref<Record<string, boolean>>({})

  const onlineByUserId = ref<Record<string, boolean>>({})
  const busyByUserId = ref<Record<string, boolean>>({})
  let presenceTimer: number | null = null

  const signedIn = computed(() => Boolean(token.value && userId.value && username.value))
  async function syncAppStateToServiceWorker() {
    try {
      const foreground = typeof document !== 'undefined' && document.visibilityState === 'visible'
      await broadcastAppStateToServiceWorker({ foreground, view: view.value })

      if (foreground && view.value === 'contacts') {
        await closeAllNotifications()
      }
    } catch {
      // ignore
    }
  }

  // Keep SW aware of whether it should suppress push while user is in-app.
  watch(
    () => view.value,
    () => {
      void syncAppStateToServiceWorker()
    },
    { immediate: true },
  )

  try {
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        void syncAppStateToServiceWorker()
      })
    }
  } catch {
    // ignore
  }

  let tokenRefreshTimer: number | null = null

  function clearPresenceTimer() {
    if (presenceTimer != null) {
      try {
        window.clearInterval(presenceTimer)
      } catch {
        // ignore
      }
      presenceTimer = null
    }
  }

  function clearTokenRefreshTimer() {
    if (tokenRefreshTimer != null) {
      try {
        window.clearTimeout(tokenRefreshTimer)
      } catch {
        // ignore
      }
      tokenRefreshTimer = null
    }
  }

  function scheduleTokenRefresh() {
    clearTokenRefreshTimer()
    if (!token.value) return
    if (!expiresAtMs.value) return

    const now = Date.now()
    const refreshAt = expiresAtMs.value - 5 * 60 * 1000
    const delay = Math.max(30_000, refreshAt - now)

    tokenRefreshTimer = window.setTimeout(() => {
      void refreshSessionToken()
    }, delay)
  }

  async function refreshSessionToken() {
    if (!token.value) return

    try {
      const r = await fetch(`${apiBase()}/api/signed/session/refresh`, {
        method: 'POST',
        headers: { ...authHeaders() },
      })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) {
        if (r.status === 401) logout()
        return
      }

      const nextToken = typeof (j as any)?.token === 'string' ? String((j as any).token) : null
      const nextExpires = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
      if (!nextToken || !nextExpires) return

      token.value = nextToken
      expiresAtMs.value = nextExpires

      if (token.value && userId.value && username.value) {
        storeSession(
          { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
          token.value,
          expiresAtMs.value,
        )
      }

      await connectWs()
      scheduleTokenRefresh()
    } catch {
      // ignore
    }
  }

  function setNotificationsEnabledLocal(next: boolean) {
    notificationsEnabled.value = Boolean(next)
    setNotificationsEnabled(Boolean(next))
  }

  async function trySyncPushSubscription() {
    if (!token.value) return false
    if (!notificationsEnabled.value) return false
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return false

    const subscription = await tryGetWebPushSubscriptionJson()
    if (!subscription) return false

    try {
      await fetchJson('/api/signed/push/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ subscription }),
      })
      return true
    } catch {
      return false
    }
  }

  async function disablePushSubscription() {
    try {
      if (!('serviceWorker' in navigator)) return
      const reg = await navigator.serviceWorker.ready
      const sub = await reg.pushManager.getSubscription()
      if (sub) await sub.unsubscribe()
    } catch {
      // ignore
    }
  }

  async function refreshPresence() {
    if (!token.value || !userId.value) return

    // Privacy + load: presence can only be requested for correspondents in
    // personal chats. If we're actively viewing a personal chat, request only
    // the current correspondent.
    const list: string[] = []

    if (view.value === 'chat' && activeChatId.value) {
      const c = chats.value.find((x) => x.id === activeChatId.value) ?? null
      if (c?.type === 'personal' && c.otherUserId) list.push(String(c.otherUserId))
    }

    if (!list.length) {
      const ids = new Set<string>()
      for (const c of chats.value) {
        if (c.type === 'personal' && c.otherUserId) ids.add(String(c.otherUserId))
      }
      list.push(...Array.from(ids))
    }

    if (!list.length) {
      onlineByUserId.value = {}
      return
    }

    try {
      const j = await fetchJson('/api/signed/presence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ userIds: list }),
      })

      const online = new Set<string>(Array.isArray(j?.onlineUserIds) ? j.onlineUserIds.map(String) : [])
      const busy = new Set<string>(Array.isArray(j?.busyUserIds) ? j.busyUserIds.map(String) : [])
      const next: Record<string, boolean> = {}
      const nextBusy: Record<string, boolean> = {}
      for (const id of list) next[id] = online.has(id)
      for (const id of list) nextBusy[id] = busy.has(id)
      onlineByUserId.value = next
      busyByUserId.value = nextBusy
    } catch {
      // ignore
    }
  }

  function startPresencePolling() {
    clearPresenceTimer()
    // Polling keeps this simple and avoids leaking global online lists.
    presenceTimer = window.setInterval(() => {
      void refreshPresence()
    }, 10000)
    void refreshPresence()
  }

  function getChatOnlineState(chatId: string): 'online' | 'offline' | 'busy' | null {
    const c = chats.value.find((x) => x.id === chatId)
    if (!c) return null
    if (c.type === 'personal') {
      const id = c.otherUserId
      if (!id) return null
      if (busyByUserId.value[id]) return 'busy'
      return onlineByUserId.value[id] ? 'online' : 'offline'
    }

    // Group: best-effort based on cached members only.
    const members = membersByChatId.value[chatId]
    if (!Array.isArray(members) || !members.length) return null
    let anyOnline = false
    let anyBusy = false
    for (const m of members) {
      if (!m?.userId) continue
      const id = String(m.userId)
      if (busyByUserId.value[id]) anyBusy = true
      if (onlineByUserId.value[id]) anyOnline = true
    }
    if (anyBusy) return 'busy'
    return anyOnline ? 'online' : 'offline'
  }

  const otherChatsUnread = computed(() => {
    let n = 0
    const active = activeChatId.value
    for (const [cid, count] of Object.entries(unreadByChatId.value)) {
      if (active && cid === active) continue
      n += count
    }
    return n
  })

  function authHeaders() {
    const h: Record<string, string> = {}
    if (token.value) h.Authorization = `Bearer ${token.value}`
    return h
  }

  function clearWsReconnectTimer() {
    if (wsReconnectTimer != null) {
      try {
        window.clearTimeout(wsReconnectTimer)
      } catch {
        // ignore
      }
      wsReconnectTimer = null
    }
  }

  async function syncAfterConnect() {
    // Best-effort: resync unread counts and refresh current chat.
    if (!token.value) return
    try {
      await refreshChats()
    } catch {
      // ignore
    }

    const cid = activeChatId.value
    if (view.value === 'chat' && cid) {
      try {
        // Pull more history on reconnect in case we missed WS events.
        await loadMessages(cid, 200)
      } catch {
        // ignore
      }
    }
  }

  function scheduleWsReconnect() {
    if (!wsShouldReconnect.value) return
    if (!token.value) return
    if (!privateKey.value) return

    const maxAttempts = 3
    if (wsReconnectAttempt.value >= maxAttempts) return

    clearWsReconnectTimer()
    const attempt = wsReconnectAttempt.value + 1
    wsReconnectAttempt.value = attempt

    wsReconnectTimer = window.setTimeout(() => {
      void connectWs()
    }, 1000)
  }

  function loadKeyEntries(): StoredKeyV2[] {
    try {
      const raw = localStorage.getItem(LS_KEYS)
      if (!raw) return []
      const arr = JSON.parse(raw)
      if (!Array.isArray(arr)) return []
      const out: StoredKeyV2[] = []
      for (const it of arr) {
        if (it && it.v === 2 && typeof it.encryptedUsername === 'string' && typeof it.encryptedPrivateKey === 'string') {
          out.push({ v: 2, encryptedUsername: it.encryptedUsername, encryptedPrivateKey: it.encryptedPrivateKey })
        }
      }
      return out
    } catch {
      return []
    }
  }

  function saveKeyEntries(next: StoredKeyV2[]) {
    try {
      localStorage.setItem(LS_KEYS, JSON.stringify(next))
    } catch {
      // ignore
    }
  }

  function loadLegacyKeyMaterial(): LegacyStoredKeyV1 | null {
    try {
      const raw = localStorage.getItem(LS_LEGACY_KEY)
      if (!raw) return null
      const k = JSON.parse(raw)
      if (!k?.username || !k?.publicKeyJwk || !k?.encryptedPrivateKey) return null
      return { username: String(k.username), publicKeyJwk: String(k.publicKeyJwk), encryptedPrivateKey: String(k.encryptedPrivateKey) }
    } catch {
      return null
    }
  }

  function clearAllKeyMaterial() {
    try {
      localStorage.removeItem(LS_KEYS)
      localStorage.removeItem(LS_LEGACY_KEY)
    } catch {
      // ignore
    }
  }

  async function saveLocalKeyForUser(params: { username: string; password: string; encryptedPrivateKey: string; extraEntropy?: Uint8Array }) {
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)
    const encryptedUsername = await encryptStringWithPassword({ plaintext: params.username, password: params.password, extraEntropy: params.extraEntropy })

    const cur = loadKeyEntries()
    const kept: StoredKeyV2[] = []
    for (const e of cur) {
      try {
        const u = await decryptStringWithPassword({ encrypted: e.encryptedUsername, password: params.password })
        if (u === params.username) continue
      } catch {
        // If it can't be decrypted with this password, keep it.
      }
      kept.push(e)
    }

    kept.push({ v: 2, encryptedUsername, encryptedPrivateKey: params.encryptedPrivateKey })
    saveKeyEntries(kept)

    // Remove legacy plaintext storage once password is known.
    try {
      localStorage.removeItem(LS_LEGACY_KEY)
    } catch {
      // ignore
    }
  }

  async function findEncryptedPrivateKeyForLogin(params: { username: string; password: string }) {
    const list = loadKeyEntries()
    for (const e of list) {
      try {
        const u = await decryptStringWithPassword({ encrypted: e.encryptedUsername, password: params.password })
        if (u === params.username) return e.encryptedPrivateKey
      } catch {
        // ignore
      }
    }

    const legacy = loadLegacyKeyMaterial()
    if (legacy && legacy.username === params.username) return legacy.encryptedPrivateKey
    return null
  }

  function storeSession(u: StoredUser, t: string, expiresAt?: number | null) {
    try {
      sessionStorage.setItem(SS_TOKEN, t)
      sessionStorage.setItem(SS_USER, JSON.stringify(u))
      if (typeof expiresAt === 'number' && Number.isFinite(expiresAt)) sessionStorage.setItem(SS_EXPIRES_AT, String(expiresAt))
      else sessionStorage.removeItem(SS_EXPIRES_AT)
    } catch {
      // ignore
    }
  }

  function loadSession(): { u: StoredUser; t: string; e: number | null } | null {
    try {
      const t = sessionStorage.getItem(SS_TOKEN)
      const rawU = sessionStorage.getItem(SS_USER)
      if (!t || !rawU) return null
      const u = JSON.parse(rawU) as StoredUser
      if (!u?.userId || !u?.username) return null
      const rawE = sessionStorage.getItem(SS_EXPIRES_AT)
      const e = rawE != null && rawE.trim() ? Number(rawE) : null
      return { u, t, e: Number.isFinite(e as number) ? (e as number) : null }
    } catch {
      return null
    }
  }

  function clearSession() {
    try {
      sessionStorage.removeItem(SS_TOKEN)
      sessionStorage.removeItem(SS_USER)
      sessionStorage.removeItem(SS_EXPIRES_AT)
    } catch {
      // ignore
    }
  }

  function loadLastUsername(): string {
    try {
      const v = sessionStorage.getItem(SS_LAST_USERNAME)
      return (v ?? '').trim()
    } catch {
      return ''
    }
  }

  function storeLastUsername(u: string) {
    const v = (u ?? '').trim()
    lastUsername.value = v
    try {
      if (v) sessionStorage.setItem(SS_LAST_USERNAME, v)
      else sessionStorage.removeItem(SS_LAST_USERNAME)
    } catch {
      // ignore
    }
  }

  function loadPendingAddUsername(): string {
    try {
      return String(sessionStorage.getItem(SS_ADD_USERNAME) ?? '').trim()
    } catch {
      return ''
    }
  }

  function storePendingAddUsername(u: string) {
    const v = String(u ?? '').trim()
    pendingAddUsername.value = v
    try {
      if (v) sessionStorage.setItem(SS_ADD_USERNAME, v)
      else sessionStorage.removeItem(SS_ADD_USERNAME)
    } catch {
      // ignore
    }
  }

  function capturePendingAddFromUrl() {
    try {
      const qs = new URLSearchParams(location.search)
      const u = String(qs.get('add') ?? '').trim()
      if (!u) return
      // Basic sanity bounds (matches server username max).
      if (u.length > 64) return
      storePendingAddUsername(u)
    } catch {
      // ignore
    }
  }

  function cleanAddParamFromUrl() {
    try {
      const qs = new URLSearchParams(location.search)
      if (!qs.has('add')) return
      qs.delete('add')
      const next = qs.toString()
      const url = `${location.pathname}${next ? `?${next}` : ''}${location.hash || ''}`
      history.replaceState(null, '', url)
    } catch {
      // ignore
    }
  }

  async function maybeAddChatFromUrl() {
    const target = String(pendingAddUsername.value ?? '').trim()
    if (!target) return
    if (!token.value) return

    try {
      // Avoid attempting to add yourself.
      if (username.value && target.toLowerCase() === String(username.value).toLowerCase()) return
      await createPersonalChat(target)
    } catch {
      // ignore (not found / introvert / etc)
    } finally {
      storePendingAddUsername('')
      cleanAddParamFromUrl()
    }
  }

  async function unlock(params: { password: string }) {
    const u = (username.value ?? '').trim()
    if (!u) throw new Error('Username required')
    if (!params.password) throw new Error('Password required')
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    const encryptedPrivateKey = await findEncryptedPrivateKeyForLogin({ username: u, password: params.password })
    if (!encryptedPrivateKey) throw new Error('No local key found')

    const privateJwk = await decryptPrivateKeyJwk({ encrypted: encryptedPrivateKey, password: params.password })
    privateKey.value = await importRsaPrivateKeyJwk(privateJwk)
    publicKeyJwk.value = publicJwkFromPrivateJwk(privateJwk)

    // Now that the password is known, ensure we persist only the low-profile entry.
    await saveLocalKeyForUser({ username: u, password: params.password, encryptedPrivateKey })

    // After unlock: load server state and connect realtime.
    if (token.value) {
      await refreshChats()
      await connectWs()
      void maybeAddChatFromUrl()
      void maybeOpenChatFromUrl()
      scheduleTokenRefresh()
      void trySyncPushSubscription()
    }
  }

  async function maybeOpenChatFromUrl() {
    try {
      const qs = new URLSearchParams(location.search)
      const chatId = (qs.get('chatId') ?? '').trim()
      if (!chatId) return

      // Remove the param immediately to avoid re-open loops on reload.
      try {
        qs.delete('chatId')
        const next = qs.toString()
        const url = `${location.pathname}${next ? `?${next}` : ''}${location.hash || ''}`
        history.replaceState(null, '', url)
      } catch {
        // ignore
      }

      const exists = chats.value.some((c) => String(c.id) === String(chatId))
      if (!exists) return
      await openChat(chatId)
    } catch {
      // ignore
    }
  }

  async function fetchJson(path: string, init?: RequestInit) {
    const r = await fetch(`${apiBase()}${path}`, init)
    const j = await r.json().catch(() => ({}))
    if (!r.ok) {
      if (r.status === 401) {
        const msg = typeof j?.error === 'string' ? j.error : 'Unauthorized'

        // If we had a token, it likely expired / server restarted (tokens are in-memory).
        // For login/register (no token yet), don't clear local state.
        if (token.value) {
          try {
            logout()
          } catch {
            // ignore
          }
        }

        throw new Error(msg)
      }
      const msg = typeof j?.error === 'string' ? j.error : 'Request failed'
      throw new Error(msg)
    }
    return j
  }

  function registerInboundHandler(handler: (type: string, obj: Record<string, unknown>) => void) {
    inboundHandlers.push(handler)
  }

  function registerDisconnectHandler(handler: () => void) {
    disconnectHandlers.push(handler)
  }

  function sendWs(obj: unknown) {
    try {
      if (!ws.value || ws.value.readyState !== WebSocket.OPEN) return
      ws.value.send(JSON.stringify(obj))
    } catch {
      // ignore
    }
  }

  async function ensureTurnConfig() {
    if (turnConfig.value) return turnConfig.value
    try {
      const j = await fetchJson('/turn')
      turnConfig.value = j
      return j
    } catch {
      // ignore
      return null
    }
  }

  async function connectWs() {
    wsShouldReconnect.value = true
    clearWsReconnectTimer()
    disconnectWs()
    if (!token.value) return

    const sock = new WebSocket(wsSignedUrl(token.value))
    ws.value = sock

    sock.addEventListener('open', () => {
      wsReconnectAttempt.value = 0
      startPresencePolling()
      void syncAfterConnect()
      void trySyncPushSubscription()
    })

    sock.addEventListener('close', () => {
      ws.value = null
      clearPresenceTimer()
      for (const h of disconnectHandlers) {
        try {
          h()
        } catch {
          // ignore
        }
      }
      scheduleWsReconnect()
    })

    sock.addEventListener('error', () => {
      // no logs
      clearPresenceTimer()
      scheduleWsReconnect()
    })

    sock.addEventListener('message', async (ev) => {
      let obj: any
      try {
        obj = JSON.parse(String(ev.data))
      } catch {
        return
      }
      if (!obj || typeof obj.type !== 'string') return

      if (obj.type === 'signedMessage') {
        const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
        const id = typeof obj.id === 'string' ? obj.id : null
        const senderId = typeof obj.senderId === 'string' ? obj.senderId : null
        const senderUsername = typeof obj.senderUsername === 'string' ? obj.senderUsername : null
        const encryptedData = typeof obj.encryptedData === 'string' ? obj.encryptedData : null
        if (!chatId || !id || !senderId || !encryptedData) return

        if (privateKey.value && userId.value) {
          try {
            const plain = await decryptSignedMessage({ encryptedData, myUserId: userId.value, myPrivateKey: privateKey.value })
            const displayName =
              senderUsername ??
              membersByChatId.value[chatId]?.find((m) => String(m.userId) === String(senderId))?.username ??
              String(senderId)
            const msg: SignedDecryptedMessage = {
              id,
              chatId,
              atIso: plain.atIso,
              modifiedAtIso: plain.modifiedAtIso,
              senderId,
              fromUsername: displayName,
              text: plain.text,
              replyToId: plain.replyToId,
            }

            const cur = messagesByChatId.value[chatId] ?? []
            if (cur.some((m) => m.id === id)) return
            messagesByChatId.value = { ...messagesByChatId.value, [chatId]: [...cur, msg] }

            // Unread bump if not currently viewing this chat.
            if (!(view.value === 'chat' && activeChatId.value === chatId)) {
              unreadByChatId.value = {
                ...unreadByChatId.value,
                [chatId]: (unreadByChatId.value[chatId] ?? 0) + 1,
              }

              try {
                const shouldNotify = typeof document !== 'undefined' && document.visibilityState !== 'visible'
                if (shouldNotify) {
                  notify('Last', senderUsername ? `New message from ${senderUsername}` : 'New message', {
                    tag: `lrcom-chat-${String(chatId)}`,
                  })
                }
              } catch {
                // ignore
              }
            }

            // Best-effort: keep chat list previews fresh.
            lastMessageByChatId.value = {
              ...lastMessageByChatId.value,
              [chatId]: { id, chatId, senderId, senderUsername: senderUsername ?? displayName, encryptedData },
            }
            lastMessagePreviewByChatId.value = {
              ...lastMessagePreviewByChatId.value,
              [chatId]: {
                id,
                chatId,
                senderId,
                senderUsername: senderUsername ?? displayName,
                tsMs: uuidV7ToUnixMs(id) ?? 0,
                text: plain.text,
              },
            }
          } catch {
            // ignore decrypt failures
          }
        }
      }

      if (obj.type === 'signedMessageDeleted') {
        const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
        const id = typeof obj.id === 'string' ? obj.id : null
        if (!chatId || !id) return

        const cur = messagesByChatId.value[chatId] ?? []
        if (cur.length) {
          messagesByChatId.value = { ...messagesByChatId.value, [chatId]: cur.filter((m) => m.id !== id) }
        }
        // Best-effort refresh counts; deletion may clear unread for others via cascade.
        void refreshChats()
      }

      if (obj.type === 'signedMessagesDeleted') {
        const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
        const idsRaw = (obj as any).ids
        const ids = Array.isArray(idsRaw) ? idsRaw.map(String).filter(Boolean) : []
        if (!chatId || !ids.length) return

        const cur = messagesByChatId.value[chatId] ?? []
        if (cur.length) {
          const s = new Set(ids)
          const hasAny = cur.some((m) => s.has(m.id))
          if (hasAny) {
            messagesByChatId.value = { ...messagesByChatId.value, [chatId]: cur.filter((m) => !s.has(m.id)) }
          }
        }
        void refreshChats()
      }

      if (obj.type === 'signedMessageUpdated') {
        const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
        const id = typeof obj.id === 'string' ? obj.id : null
        const senderId = typeof obj.senderId === 'string' ? obj.senderId : null
        const senderUsername = typeof obj.senderUsername === 'string' ? obj.senderUsername : null
        const encryptedData = typeof obj.encryptedData === 'string' ? obj.encryptedData : null
        if (!chatId || !id || !senderId || !encryptedData) return

        if (privateKey.value && userId.value) {
          try {
            const plain = await decryptSignedMessage({ encryptedData, myUserId: userId.value, myPrivateKey: privateKey.value })
            const displayName =
              senderUsername ??
              membersByChatId.value[chatId]?.find((m) => String(m.userId) === String(senderId))?.username ??
              String(senderId)
            const cur = messagesByChatId.value[chatId] ?? []
            const next = cur.map((m) =>
              m.id === id
                ? {
                    ...m,
                    atIso: plain.atIso,
                    modifiedAtIso: plain.modifiedAtIso,
                    senderId,
                    fromUsername: displayName,
                    text: plain.text,
                    replyToId: plain.replyToId,
                  }
                : m,
            )
            messagesByChatId.value = { ...messagesByChatId.value, [chatId]: next }

            if (lastMessageByChatId.value[chatId]?.id === id) {
              lastMessageByChatId.value = {
                ...lastMessageByChatId.value,
                [chatId]: { id, chatId, senderId, senderUsername: senderUsername ?? displayName, encryptedData },
              }
              lastMessagePreviewByChatId.value = {
                ...lastMessagePreviewByChatId.value,
                [chatId]: {
                  id,
                  chatId,
                  senderId,
                  senderUsername: senderUsername ?? displayName,
                  tsMs: uuidV7ToUnixMs(id) ?? 0,
                  text: plain.text,
                },
              }
            }
          } catch {
            // ignore
          }
        }
      }

      if (obj.type === 'signedChatDeleted') {
        const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
        if (chatId) removeChatLocal(chatId)
      }

      if (obj.type === 'signedChatsChanged') {
        // Best-effort: refresh the chat list when membership changes or a new
        // chat is created on the other side.
        void refreshChats()
      }

      // Forward all inbound messages to registered handlers (e.g. voice calls).
      for (const h of inboundHandlers) {
        try {
          h(String(obj.type), obj as Record<string, unknown>)
        } catch {
          // ignore
        }
      }
    })
  }

  function disconnectWs() {
    // Callers can disable reconnect by setting wsShouldReconnect=false before disconnect.
    try {
      ws.value?.close()
    } catch {
      // ignore
    }
    ws.value = null
    clearPresenceTimer()
    for (const h of disconnectHandlers) {
      try {
        h()
      } catch {
        // ignore
      }
    }
  }

  async function refreshChats() {
    const j = await fetchJson('/api/signed/chats', { headers: { ...authHeaders() } })
    const nextChats: SignedChat[] = Array.isArray(j.chats) ? j.chats : []
    chats.value = nextChats

    // New server versions may include `lastMessage` on each chat.
    const nextLast: Record<string, SignedLastMessageWire | null> = {}
    if (Array.isArray((j as any)?.chats)) {
      for (const c of (j as any).chats) {
        const chatId = typeof c?.id === 'string' ? String(c.id) : ''
        if (!chatId) continue
        const lm = c?.lastMessage
        if (!lm) {
          nextLast[chatId] = null
          continue
        }
        const id = typeof lm?.id === 'string' ? String(lm.id) : ''
        const senderId = typeof lm?.senderId === 'string' ? String(lm.senderId) : ''
        const encryptedData = typeof lm?.encryptedData === 'string' ? String(lm.encryptedData) : ''
        const senderUsername = typeof lm?.senderUsername === 'string' ? String(lm.senderUsername) : ''

        if (!id || !senderId || !encryptedData) {
          nextLast[chatId] = null
          continue
        }

        nextLast[chatId] = { id, chatId, senderId, senderUsername, encryptedData }
      }
    }
    lastMessageByChatId.value = nextLast

    // Best-effort: decrypt last-message previews for the chat list.
    if (privateKey.value && userId.value) {
      const entries = Object.entries(nextLast)
      const previews = await Promise.all(
        entries.map(async ([chatId, lm]) => {
          if (!lm) return null
          try {
            const plain = await decryptSignedMessage({
              encryptedData: lm.encryptedData,
              myUserId: userId.value as string,
              myPrivateKey: privateKey.value as CryptoKey,
            })
            const tsMs = uuidV7ToUnixMs(lm.id) ?? 0
            const text = typeof plain?.text === 'string' ? plain.text : ''
            const preview: SignedLastMessagePreview = {
              id: lm.id,
              chatId,
              senderId: lm.senderId,
              senderUsername: lm.senderUsername ?? '',
              tsMs,
              text,
            }
            return { chatId, preview }
          } catch {
            return null
          }
        }),
      )

      const nextPreview: Record<string, SignedLastMessagePreview> = {}
      for (const p of previews) {
        if (!p) continue
        nextPreview[p.chatId] = p.preview
      }
      lastMessagePreviewByChatId.value = nextPreview
    } else {
      lastMessagePreviewByChatId.value = {}
    }

    const unread: Record<string, number> = {}
    if (Array.isArray(j.unread)) {
      for (const u of j.unread) {
        if (u && typeof u.chatId === 'string' && typeof u.count === 'number') unread[u.chatId] = u.count
      }
    }
    unreadByChatId.value = unread
  }

  function getChat(chatId: string): SignedChat | null {
    const c = chats.value.find((x) => x.id === chatId)
    return c ?? null
  }

  function getChatLastMessagePreview(chatId: string): SignedLastMessagePreview | null {
    return lastMessagePreviewByChatId.value[chatId] ?? null
  }

  function getChatLastMessageTsMs(chatId: string): number {
    return getChatLastMessagePreview(chatId)?.tsMs ?? 0
  }

  async function fetchChatMembers(chatId: string) {
    const j = await fetchJson(`/api/signed/chats/members?chatId=${encodeURIComponent(chatId)}`, {
      headers: { ...authHeaders() },
    })

    const list: SignedChatMember[] = Array.isArray(j.members)
      ? j.members
          .filter((m: any) => m && typeof m.userId === 'string' && typeof m.username === 'string' && typeof m.publicKey === 'string')
          .map((m: any) => ({ userId: String(m.userId), username: String(m.username), publicKey: String(m.publicKey) }))
      : []

    membersByChatId.value = { ...membersByChatId.value, [chatId]: list }
    return list
  }

  async function ensureChatMembers(chatId: string) {
    const cached = membersByChatId.value[chatId]
    if (Array.isArray(cached) && cached.length) return cached
    return fetchChatMembers(chatId)
  }

  async function openChat(chatId: string) {
    activeChatId.value = chatId
    view.value = 'chat'

    // Best-effort: clear any notification for this chat.
    void closeNotificationsByTag(`lrcom-chat-${String(chatId)}`)

    await loadMessages(chatId)

    // Best-effort: prefetch group members so we can encrypt to all.
    try {
      const chat = getChat(chatId)
      if (chat?.type === 'group') await ensureChatMembers(chatId)
    } catch {
      // ignore
    }
  }

  async function markMessagesRead(chatId: string, messageIds: string[]) {
    if (!token.value) return
    const ids = Array.isArray(messageIds) ? messageIds.map(String).filter(Boolean) : []
    if (!ids.length) return
    try {
      const j = await fetchJson('/api/signed/messages/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ chatId, messageIds: ids }),
      })
      const next = typeof j?.unreadCount === 'number' ? j.unreadCount : null
      if (next != null) unreadByChatId.value = { ...unreadByChatId.value, [chatId]: Math.max(0, next) }

      // Best-effort: if user read it, close any delivered push notification.
      void closeNotificationsByTag(`lrcom-chat-${String(chatId)}`)
    } catch {
      // ignore
    }
  }

  async function listUnreadMessageIds(chatId: string, limit = 500) {
    const j = await fetchJson(`/api/signed/messages/unread?chatId=${encodeURIComponent(chatId)}&limit=${encodeURIComponent(String(limit))}`, {
      headers: { ...authHeaders() },
    })
    return Array.isArray(j?.messageIds) ? j.messageIds.map(String) : []
  }

  async function deleteMessage(chatId: string, messageId: string) {
    await fetchJson('/api/signed/messages/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, messageId }),
    })
  }

  async function updateMessage(chatId: string, messageId: string, encryptedData: string) {
    if (utf8ByteLength(encryptedData) > MAX_ENCRYPTED_MESSAGE_BYTES) throw new Error(ERR_ENCRYPTED_TOO_LARGE)
    await fetchJson('/api/signed/messages/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, messageId, encryptedData }),
    })
  }

  async function updateMessageText(chatId: string, messageId: string, text: string) {
    const t = text.trim()
    if (!t) return
    if (!userId.value || !username.value || !publicKeyJwk.value) throw new Error('Not logged in')

    const chat = chats.value.find((c) => c.id === chatId)
    if (!chat) throw new Error('Chat not found')

    const cur = messagesByChatId.value[chatId] ?? []
    const existing = cur.find((m) => m.id === messageId) ?? null
    const atIso = existing?.atIso ?? new Date().toISOString()
    const modifiedAtIso = new Date().toISOString()
    const replyToId = existing?.replyToId ?? null

    let recipients: Array<{ userId: string; publicKeyJwk: string }> = []

    if (chat.type === 'personal') {
      if (!chat.otherUserId || !chat.otherPublicKey) throw new Error('Chat not ready')
      recipients = [
        { userId: userId.value, publicKeyJwk: publicKeyJwk.value },
        { userId: chat.otherUserId, publicKeyJwk: chat.otherPublicKey },
      ]
    } else {
      const members = await ensureChatMembers(chatId)
      recipients = members.map((m) => ({ userId: m.userId, publicKeyJwk: m.publicKey }))
      if (!recipients.length) throw new Error('No recipients')
    }

    const encryptedData = await encryptSignedMessage({
      plaintext: { text: t, atIso, replyToId, modifiedAtIso },
      recipients,
    })

    if (utf8ByteLength(encryptedData) > MAX_ENCRYPTED_MESSAGE_BYTES) throw new Error(ERR_ENCRYPTED_TOO_LARGE)

    await updateMessage(chatId, messageId, encryptedData)

    // Optimistic local patch (WS update is best-effort).
    const next = cur.map((m) =>
      m.id === messageId
        ? { ...m, senderId: userId.value as string, atIso, modifiedAtIso, fromUsername: username.value as string, text: t, replyToId }
        : m,
    )
    messagesByChatId.value = { ...messagesByChatId.value, [chatId]: next }
  }

  async function deleteChat(chatId: string) {
    await fetchJson('/api/signed/chats/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId }),
    })

    removeChatLocal(chatId)
  }

  function removeChatLocal(chatId: string) {
    chats.value = chats.value.filter((c) => c.id !== chatId)
    const { [chatId]: _u, ...restUnread } = unreadByChatId.value
    unreadByChatId.value = restUnread
    const { [chatId]: _m, ...restMsgs } = messagesByChatId.value
    messagesByChatId.value = restMsgs
    const { [chatId]: _mm, ...restMembers } = membersByChatId.value
    membersByChatId.value = restMembers
    if (activeChatId.value === chatId) {
      activeChatId.value = null
      view.value = 'contacts'
    }
    void refreshPresence()
  }

  function goHome() {
    view.value = 'contacts'
    void refreshPresence()
  }

  function openSettings() {
    view.value = 'settings'
  }

  async function createPersonalChat(friendUsername: string) {
    const u = friendUsername.trim()
    if (!u) throw new Error('Username required')

    // Avoid creating a private chat with yourself.
    if (username.value && u.toLowerCase() === String(username.value).toLowerCase()) {
      throw new Error('self')
    }

    const j = await fetchJson('/api/signed/chats/create-personal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ username: u }),
    })

    await refreshChats()

    if (j?.chat?.id) {
      await openChat(String(j.chat.id))
    }

  }

  async function createGroupChat(name: string) {
    const n = name.trim()
    if (!n) throw new Error('Name required')

    const j = await fetchJson('/api/signed/chats/create-group', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ name: n }),
    })

    await refreshChats()
    if (j?.chat?.id) await openChat(String(j.chat.id))
  }

  async function addGroupMember(chatId: string, memberUsername: string) {
    const u = memberUsername.trim()
    if (!u) throw new Error('Username required')

    const j = await fetchJson('/api/signed/chats/add-member', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, username: u }),
    })

    // Best-effort: update cached members.
    const member = j?.member
    if (member && typeof member.userId === 'string' && typeof member.username === 'string' && typeof member.publicKey === 'string') {
      const cur = membersByChatId.value[chatId] ?? []
      const exists = cur.some((m) => m.userId === String(member.userId))
      if (!exists) {
        membersByChatId.value = {
          ...membersByChatId.value,
          [chatId]: [...cur, { userId: String(member.userId), username: String(member.username), publicKey: String(member.publicKey) }],
        }
      }
    } else {
      // If response isn't usable, just refetch.
      try {
        await fetchChatMembers(chatId)
      } catch {
        // ignore
      }
    }
  }

  async function renameGroupChat(chatId: string, name: string) {
    const cid = String(chatId || '').trim()
    const n = String(name || '').trim()
    if (!cid) throw new Error('chatId required')
    if (n.length < 3 || n.length > 64) throw new Error('Name must be 3-64 characters')

    const j = await fetchJson('/api/signed/chats/rename-group', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId: cid, name: n }),
    })

    const chat = j?.chat
    if (!chat || typeof chat.id !== 'string') throw new Error('Bad response')

    // Best-effort: update local chat list.
    chats.value = chats.value.map((c) => (String(c.id) === String(chat.id) ? { ...c, name: String(chat.name ?? n) } : c))
    return chat
  }

  async function loadMessages(chatId: string, limit = 50) {
    const lim = Math.max(1, Math.min(200, Number(limit) || 50))

    const j = await fetchJson(`/api/signed/messages?chatId=${encodeURIComponent(chatId)}&limit=${encodeURIComponent(String(lim))}`, {
      headers: { ...authHeaders() },
    })

    const list: SignedMessage[] = Array.isArray(j.messages) ? j.messages : []

    if (!privateKey.value || !userId.value) {
      messagesByChatId.value = { ...messagesByChatId.value, [chatId]: [] }
      const { [chatId]: _o, ...restOldest } = messagesOldestIdByChatId.value
      messagesOldestIdByChatId.value = restOldest
      messagesHasMoreByChatId.value = { ...messagesHasMoreByChatId.value, [chatId]: false }
      return { count: 0, hasMore: false, oldestId: null as string | null }
    }

    const out: SignedDecryptedMessage[] = []
    for (const m of list) {
      try {
        const plain = await decryptSignedMessage({
          encryptedData: m.encryptedData,
          myUserId: userId.value,
          myPrivateKey: privateKey.value,
        })
        const displayName =
          typeof m.senderUsername === 'string'
            ? m.senderUsername
            : membersByChatId.value[chatId]?.find((mm) => String(mm.userId) === String(m.senderId))?.username ?? String(m.senderId)
        out.push({
          id: m.id,
          chatId,
          senderId: String(m.senderId),
          atIso: plain.atIso,
          modifiedAtIso: plain.modifiedAtIso,
          fromUsername: displayName,
          text: plain.text,
          replyToId: plain.replyToId,
        })
      } catch {
        // ignore undecryptable messages
      }
    }

    // API returns newest-first; render oldest-first.
    out.reverse()
    messagesByChatId.value = { ...messagesByChatId.value, [chatId]: out }

    const oldestId = out[0]?.id ? String(out[0].id) : null
    if (oldestId) messagesOldestIdByChatId.value = { ...messagesOldestIdByChatId.value, [chatId]: oldestId }
    else {
      const { [chatId]: _o, ...restOldest } = messagesOldestIdByChatId.value
      messagesOldestIdByChatId.value = restOldest
    }

    const hasMore = list.length >= lim
    messagesHasMoreByChatId.value = { ...messagesHasMoreByChatId.value, [chatId]: hasMore }

    return { count: out.length, hasMore, oldestId }
  }

  async function loadMoreMessages(chatId: string, limit = 50) {
    const lim = Math.max(1, Math.min(200, Number(limit) || 50))
    if (!chatId) return { added: 0, hasMore: false }
    if (!privateKey.value || !userId.value) return { added: 0, hasMore: false }

    if (messagesLoadingMoreByChatId.value[chatId]) {
      return { added: 0, hasMore: Boolean(messagesHasMoreByChatId.value[chatId]) }
    }
    if (messagesHasMoreByChatId.value[chatId] === false) return { added: 0, hasMore: false }

    const before = messagesOldestIdByChatId.value[chatId]
    if (!before) return { added: 0, hasMore: false }

    messagesLoadingMoreByChatId.value = { ...messagesLoadingMoreByChatId.value, [chatId]: true }
    try {
      const j = await fetchJson(
        `/api/signed/messages?chatId=${encodeURIComponent(chatId)}&limit=${encodeURIComponent(String(lim))}&before=${encodeURIComponent(before)}`,
        { headers: { ...authHeaders() } },
      )

      const list: SignedMessage[] = Array.isArray(j.messages) ? j.messages : []

      const decoded: SignedDecryptedMessage[] = []
      for (const m of list) {
        try {
          const plain = await decryptSignedMessage({
            encryptedData: m.encryptedData,
            myUserId: userId.value,
            myPrivateKey: privateKey.value,
          })
          const displayName =
            typeof m.senderUsername === 'string'
              ? m.senderUsername
              : membersByChatId.value[chatId]?.find((mm) => String(mm.userId) === String(m.senderId))?.username ?? String(m.senderId)
          decoded.push({
            id: m.id,
            chatId,
            senderId: String(m.senderId),
            atIso: plain.atIso,
            modifiedAtIso: plain.modifiedAtIso,
            fromUsername: displayName,
            text: plain.text,
            replyToId: plain.replyToId,
          })
        } catch {
          // ignore
        }
      }

      // API returns newest-first; convert to oldest-first.
      decoded.reverse()

      const cur = messagesByChatId.value[chatId] ?? []
      const existing = new Set(cur.map((x) => x.id))
      const nextChunk = decoded.filter((m) => !existing.has(m.id))

      if (nextChunk.length) {
        messagesByChatId.value = { ...messagesByChatId.value, [chatId]: [...nextChunk, ...cur] }
        const nextOldest = nextChunk[0]?.id
        if (nextOldest) messagesOldestIdByChatId.value = { ...messagesOldestIdByChatId.value, [chatId]: String(nextOldest) }
      }

      const hasMore = list.length >= lim
      messagesHasMoreByChatId.value = { ...messagesHasMoreByChatId.value, [chatId]: hasMore }
      return { added: nextChunk.length, hasMore }
    } finally {
      const { [chatId]: _l, ...rest } = messagesLoadingMoreByChatId.value
      messagesLoadingMoreByChatId.value = rest
    }
  }

  async function sendMessage(chatId: string, text: string, opts?: { replyToId?: string | null }) {
    const t = text.trim()
    if (!t) return
    if (!userId.value || !username.value || !publicKeyJwk.value) throw new Error('Not logged in')

    const chat = chats.value.find((c) => c.id === chatId)
    if (!chat) throw new Error('Chat not found')

    const atIso = new Date().toISOString()
    const replyToId = typeof opts?.replyToId === 'string' ? opts?.replyToId : null

    let recipients: Array<{ userId: string; publicKeyJwk: string }> = []

    if (chat.type === 'personal') {
      if (!chat.otherUserId || !chat.otherPublicKey) throw new Error('Chat not ready')
      recipients = [
        { userId: userId.value, publicKeyJwk: publicKeyJwk.value },
        { userId: chat.otherUserId, publicKeyJwk: chat.otherPublicKey },
      ]
    } else {
      const members = await ensureChatMembers(chatId)
      recipients = members.map((m) => ({ userId: m.userId, publicKeyJwk: m.publicKey }))
      if (!recipients.length) throw new Error('No recipients')
    }

    const encryptedData = await encryptSignedMessage({
      plaintext: { text: t, atIso, replyToId, modifiedAtIso: null },
      recipients,
    })

    if (utf8ByteLength(encryptedData) > MAX_ENCRYPTED_MESSAGE_BYTES) throw new Error(ERR_ENCRYPTED_TOO_LARGE)

    const j = await fetchJson('/api/signed/messages/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, encryptedData }),
    })

    const msgId = typeof j.messageId === 'string' ? j.messageId : null
    if (!msgId) return

    // Append optimistically (it will also arrive via WS, but WS is best-effort).
    const cur = messagesByChatId.value[chatId] ?? []
    if (cur.some((m) => m.id === msgId)) return
    messagesByChatId.value = {
      ...messagesByChatId.value,
      [chatId]: [...cur, { id: msgId, chatId, senderId: userId.value, atIso, modifiedAtIso: null, fromUsername: username.value, text: t, replyToId }],
    }
  }

  async function register(params: { username: string; password: string; expirationDays: number; extraEntropy?: Uint8Array }) {
    const u = params.username.trim()
    if (!u) throw new Error('Username required')
    if (u.length < 3 || u.length > 64) throw new Error('Username must be between 3 and 64 characters')

    if (!params.password) throw new Error('Password required')
    if (params.password.length < 8) throw new Error('Password must be at least 8 characters')
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    const exp = Number(params.expirationDays)
    if (!Number.isFinite(exp) || exp < 7 || exp > 365) {
      throw new Error('Expiration days must be between 7 and 365')
    }

    // Check name availability before generating/storing key material.
    const check = await fetchJson('/api/auth/check-username', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u }),
    })
    if (check && check.exists === true) {
      throw new Error('Username already exists')
    }

    storeLastUsername(u)

    const { publicJwk, privateJwk } = await generateRsaKeyPair()
    const encryptedPrivateKey = await encryptPrivateKeyJwk({ privateJwk, password: params.password, extraEntropy: params.extraEntropy })

    // Import private key before setting token/userId so App.vue doesn't interpret
    // the session as "signed in but locked" mid-register and auto-logout.
    const importedPrivateKey = await importRsaPrivateKeyJwk(privateJwk)

    const j = await fetchJson('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: u,
        password: params.password,
        publicKey: publicJwk,
        expirationDays: exp,
      }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = typeof j.username === 'string' ? j.username : u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk

    privateKey.value = importedPrivateKey

    // Persist key material only after server registration succeeds.
    await saveLocalKeyForUser({ username: u, password: params.password, encryptedPrivateKey, extraEntropy: params.extraEntropy })

    if (token.value && userId.value && username.value) {
      storeSession(
        { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
        token.value,
        expiresAtMs.value,
      )
    }

    await refreshChats()
    await connectWs()
    void maybeAddChatFromUrl()
    void maybeOpenChatFromUrl()
    scheduleTokenRefresh()
    void trySyncPushSubscription()
    view.value = 'contacts'
  }

  async function login(params: { username: string; password: string }) {
    const u = params.username.trim()
    if (!u) throw new Error('Username required')
    if (!params.password) throw new Error('Password required')
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    storeLastUsername(u)

    const encryptedPrivateKey = await findEncryptedPrivateKeyForLogin({ username: u, password: params.password })
    if (!encryptedPrivateKey) throw new Error('No local key found')

    const privateJwk = await decryptPrivateKeyJwk({ encrypted: encryptedPrivateKey, password: params.password })
    const priv = await importRsaPrivateKeyJwk(privateJwk)

    const publicJwk = publicJwkFromPrivateJwk(privateJwk)

    const j = await fetchJson('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: params.password, publicKey: publicJwk }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = typeof j.username === 'string' ? j.username : u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk
    privateKey.value = priv

    if (token.value && userId.value && username.value) {
      storeSession(
        { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
        token.value,
        expiresAtMs.value,
      )
    }

    // Migrate/ensure low-profile local storage now that we have the password.
    await saveLocalKeyForUser({ username: u, password: params.password, encryptedPrivateKey })

    await refreshChats()
    await connectWs()
    void maybeAddChatFromUrl()
    void maybeOpenChatFromUrl()
    scheduleTokenRefresh()
    void trySyncPushSubscription()
    view.value = 'contacts'
  }

  function logout(wipeSessionStorage = false) {
    wsShouldReconnect.value = false
    clearWsReconnectTimer()
    clearPresenceTimer()
    disconnectWs()
    clearTokenRefreshTimer()
    token.value = null
    expiresAtMs.value = null
    userId.value = null
    username.value = null
    hiddenMode.value = false
    introvertMode.value = false
    publicKeyJwk.value = null
    privateKey.value = null
    chats.value = []
    unreadByChatId.value = {}
    messagesByChatId.value = {}
    membersByChatId.value = {}
    activeChatId.value = null
    view.value = 'contacts'

    if (wipeSessionStorage) {
      try {
        sessionStorage.clear()
      } catch {
        // ignore
      }
      lastUsername.value = ''
      pendingAddUsername.value = ''
    } else {
      clearSession()
    }
  }

  async function deleteAccount() {
    // Requires an active signed session.
    if (!token.value) throw new Error('Not logged in')

    await fetchJson('/api/signed/account/delete', {
      method: 'POST',
      headers: { ...authHeaders() },
    })

    // Clear all local traces for this signed identity.
    // Without a stable plaintext identifier, prefer privacy: remove all stored signed keys.
    clearAllKeyMaterial()
    storeLastUsername('')
    logout(true)
  }

  // Attempt to restore token+user on refresh. Private key still requires password.
  const restored = loadSession()
  if (restored) {
    token.value = restored.t
    userId.value = restored.u.userId
    username.value = restored.u.username
    hiddenMode.value = Boolean(restored.u.hiddenMode)
    introvertMode.value = Boolean(restored.u.introvertMode)
    expiresAtMs.value = restored.e
    publicKeyJwk.value = null
  }

  // Capture invite links on initial load, before login/register.
  pendingAddUsername.value = loadPendingAddUsername()
  if (!pendingAddUsername.value) capturePendingAddFromUrl()

  async function updateHiddenMode(next: boolean) {
    if (!token.value) throw new Error('Not logged in')
    const prev = hiddenMode.value
    hiddenMode.value = Boolean(next)
    try {
      const j = await fetchJson('/api/signed/account/hidden-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ hiddenMode: hiddenMode.value }),
      })
      hiddenMode.value = Boolean(j?.hiddenMode)

      if (token.value && userId.value && username.value) {
        storeSession(
          { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
          token.value,
          expiresAtMs.value,
        )
      }
    } catch (e) {
      hiddenMode.value = prev
      throw e
    }
  }

  async function updateIntrovertMode(next: boolean) {
    if (!token.value) throw new Error('Not logged in')
    const prev = introvertMode.value
    introvertMode.value = Boolean(next)
    try {
      const j = await fetchJson('/api/signed/account/introvert-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ introvertMode: introvertMode.value }),
      })
      introvertMode.value = Boolean(j?.introvertMode)

      if (token.value && userId.value && username.value) {
        storeSession(
          { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
          token.value,
          expiresAtMs.value,
        )
      }
    } catch (e) {
      introvertMode.value = prev
      throw e
    }
  }

  // For convenience in setup screen.
  lastUsername.value = loadLastUsername()

  return {
    token,
    expiresAtMs,
    userId,
    username,
    hiddenMode,
    introvertMode,
    notificationsEnabled,
    publicKeyJwk,
    privateKey,
    ws,
    turnConfig,
    signedIn,
    lastUsername,
    view,
    activeChatId,
    chats,
    unreadByChatId,
    lastMessageByChatId,
    lastMessagePreviewByChatId,
    membersByChatId,
    messagesByChatId,
    onlineByUserId,
    busyByUserId,
    otherChatsUnread,
    register,
    login,
    logout,
    deleteAccount,
    updateHiddenMode,
    updateIntrovertMode,
    refreshChats,
    fetchChatMembers,
    openChat,
    goHome,
    openSettings,
    setNotificationsEnabledLocal,
    trySyncPushSubscription,
    disablePushSubscription,
    createPersonalChat,
    createGroupChat,
    addGroupMember,
    renameGroupChat,
    loadMoreMessages,
    sendMessage,
    markMessagesRead,
    listUnreadMessageIds,
    deleteMessage,
    updateMessage,
    updateMessageText,
    deleteChat,
    refreshPresence,
    getChatOnlineState,
    getChatLastMessagePreview,
    getChatLastMessageTsMs,
    ensureTurnConfig,
    sendWs,
    registerInboundHandler,
    registerDisconnectHandler,
    connectWs,
    disconnectWs,
    unlock,
  }
})
