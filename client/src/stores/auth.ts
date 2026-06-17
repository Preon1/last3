import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { notify } from '../utils/notify'
import { tryGetWebPushSubscriptionJson } from '../utils/push'
import {
  broadcastAppStateToServiceWorker,
  closeAllNotifications,
  closeNotificationsByTag,
  getNotificationsEnabled,
  getPushNotificationsEnabled,
  setNotificationsEnabled,
  setPushNotificationsEnabled,
} from '../utils/notificationPrefs'
import {
  decryptMessageEnvelope,
  decryptStringWithPassword,
  decryptSmallStringWithPrivateKey,
  encryptMessageEnvelope,
  encryptStringWithPassword,
  encryptSmallStringWithPublicKeyJwk,
  generateRsaKeyPair,
  importRsaPssPrivateKeyJwk,
  importRsaPssPublicKeyJwk,
  importRsaPrivateKeyJwk,
  LOCAL_KEY_PRIVATE_KEY_ITERATIONS,
  publicJwkFromPrivateJwk,
  signEnvelope,
  verifyEnvelope,
} from '../utils/signedCrypto'
import { LocalEntity, localData } from '../utils/localData'
import { APP_VERSION as CLIENT_APP_VERSION } from '../appVersion'
import { useToastStore } from './toast'
import { voprfNameToken } from '../utils/voprfNames'
import { AuthTransportClient } from '../utils/authTransport'

export type AuthChat = {
  id: string
  type: 'personal' | 'group'
  name?: string
  chatNameEnc?: string
  names?: Record<string, string>
  otherUserId?: string
  otherPublicKey?: string
}

export type AuthLastMessageWire = {
  id: string
  chatId: string
  senderId: string
  encryptedData: string
  signature?: string
}

export type AuthLastMessagePreview = {
  id: string
  chatId: string
  senderId: string
  senderUsername: string
  tsMs: number
  text: string
}

export type AuthChatMember = {
  userId: string
  username?: string
  publicKey: string
}

export type AuthMessage = {
  id: string
  chatId: string
  senderId: string
  encryptedData: string
  signature?: string
}

export type AuthMessageVerification = 'verified' | 'unverifiable'

export type AuthDecryptedMessage = {
  id: string
  chatId: string
  senderId: string
  atIso: string
  modifiedAtIso?: string | null
  fromUsername: string
  text: string
  replyToId?: string | null
  verification: AuthMessageVerification
}

function apiBase() {
  return ''
}

function transportAuthUrl(token: string) {
  const configured = String(import.meta.env.VITE_WEBTRANSPORT_URL ?? '').trim()

  const base = configured ? new URL(configured, location.origin) : new URL(location.origin)

  if (!configured) {
    if (location.protocol === 'https:') {
      const p = Number(location.port || 443)
      if (Number.isFinite(p) && p > 0) base.port = String(p + 1)
      else base.port = '8444'
    }
  }

  base.protocol = 'https:'
  base.pathname = '/private'
  base.search = ''
  base.hash = ''
  base.searchParams.set('token', token)
  return base.toString()
}

// NOTE: All locally persisted entities must be accessed via LocalData.

const MAX_PASSWORD_LEN = 512

const MAX_ENCRYPTED_MESSAGE_BYTES = 50 * 1024
const ERR_ENCRYPTED_TOO_LARGE = 'Encrypted message too large'
const CHAT_META_TEXT_PAD_MIN_CHARS = 0
const CHAT_META_TEXT_PAD_MAX_CHARS = 32
const MESSAGE_TEXT_PAD_MIN_CHARS = 0
const MESSAGE_TEXT_PAD_MAX_CHARS = 64
const LOCAL_KEY_ENTRY_POSTFIX_MIN_CHARS = 0
const LOCAL_KEY_ENTRY_POSTFIX_MAX_CHARS = 32
const LOCAL_KEY_ENTRY_POSTFIX_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()-_=+[]{};:,.<>/?'

// Signature verification: cache imported RSA-PSS verify keys by JWK string.
const verifyKeyCache = new Map<string, CryptoKey>()

async function getVerifyKeyFromPublicJwk(publicJwkJson: string): Promise<CryptoKey> {
  const jwk = String(publicJwkJson ?? '')
  const cached = verifyKeyCache.get(jwk)
  if (cached) return cached
  const k = await importRsaPssPublicKeyJwk(jwk)
  verifyKeyCache.set(jwk, k)
  return k
}

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

function assertUsernameIsXssSafe(username: string) {
  const u = String(username ?? '')
  // Vue text bindings escape HTML, but usernames can still end up in other contexts
  // (notifications, attributes, logs). Reject the most dangerous characters early.
  if (u.includes('<') || u.includes('>')) throw new Error('Username contains unsafe characters')
  // Disallow ASCII control characters (including newlines/tabs) which can cause UI or parsing issues.
  if (/[\u0000-\u001F\u007F]/.test(u)) throw new Error('Username contains unsafe characters')
}

type StoredKeyV3 = {
  v: 3
  d: string
}

type LocalKeyEntryPlain = {
  n: string
  k: string
  p: string
  s?: string
}

type StoredUser = {
  userId: string
  username: string
  hiddenMode?: boolean
  introvertMode?: boolean
}

type VaultPlain = {
  expirationDays: number
}

export const useAuthStore = defineStore('auth', () => {
  const toast = useToastStore()
  const token = ref<string | null>(null)
  const expiresAtMs = ref<number | null>(null)
  const userId = ref<string | null>(null)
  const username = ref<string | null>(null)
  const hiddenMode = ref<boolean>(false)
  const introvertMode = ref<boolean>(false)
  const publicKeyJwk = ref<string | null>(null)
  const privateKey = ref<CryptoKey | null>(null)
  const signingKey = ref<CryptoKey | null>(null)

  const vaultEncrypted = ref<string>('')
  const vaultPlain = ref<VaultPlain | null>(null)
  const removeDateIso = ref<string | null>(null)

  const notificationsEnabled = ref<boolean>(getNotificationsEnabled())
  const pushNotificationsEnabled = ref<boolean>(getPushNotificationsEnabled())

  const restoring = ref<boolean>(false)

  let lastPrivateJwkJsonForStay: string | null = null

  let stayMirrorTimer: number | null = null
  function clearStayMirrorTimer() {
    if (stayMirrorTimer != null) {
      try {
        window.clearTimeout(stayMirrorTimer)
      } catch {
        // ignore
      }
      stayMirrorTimer = null
    }
  }

  const stayLoggedIn = ref<boolean>(false)
  stayLoggedIn.value = localData.getAuthStayLoggedIn()

  // Only show a restore/loading state when stay mode is enabled.
  restoring.value = stayLoggedIn.value

  async function syncStayMirrorNow() {
    try {
      if (!stayLoggedIn.value) return

      // Mirror session details.
      if (token.value && userId.value && username.value) {
        await localData.mirrorAuthSessionToIdb({
          user: {
            userId: userId.value,
            username: username.value,
            hiddenMode: hiddenMode.value,
            introvertMode: introvertMode.value,
          },
          token: token.value,
          expiresAtMs: expiresAtMs.value,
        })
      }

      // Mirror vault/remove-date.
      if (vaultPlain.value) {
        await localData.idbSet(LocalEntity.IdbStayVault, JSON.stringify({ expirationDays: vaultPlain.value.expirationDays }))
      }
      if (removeDateIso.value) {
        await localData.idbSet(LocalEntity.IdbStayRemoveDate, removeDateIso.value)
      }

      // Mirror device-bound unlock blob.
      // The stay-unlock blob is persisted at login/register time from the decrypted private JWK string.
    } catch {
      // ignore
    }
  }

  function scheduleStayMirrorSync() {
    clearStayMirrorTimer()
    if (!stayLoggedIn.value) return
    // Debounce to avoid writing IDB too frequently.
    stayMirrorTimer = window.setTimeout(() => {
      void syncStayMirrorNow()
    }, 150)
  }

  function setStayLoggedIn(next: boolean) {
    stayLoggedIn.value = Boolean(next)
    localData.setAuthStayLoggedIn(stayLoggedIn.value)

    if (stayLoggedIn.value) {
      try {
        if (token.value && userId.value && username.value) {
          storeSession(
            { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
            token.value,
            expiresAtMs.value,
          )
        }
        if (vaultPlain.value) {
          storeVaultPlain(JSON.stringify({ expirationDays: vaultPlain.value.expirationDays }))
        }
        if (removeDateIso.value) {
          storeRemoveDateIso(removeDateIso.value)
        }
      } catch {
        // ignore
      }

      // Variant B: if we already have key material in-memory (e.g. settings toggle while authenticated),
      // ensure the stay-unlock blob exists.
      void ensureStayUnlockBlobIfPossible()

      // Ensure mirrors are present.
      scheduleStayMirrorSync()
    }

    if (!stayLoggedIn.value) {
      clearStayMirrorTimer()

      // Clear stay artifacts stored in localStorage.
      void localData.idbSet(LocalEntity.IdbStaySession, null)
      void localData.idbSet(LocalEntity.IdbStayVault, null)
      void localData.idbSet(LocalEntity.IdbStayRemoveDate, null)
      void localData.idbSet(LocalEntity.IdbStayUnlockBlob, null)
      localData.remove(LocalEntity.StayDeviceKey)

      // Push notifications are only allowed in stay mode.
      void disablePushNotifications()
    }
  }

  const lastUsername = ref<string>('')

  const pendingAddUsername = ref<string>('')

  const ws = ref<{ readyState: number } | null>(null)
  const wsShouldReconnect = ref(false)
  const wsReconnectAttempt = ref(0)
  const wsPermanentlyFailed = ref(false)
  const transportFatalReason = ref<string>('')
  let wsReconnectTimer: number | null = null
  let wsGeneration = 0
  const transportClient = new AuthTransportClient()

  // App version mismatch detection (server updates while client is open)
  const clientVersion = ref<string>(String(CLIENT_APP_VERSION))
  const serverVersion = ref<string>('')
  const lastKnownServerVersion = ref<string>('')
  const serverUpdatedFrom = ref<string | null>(null)
  const serverUpdatedTo = ref<string | null>(null)
  const serverUpdateModalOpen = ref(false)

  const turnConfig = ref<any | null>(null)

  const inboundHandlers: Array<(type: string, obj: Record<string, unknown>) => void> = []
  const disconnectHandlers: Array<() => void> = []

  const view = ref<'contacts' | 'chat' | 'settings'>('contacts')
  const activeChatId = ref<string | null>(null)

  const chats = ref<AuthChat[]>([])
  const unreadByChatId = ref<Record<string, number>>({})

  const lastMessageByChatId = ref<Record<string, AuthLastMessageWire | null>>({})
  const lastMessagePreviewByChatId = ref<Record<string, AuthLastMessagePreview>>({})

  const membersByChatId = ref<Record<string, AuthChatMember[]>>({})

  const messagesByChatId = ref<Record<string, AuthDecryptedMessage[]>>({})

  const messagesOldestIdByChatId = ref<Record<string, string>>({})
  const messagesHasMoreByChatId = ref<Record<string, boolean>>({})
  const messagesLoadingMoreByChatId = ref<Record<string, boolean>>({})

  const onlineByUserId = ref<Record<string, boolean>>({})
  const busyByUserId = ref<Record<string, boolean>>({})
  let presenceTimer: number | null = null
  const PRESENCE_HEARTBEAT_MS = 10000

  const authIn = computed(() => Boolean(token.value && userId.value && username.value))
  const locked = computed(() => Boolean(authIn.value && !privateKey.value))
  const unlocking = ref(false)
  const authReadyForPresence = computed(() => Boolean(token.value && userId.value && username.value && privateKey.value && !wsPermanentlyFailed.value))
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
        if (document.visibilityState === 'visible') sendPresenceHeartbeat()
      })
      window.addEventListener('focus', () => {
        sendPresenceHeartbeat()
      })
    }
  } catch {
    // ignore
  }

  let tokenRefreshTimer: number | null = null

  let removeDateSyncTimer: number | null = null

  function readServerVersionFromMeta(): string {
    try {
      const el = document.querySelector('meta[name="lrcom-server-version"]') as HTMLMetaElement | null
      const v = typeof el?.content === 'string' ? el.content.trim() : ''
      return v
    } catch {
      return ''
    }
  }

  function applyServerVersion(nextRaw: unknown) {
    const next = typeof nextRaw === 'string' ? nextRaw.trim() : ''
    if (!next) return

    const prev = String(serverVersion.value || '')

    // First time we learn server version.
    if (!prev) {
      serverVersion.value = next
      lastKnownServerVersion.value = next

      // If the client is cached old (SW), mismatch can exist on first load.
      if (clientVersion.value && clientVersion.value !== next) {
        serverUpdatedFrom.value = clientVersion.value
        serverUpdatedTo.value = next
        serverUpdateModalOpen.value = true
      }
      return
    }

    // Version changed while app is open.
    if (prev !== next) {
      serverUpdatedFrom.value = prev
      serverUpdatedTo.value = next
      serverVersion.value = next
      lastKnownServerVersion.value = next
      serverUpdateModalOpen.value = true
      return
    }

    // Same server version; still may be a client/server mismatch.
    lastKnownServerVersion.value = next

    const mismatch = Boolean(clientVersion.value && clientVersion.value !== next)
    if (mismatch && serverUpdatedTo.value !== next && !serverUpdateModalOpen.value) {
      serverUpdatedFrom.value = clientVersion.value
      serverUpdatedTo.value = next
      serverUpdateModalOpen.value = true
    }
  }

  // On boot/page load, capture server version from injected meta.
  try {
    if (typeof document !== 'undefined') {
      applyServerVersion(readServerVersionFromMeta())
    }
  } catch {
    // ignore
  }

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

  function dismissServerUpdateModal() {
    serverUpdateModalOpen.value = false
  }

  // Presence heartbeat should not depend on transport open: if transport is delayed/blocked
  // we still want to refresh presence for known correspondents.
  watch(
    () => authReadyForPresence.value,
    (ready) => {
      if (ready) startPresenceHeartbeat()
      else clearPresenceTimer()
    },
    { immediate: true },
  )

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

  function clearRemoveDateSyncTimer() {
    if (removeDateSyncTimer != null) {
      try {
        window.clearInterval(removeDateSyncTimer)
      } catch {
        // ignore
      }
      removeDateSyncTimer = null
    }
  }

  function parseVaultPlain(raw: string): VaultPlain | null {
    try {
      const obj = JSON.parse(raw) as any
      const exp = Number(obj?.expirationDays)
      if (!Number.isFinite(exp) || exp < 7 || exp > 365) return null
      return { expirationDays: exp }
    } catch {
      return null
    }
  }

  function bytesToB64(bytes: Uint8Array): string {
    let bin = ''
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
    return btoa(bin)
  }

  function makeVaultJson(expirationDays: number): string {
    const exp = Number(expirationDays)
    if (!Number.isFinite(exp)) throw new Error('Invalid expirationDays')

    // Add per-encryption random salt so ciphertext changes even when the
    // user keeps the same settings.
    const saltLen = randomIntInclusive(4, 16)
    const saltBytes = crypto.getRandomValues(new Uint8Array(saltLen))
    const s = bytesToB64(saltBytes)

    return JSON.stringify({ expirationDays: exp, s })
  }

  function randomIntInclusive(min: number, max: number) {
    const lo = Math.min(min, max)
    const hi = Math.max(min, max)
    const range = hi - lo + 1
    try {
      const u32 = new Uint32Array(1)
      crypto.getRandomValues(u32)
      const v = u32[0] ?? 0
      return lo + (v % range)
    } catch {
      return lo + Math.floor(Math.random() * range)
    }
  }

  function randomStringFromAlphabet(len: number, alphabet: string) {
    if (len <= 0) return ''
    const chars = String(alphabet ?? '')
    if (!chars.length) throw new Error('Alphabet must not be empty')

    const u8 = crypto.getRandomValues(new Uint8Array(len))
    let out = ''
    for (let i = 0; i < u8.length; i++) out += chars[u8[i]! % chars.length]
    return out
  }

  function parseLocalKeyEntryPlain(raw: string): LocalKeyEntryPlain | null {
    try {
      const obj = JSON.parse(raw) as Partial<LocalKeyEntryPlain>
      if (!obj || typeof obj !== 'object') return null

      const n = typeof obj.n === 'string' ? obj.n : ''
      const k = typeof obj.k === 'string' ? obj.k : ''
      const p = typeof obj.p === 'string' ? obj.p : ''
      if (!n || !k) return null
      if (p.length < LOCAL_KEY_ENTRY_POSTFIX_MIN_CHARS || p.length > LOCAL_KEY_ENTRY_POSTFIX_MAX_CHARS) return null

      const s = typeof obj.s === 'string' && obj.s ? obj.s : undefined
      return s ? { n, k, p, s } : { n, k, p }
    } catch {
      return null
    }
  }

  function computeRemoveDateIsoForNow(expirationDays: number) {
    const jitterSeconds = randomIntInclusive(0, 86400)
    const ms = Date.now() + expirationDays * 86400_000 + jitterSeconds * 1000
    return new Date(ms).toISOString()
  }

  function storeVaultPlain(rawJson: string) {
    localData.setString(LocalEntity.AuthVault, rawJson)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayVault, rawJson)
  }

  function loadVaultPlain(): VaultPlain | null {
    const raw = String(localData.getString(LocalEntity.AuthVault) ?? '')
    return raw ? parseVaultPlain(raw) : null
  }

  function clearVaultPlain() {
    localData.remove(LocalEntity.AuthVault)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayVault, null)
  }

  function storeRemoveDateIso(iso: string) {
    localData.setString(LocalEntity.AuthRemoveDate, iso)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayRemoveDate, iso)
  }

  function loadRemoveDateIso(): string | null {
    const raw = String(localData.getString(LocalEntity.AuthRemoveDate) ?? '').trim()
    return raw ? raw : null
  }

  function clearRemoveDateIso() {
    localData.remove(LocalEntity.AuthRemoveDate)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayRemoveDate, null)
  }

  async function updateAccount(fields: {
    hiddenMode?: boolean
    introvertMode?: boolean
    removeDate?: string
    vault?: string
  }) {
    await fetchJson('/api/account/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify(fields),
    })
  }

  async function bestEffortSyncRemoveDateNow() {
    if (!authIn.value) return
    const exp = vaultPlain.value?.expirationDays
    if (!exp || !Number.isFinite(exp)) return
    const iso = computeRemoveDateIsoForNow(exp)
    removeDateIso.value = iso
    storeRemoveDateIso(iso)
    try {
      await updateAccount({ removeDate: iso })
    } catch {
      // ignore
    }
  }

  function startRemoveDateSyncTimer() {
    clearRemoveDateSyncTimer()
    // Every 10 minutes.
    removeDateSyncTimer = window.setInterval(() => {
      void bestEffortSyncRemoveDateNow()
    }, 10 * 60 * 1000)
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
      const r = await fetch(`${apiBase()}/api/session/refresh`, {
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

  function setPushNotificationsEnabledLocal(next: boolean) {
    pushNotificationsEnabled.value = Boolean(next)
    setPushNotificationsEnabled(Boolean(next))
  }

  async function disablePushNotifications() {
    // Wipe preference, server state, and local browser subscription.
    setPushNotificationsEnabledLocal(false)

    try {
      if (token.value) {
        await fetchJson('/api/push/disable', {
          method: 'POST',
          headers: { ...authHeaders() },
        })
      }
    } catch {
      // ignore
    }

    try {
      await disablePushSubscription()
    } catch {
      // ignore
    }
  }

  async function trySyncPushSubscription() {
    if (!token.value) return false
    if (!stayLoggedIn.value) return false
    if (!pushNotificationsEnabled.value) return false
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return false

    const subscription = await tryGetWebPushSubscriptionJson()
    if (!subscription) return false

    try {
      await fetchJson('/api/push/subscribe', {
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

  function getPresenceProbeList() {
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

    return list
  }

  function sendPresenceHeartbeat() {
    if (!token.value || !userId.value) return
    const list = getPresenceProbeList()
    sendDatagram({ type: 'presenceHeartbeat', userIds: list })
  }

  function startPresenceHeartbeat() {
    clearPresenceTimer()
    // Best-effort heartbeat for presence snapshots.
    presenceTimer = window.setInterval(() => {
      sendPresenceHeartbeat()
    }, PRESENCE_HEARTBEAT_MS)
    sendPresenceHeartbeat()
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
        // Pull more history on reconnect in case we missed realtime events.
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
    const retryDelayMs = 5000
    if (wsReconnectAttempt.value >= maxAttempts) {
      wsShouldReconnect.value = false
      wsPermanentlyFailed.value = true
      clearWsReconnectTimer()
      clearPresenceTimer()
      return
    }

    clearWsReconnectTimer()
    const attempt = wsReconnectAttempt.value + 1
    wsReconnectAttempt.value = attempt

    wsReconnectTimer = window.setTimeout(() => {
      void connectWs()
    }, retryDelayMs)
  }

  function loadKeyEntries(): StoredKeyV3[] {
    const arr = localData.getJson<any[]>(LocalEntity.AuthKeys)
    if (!Array.isArray(arr)) return []
    const out: StoredKeyV3[] = []
    for (const it of arr) {
      if (it && it.v === 3 && typeof it.d === 'string') {
        out.push({ v: 3, d: it.d })
      }
    }
    return out
  }

  function saveKeyEntries(next: StoredKeyV3[]) {
    localData.setJson(LocalEntity.AuthKeys, next)
  }


  function clearAllKeyMaterial() {
    localData.remove(LocalEntity.AuthKeys)
  }

  async function saveLocalKeyForUser(params: { username: string; password: string; privateKeyMaterial: string; signingKeyMaterial?: string }) {
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    const postfixLen = randomIntInclusive(LOCAL_KEY_ENTRY_POSTFIX_MIN_CHARS, LOCAL_KEY_ENTRY_POSTFIX_MAX_CHARS)
    const p = randomStringFromAlphabet(postfixLen, LOCAL_KEY_ENTRY_POSTFIX_ALPHABET)

    const payload: LocalKeyEntryPlain = {
      n: String(params.username ?? ''),
      k: String(params.privateKeyMaterial ?? ''),
      p,
    }
    const separateSigning = typeof params.signingKeyMaterial === 'string' && params.signingKeyMaterial && params.signingKeyMaterial !== payload.k
    if (separateSigning) payload.s = params.signingKeyMaterial

    const d = await encryptStringWithPassword({
      plaintext: JSON.stringify(payload),
      password: params.password,
      iterations: LOCAL_KEY_PRIVATE_KEY_ITERATIONS,
    })

    const cur = loadKeyEntries()
    const kept: StoredKeyV3[] = []
    for (const e of cur) {
      try {
        const raw = await decryptStringWithPassword({ encrypted: e.d, password: params.password })
        const plain = parseLocalKeyEntryPlain(raw)
        if (plain?.n === params.username) continue
      } catch {
        // If it can't be decrypted with this password, keep it.
      }
      kept.push(e)
    }

    kept.push({ v: 3, d })
    saveKeyEntries(kept)
  }

  async function findLocalKeyMaterialForLogin(params: { username: string; password: string }) {
    const list = loadKeyEntries()
    for (const e of list) {
      try {
        const raw = await decryptStringWithPassword({ encrypted: e.d, password: params.password })
        const plain = parseLocalKeyEntryPlain(raw)
        if (plain?.n === params.username) {
          return {
            privateKeyMaterial: plain.k,
            signingKeyMaterial: plain.s ?? plain.k,
          }
        }
      } catch {
        // ignore
      }
    }

    return null
  }

  function storeSession(u: StoredUser, t: string, expiresAt?: number | null) {
    localData.setAuthSession({ user: u, token: t, expiresAtMs: expiresAt })
    if (stayLoggedIn.value) void localData.mirrorAuthSessionToIdb({ user: u, token: t, expiresAtMs: expiresAt })
  }

  function loadSession(): { u: StoredUser; t: string; e: number | null } | null {
    const s = localData.getAuthSession()
    if (!s?.token || !s.user) return null
    const u = s.user as StoredUser
    if (!u?.userId || !u?.username) return null
    return { u, t: s.token, e: typeof s.expiresAtMs === 'number' && Number.isFinite(s.expiresAtMs) ? s.expiresAtMs : null }
  }

  function clearSession() {
    localData.clearAuthSession()
    if (stayLoggedIn.value) void localData.clearIdbStaySession()
  }

  async function persistStayUnlockBlobFromPrivateJwk(privateJwkJson: string) {
    try {
      if (!stayLoggedIn.value) return
      const blob = await localData.encryptStayString(String(privateJwkJson ?? ''))
      await localData.idbSet(LocalEntity.IdbStayUnlockBlob, blob)
    } catch {
      // ignore
    }
  }

  async function ensureStayUnlockBlobIfPossible(): Promise<void> {
    try {
      if (!stayLoggedIn.value) return
      // If user enables stay mode before login, we don't have key material yet.
      if (!token.value || !userId.value || !username.value) return

      const existing = await localData.idbGet<string>(LocalEntity.IdbStayUnlockBlob)
      if (existing) return

      if (lastPrivateJwkJsonForStay) {
        await persistStayUnlockBlobFromPrivateJwk(lastPrivateJwkJsonForStay)
        return
      }

      // We cannot recover a private JWK from a non-extractable CryptoKey.
      // In this scenario, user must re-login with stay mode enabled.
      stayLoggedIn.value = false
      localData.setAuthStayLoggedIn(false)
      toast.push({
        title: 'Keep logged in disabled',
        message: 'Please log in again with "Keep logged in" enabled to allow auto-unlock.',
        variant: 'info',
        timeoutMs: 8000,
      })
    } catch {
      // ignore
    }
  }

  async function tryRestoreStayUnlockBlob(): Promise<boolean> {
    try {
      if (!stayLoggedIn.value) return false
      if (!token.value || !userId.value || !username.value) return false
      if (privateKey.value) return true

      const blob = await localData.idbGet<string>(LocalEntity.IdbStayUnlockBlob)
      if (!blob) return false
      const jwkJson = await localData.decryptStayString(blob)
      lastPrivateJwkJsonForStay = jwkJson
      privateKey.value = await importRsaPrivateKeyJwk(jwkJson)
      signingKey.value = await importRsaPssPrivateKeyJwk(jwkJson)
      publicKeyJwk.value = publicJwkFromPrivateJwk(jwkJson)
      return true
    } catch {
      return false
    }
  }

  function loadLastUsername(): string {
    return String(localData.getString(LocalEntity.AuthUsername) ?? '').trim()
  }

  function storeLastUsername(u: string) {
    const v = (u ?? '').trim()
    lastUsername.value = v
    localData.setString(LocalEntity.AuthUsername, v)
  }

  function loadPendingAddUsername(): string {
    return String(localData.getString(LocalEntity.AuthAddUsername) ?? '').trim()
  }

  function storePendingAddUsername(u: string) {
    const v = String(u ?? '').trim()
    pendingAddUsername.value = v
    localData.setString(LocalEntity.AuthAddUsername, v)
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

    const localKey = await findLocalKeyMaterialForLogin({ username: u, password: params.password })
    if (!localKey) throw new Error('No local key found')

    const privateJwk = localKey.privateKeyMaterial
    const signingJwk = localKey.signingKeyMaterial
    lastPrivateJwkJsonForStay = privateJwk
    privateKey.value = await importRsaPrivateKeyJwk(privateJwk)
    signingKey.value = await importRsaPssPrivateKeyJwk(signingJwk)
    publicKeyJwk.value = publicJwkFromPrivateJwk(privateJwk)

    // Variant B: if stay mode is enabled, persist auto-unlock blob from private JWK.
    void persistStayUnlockBlobFromPrivateJwk(privateJwk)

    // Now that the password is known, ensure we persist only the low-profile entry.
    await saveLocalKeyForUser({
      username: u,
      password: params.password,
      privateKeyMaterial: privateJwk,
      signingKeyMaterial: signingJwk !== privateJwk ? signingJwk : undefined,
    })

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

  let resumeSyncInFlight: Promise<void> | null = null
  let lastResumeSyncAtMs = 0

  function bestEffortResumeSync(_reason?: string) {
    // iOS PWA can restore an in-memory snapshot; ensure we refresh chats/presence
    // when the app becomes visible again.
    if (!token.value) return

    const now = Date.now()
    if (now - lastResumeSyncAtMs < 5000) return
    lastResumeSyncAtMs = now

    if (resumeSyncInFlight) return
    resumeSyncInFlight = (async () => {
      try {
        await refreshChats()
      } catch {
        // ignore
      }

      try {
        await connectWs()
      } catch {
        // ignore
      }

      // If app was opened via push/link, these params may exist.
      try {
        void maybeAddChatFromUrl()
      } catch {
        // ignore
      }

      try {
        await maybeOpenChatFromUrl()
      } catch {
        // ignore
      }

      try {
        sendPresenceHeartbeat()
      } catch {
        // ignore
      }
    })().finally(() => {
      resumeSyncInFlight = null
    })
  }

  async function maybeOpenChatFromUrl() {
    try {
      const qs = new URLSearchParams(location.search)
      const chatId = (qs.get('chatId') ?? '').trim()
      if (!chatId) return

      const wantsSync = String(qs.get('sync') ?? '').trim() === '1'

      // Remove the param immediately to avoid re-open loops on reload.
      try {
        qs.delete('chatId')
        qs.delete('sync')
        const next = qs.toString()
        const url = `${location.pathname}${next ? `?${next}` : ''}${location.hash || ''}`
        history.replaceState(null, '', url)
      } catch {
        // ignore
      }

      if (!token.value) return

      const existsBefore = chats.value.some((c) => String(c.id) === String(chatId))
      if (wantsSync || !existsBefore) {
        try {
          await refreshChats()
        } catch {
          // ignore
        }
      }

      const exists = chats.value.some((c) => String(c.id) === String(chatId))
      if (!exists) return
      await openChat(chatId)
    } catch {
      // ignore
    }
  }

  let reauthInFlight: Promise<boolean> | null = null

  function withFreshAuth(init?: RequestInit): RequestInit | undefined {
    if (!token.value) return init
    const curHeaders = (init?.headers ?? {}) as any
    const nextHeaders: Record<string, string> = {}
    try {
      if (curHeaders instanceof Headers) {
        curHeaders.forEach((v: string, k: string) => {
          nextHeaders[k] = v
        })
      } else if (Array.isArray(curHeaders)) {
        for (const [k, v] of curHeaders) nextHeaders[String(k)] = String(v)
      } else {
        Object.assign(nextHeaders, curHeaders)
      }
    } catch {
      // ignore
    }
    nextHeaders.Authorization = `Bearer ${token.value}`
    return { ...(init ?? {}), headers: nextHeaders }
  }

  async function silentReauthIfPossible(): Promise<boolean> {
    if (!stayLoggedIn.value) return false
    if (!username.value) return false

    if (reauthInFlight) return await reauthInFlight

    reauthInFlight = (async () => {
      try {
        // Ensure we have a private key to complete the challenge.
        if (!privateKey.value) {
          await tryRestoreStayUnlockBlob()
        }
        if (!privateKey.value) return false

        const publicJwk =
          publicKeyJwk.value ??
          (lastPrivateJwkJsonForStay ? publicJwkFromPrivateJwk(lastPrivateJwkJsonForStay) : null)
        if (!publicJwk) return false

        const uname = username.value
        if (!uname) return false
        const nameToken = await voprfNameToken({ kind: 'user', input: uname })

        const initRes = await fetch(`${apiBase()}/api/auth/login-init`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nameToken, publicKey: publicJwk }),
        })
        const initJson = await initRes.json().catch(() => ({}))
        if (!initRes.ok) return false

        const challengeId = typeof (initJson as any)?.challengeId === 'string' ? String((initJson as any).challengeId) : ''
        const encryptedChallengeB64 =
          typeof (initJson as any)?.encryptedChallengeB64 === 'string' ? String((initJson as any).encryptedChallengeB64) : ''
        if (!challengeId || !encryptedChallengeB64) return false

        const challengePlain = await decryptSmallStringWithPrivateKey({ ciphertextB64: encryptedChallengeB64, privateKey: privateKey.value })

        const finalRes = await fetch(`${apiBase()}/api/auth/login-final`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challengeId, response: challengePlain }),
        })
        const finalJson = await finalRes.json().catch(() => ({}))
        if (!finalRes.ok) return false

        token.value = typeof (finalJson as any)?.token === 'string' ? String((finalJson as any).token) : null
        expiresAtMs.value = typeof (finalJson as any)?.expiresAt === 'number' ? Number((finalJson as any).expiresAt) : null
        userId.value = typeof (finalJson as any)?.userId === 'string' ? String((finalJson as any).userId) : userId.value
        // Server no longer returns plaintext usernames; keep the local value.
        hiddenMode.value = Boolean((finalJson as any)?.hiddenMode)
        introvertMode.value = Boolean((finalJson as any)?.introvertMode)
        publicKeyJwk.value = publicJwk

        if (token.value && userId.value && username.value) {
          storeSession(
            { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
            token.value,
            expiresAtMs.value,
          )
          void localData.mirrorAuthSessionToIdb({
            user: { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
            token: token.value,
            expiresAtMs: expiresAtMs.value,
          })
        }

        // Re-establish realtime with the new token.
        void connectWs()
        scheduleTokenRefresh()
        return Boolean(token.value)
      } catch {
        return false
      } finally {
        reauthInFlight = null
      }
    })()

    return await reauthInFlight
  }

  async function fetchJson(path: string, init?: RequestInit, allowReauth = true) {
    const r = await fetch(`${apiBase()}${path}`, init)
    const j = await r.json().catch(() => ({}))
    if (!r.ok) {
      if (r.status === 401) {
        const msg = typeof j?.error === 'string' ? j.error : 'Unauthorized'

        // If we had a token, it likely expired / server restarted.
        // In stay-login mode, try to re-auth silently using the stored private key.
        if (token.value && stayLoggedIn.value && allowReauth) {
          const ok = await silentReauthIfPossible()
          if (ok) {
            return await fetchJson(path, withFreshAuth(init), false)
          }
        }

        if (token.value) {
          try {
            // If we can't reauth in stay mode, wipe stay artifacts so the private key isn't left behind.
            if (stayLoggedIn.value) logout(true)
            else logout()
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

  function sendReliableMessage(obj: unknown) {
    transportClient.sendJson(obj)
  }

  function sendDatagram(obj: unknown) {
    transportClient.sendDatagramJson(obj)
  }

  function sendWs(obj: unknown) {
    sendReliableMessage(obj)
  }

  let wsTokenForConnection: string | null = null

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
    const currentToken = token.value
    if (!currentToken) return

    const requireWebTransport = String(import.meta.env.VITE_REQUIRE_WEBTRANSPORT ?? '1') !== '0'
    const hasWebTransport = typeof window !== 'undefined' && typeof (window as any).WebTransport === 'function'
    if (requireWebTransport && !hasWebTransport) {
      wsShouldReconnect.value = false
      wsPermanentlyFailed.value = true
      transportFatalReason.value = 'WebTransport is not supported in this browser/environment.'
      clearWsReconnectTimer()
      clearPresenceTimer()
      return
    }

    // Idempotency: avoid tearing down a healthy socket on focus/visibility events.
    // Reconnect is still triggered when token changes (e.g. refresh) or when the socket is closed.
    const cur = transportClient.getSocket()
    if (
      cur &&
      (cur.readyState === WebSocket.OPEN || cur.readyState === WebSocket.CONNECTING) &&
      wsTokenForConnection === currentToken
    ) {
      return
    }

    // Bump generation first so close/error events from older sockets are ignored.
    wsGeneration += 1
    const gen = wsGeneration

    wsShouldReconnect.value = true
    wsPermanentlyFailed.value = false
    transportFatalReason.value = ''
    clearWsReconnectTimer()
    disconnectWs()
    wsTokenForConnection = currentToken

    const sock = transportClient.connect(transportAuthUrl(currentToken), {
      onOpen: () => {
        if (gen !== wsGeneration) return
        wsReconnectAttempt.value = 0
        // Presence heartbeats are disabled after permanent realtime failure.
        if (!wsPermanentlyFailed.value) startPresenceHeartbeat()
        void syncAfterConnect()
        void trySyncPushSubscription()
      },
      onClose: () => {
        if (gen !== wsGeneration) return
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
      },
      onError: () => {
        if (gen !== wsGeneration) return
        // Some browsers fire error without a close; force close and let the close handler schedule reconnect.
        transportClient.disconnect(true)
      },
      onMessage: async (raw) => {
        let obj: any
        try {
          obj = JSON.parse(String(raw))
        } catch {
          return
        }
        if (!obj || typeof obj.type !== 'string') return

        if (obj.type === 'authForceLogout') {
          const msgId = typeof (obj as any)?.msgId === 'string' ? String((obj as any).msgId) : ''
          if (msgId) sendReliableMessage({ type: 'ack', msgId })

          const wipeLocalKeys = Boolean((obj as any)?.wipeLocalKeys)
          try {
            if (wipeLocalKeys) {
              clearAllKeyMaterial()
              storeLastUsername('')
              logout(true)
            } else {
              logout(false)
            }
          } catch {
            // ignore
          }
          return
        }

        if (obj.type === 'authAccountUpdated') {
          const nextHidden = typeof (obj as any)?.hiddenMode === 'boolean' ? Boolean((obj as any).hiddenMode) : null
          const nextIntrovert = typeof (obj as any)?.introvertMode === 'boolean' ? Boolean((obj as any).introvertMode) : null

          if (nextHidden != null) hiddenMode.value = nextHidden
          if (nextIntrovert != null) introvertMode.value = nextIntrovert

          if (token.value && userId.value && username.value) {
            storeSession(
              { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
              token.value,
              expiresAtMs.value,
            )
          }
          return
        }

        if (obj.type === 'authMessage') {
          const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
          const id = typeof obj.id === 'string' ? obj.id : null
          const senderId = typeof obj.senderId === 'string' ? obj.senderId : null
          const encryptedData = typeof obj.encryptedData === 'string' ? obj.encryptedData : null
          const signature = typeof obj.signature === 'string' ? obj.signature : ''
          if (!chatId || !id || !senderId || !encryptedData) return

          const verification = await getIncomingEnvelopeVerification({ chatId, senderId, encryptedData, signature })
          if (verification === 'invalid') {
            toast.push({
              title: 'Unverified message',
              message: 'Blocked a message with an invalid signature.',
              variant: 'error',
              timeoutMs: 8000,
            })
            return
          }

          if (privateKey.value && userId.value) {
            try {
              const plain = await decryptMessageEnvelope({
                encryptedData,
                myUserId: userId.value,
                myPrivateKey: privateKey.value,
                textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
                textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
              })
              const displayName = await resolveDisplayNameInChat(chatId, senderId)
              const msg: AuthDecryptedMessage = {
                id,
                chatId,
                atIso: plain.atIso,
                modifiedAtIso: plain.modifiedAtIso,
                senderId,
                fromUsername: displayName,
                text: plain.text,
                replyToId: plain.replyToId,
                verification,
              }

              const cur = messagesByChatId.value[chatId] ?? []
              if (cur.some((m) => m.id === id)) return
              messagesByChatId.value = { ...messagesByChatId.value, [chatId]: [...cur, msg] }

              if (!(view.value === 'chat' && activeChatId.value === chatId)) {
                unreadByChatId.value = {
                  ...unreadByChatId.value,
                  [chatId]: (unreadByChatId.value[chatId] ?? 0) + 1,
                }

                try {
                  const shouldNotify = typeof document !== 'undefined' && document.visibilityState !== 'visible'
                  if (shouldNotify) {
                    notify('Last', displayName ? `New message from ${displayName}` : 'New message', {
                      tag: `lrcom-chat-${String(chatId)}`,
                    })
                  }
                } catch {
                  // ignore
                }
              }

              if (view.value === 'chat' && activeChatId.value === chatId && userId.value && String(senderId) !== String(userId.value)) {
                void markMessagesRead(chatId, [id])
              }

              lastMessageByChatId.value = {
                ...lastMessageByChatId.value,
                [chatId]: { id, chatId, senderId, encryptedData, signature },
              }
              lastMessagePreviewByChatId.value = {
                ...lastMessagePreviewByChatId.value,
                [chatId]: {
                  id,
                  chatId,
                  senderId,
                  senderUsername: displayName,
                  tsMs: uuidV7ToUnixMs(id) ?? 0,
                  text: plain.text,
                },
              }
            } catch {
              // ignore decrypt failures
            }
          }
        }

        if (obj.type === 'authMessageDeleted') {
          const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
          const id = typeof obj.id === 'string' ? obj.id : null
          if (!chatId || !id) return

          const cur = messagesByChatId.value[chatId] ?? []
          if (cur.length) {
            messagesByChatId.value = { ...messagesByChatId.value, [chatId]: cur.filter((m) => m.id !== id) }
          }
          void refreshChats()
        }

        if (obj.type === 'authMessagesDeleted') {
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

        if (obj.type === 'authMessageUpdated') {
          const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
          const id = typeof obj.id === 'string' ? obj.id : null
          const senderId = typeof obj.senderId === 'string' ? obj.senderId : null
          const encryptedData = typeof obj.encryptedData === 'string' ? obj.encryptedData : null
          const signature = typeof obj.signature === 'string' ? obj.signature : ''
          if (!chatId || !id || !senderId || !encryptedData) return

          const verification = await getIncomingEnvelopeVerification({ chatId, senderId, encryptedData, signature })
          if (verification === 'invalid') {
            toast.push({
              title: 'Unverified edit',
              message: 'Blocked an edited message with an invalid signature.',
              variant: 'error',
              timeoutMs: 8000,
            })
            return
          }

          if (privateKey.value && userId.value) {
            try {
              const plain = await decryptMessageEnvelope({
                encryptedData,
                myUserId: userId.value,
                myPrivateKey: privateKey.value,
                textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
                textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
              })
              const displayName = await resolveDisplayNameInChat(chatId, senderId)
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
                      verification,
                    }
                  : m,
              )
              messagesByChatId.value = { ...messagesByChatId.value, [chatId]: next }

              if (lastMessageByChatId.value[chatId]?.id === id) {
                lastMessageByChatId.value = {
                  ...lastMessageByChatId.value,
                  [chatId]: { id, chatId, senderId, encryptedData, signature },
                }
                lastMessagePreviewByChatId.value = {
                  ...lastMessagePreviewByChatId.value,
                  [chatId]: {
                    id,
                    chatId,
                    senderId,
                    senderUsername: displayName,
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

        if (obj.type === 'authChatDeleted') {
          const chatId = typeof obj.chatId === 'string' ? obj.chatId : null
          if (chatId) removeChatLocal(chatId)
        }

        if (obj.type === 'authChatsChanged') {
          const msgId = typeof (obj as any)?.msgId === 'string' ? String((obj as any).msgId) : ''
          if (msgId) sendReliableMessage({ type: 'ack', msgId })
          void refreshChats()
        }

        if (obj.type === 'presenceSnapshot') {
          const ids = getPresenceProbeList()
          const online = new Set<string>(Array.isArray((obj as any)?.onlineUserIds) ? (obj as any).onlineUserIds.map(String) : [])
          const busy = new Set<string>(Array.isArray((obj as any)?.busyUserIds) ? (obj as any).busyUserIds.map(String) : [])
          const next: Record<string, boolean> = {}
          const nextBusy: Record<string, boolean> = {}
          for (const id of ids) next[id] = online.has(id)
          for (const id of ids) nextBusy[id] = busy.has(id)
          onlineByUserId.value = next
          busyByUserId.value = nextBusy
          applyServerVersion((obj as any)?.serverVersion)
        }

        for (const h of inboundHandlers) {
          try {
            h(String(obj.type), obj as Record<string, unknown>)
          } catch {
            // ignore
          }
        }
      },
    })
    ws.value = sock
  }

  function disconnectWs() {
    // Callers can disable reconnect by setting wsShouldReconnect=false before disconnect.
    transportClient.disconnect(false)
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
    const j = await fetchJson('/api/chats', { headers: { ...authHeaders() } })

    const wireChats: any[] = Array.isArray((j as any)?.chats) ? (j as any).chats : []
    const nextChats: AuthChat[] = wireChats
      .map((c: any) => {
        const id = typeof c?.id === 'string' ? String(c.id) : ''
        const type = (c?.type === 'personal' || c?.type === 'group') ? c.type : null
        if (!id || !type) return null

        const chatNameEnc = typeof c?.chatNameEnc === 'string' ? String(c.chatNameEnc) : ''
        const names = c?.names && typeof c.names === 'object' ? (c.names as Record<string, string>) : {}
        const otherUserId = typeof c?.otherUserId === 'string' ? String(c.otherUserId) : undefined
        const otherPublicKey = typeof c?.otherPublicKey === 'string' ? String(c.otherPublicKey) : undefined

        return {
          id,
          type,
          chatNameEnc,
          names,
          otherUserId,
          otherPublicKey,
        } as AuthChat
      })
      .filter((x): x is AuthChat => Boolean(x))

    chats.value = nextChats

    // Best-effort: compute display names from encrypted metadata.
    if (privateKey.value && userId.value) {
      const withNames = await Promise.all(
        nextChats.map(async (c) => {
          try {
            if (c.type === 'group') {
              const dec = await decryptChatTextFromEnvelope(c.chatNameEnc ?? '')
              return { ...c, name: dec || 'Group' }
            }
            if (c.type === 'personal' && c.otherUserId) {
              const enc = (c.names && typeof c.names === 'object') ? c.names[c.otherUserId] : ''
              const dec = await decryptChatTextFromEnvelope(typeof enc === 'string' ? enc : '')
              return { ...c, name: dec || c.otherUserId }
            }
            return c
          } catch {
            return c
          }
        }),
      )
      chats.value = withNames
    }

    // New server versions may include `lastMessage` on each chat.
    const nextLast: Record<string, AuthLastMessageWire | null> = {}
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
        const signature = typeof lm?.signature === 'string' ? String(lm.signature) : ''

        if (!id || !senderId || !encryptedData) {
          nextLast[chatId] = null
          continue
        }

        nextLast[chatId] = { id, chatId, senderId, encryptedData, signature }
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
            const plain = await decryptMessageEnvelope({
              encryptedData: lm.encryptedData,
              myUserId: userId.value as string,
              myPrivateKey: privateKey.value as CryptoKey,
              textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
              textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
            })
            const tsMs = uuidV7ToUnixMs(lm.id) ?? 0
            const text = typeof plain?.text === 'string' ? plain.text : ''
            const senderUsername = await resolveDisplayNameInChat(chatId, lm.senderId)
            const preview: AuthLastMessagePreview = {
              id: lm.id,
              chatId,
              senderId: lm.senderId,
              senderUsername,
              tsMs,
              text,
            }
            return { chatId, preview }
          } catch {
            return null
          }
        }),
      )

      const nextPreview: Record<string, AuthLastMessagePreview> = {}
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

  function getChat(chatId: string): AuthChat | null {
    const c = chats.value.find((x) => x.id === chatId)
    return c ?? null
  }

  function getChatLastMessagePreview(chatId: string): AuthLastMessagePreview | null {
    return lastMessagePreviewByChatId.value[chatId] ?? null
  }

  function getChatLastMessageTsMs(chatId: string): number {
    return getChatLastMessagePreview(chatId)?.tsMs ?? 0
  }

  async function fetchChatMembers(chatId: string) {
    const j = await fetchJson(`/api/chats/members?chatId=${encodeURIComponent(chatId)}`, {
      headers: { ...authHeaders() },
    })

    const list: AuthChatMember[] = Array.isArray(j.members)
      ? j.members
          .filter((m: any) => m && typeof m.userId === 'string' && typeof m.publicKey === 'string')
          .map((m: any) => ({ userId: String(m.userId), publicKey: String(m.publicKey) }))
      : []

    let out = list
    try {
      if (privateKey.value && userId.value) {
        out = await Promise.all(
          list.map(async (m) => ({
            ...m,
            username: await resolveDisplayNameInChat(chatId, m.userId),
          })),
        )
      }
    } catch {
      // ignore
    }

    membersByChatId.value = { ...membersByChatId.value, [chatId]: out }
    return out
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

    // Best-effort: mark the chat as read when opened.
    // This is a fallback for platforms where IntersectionObserver can be unreliable
    // inside overflow containers.
    void markChatRead(chatId)

    // Best-effort: prefetch group members so we can encrypt to all.
    try {
      const chat = getChat(chatId)
      if (chat?.type === 'group') await ensureChatMembers(chatId)
    } catch {
      // ignore
    }
  }

  async function markChatRead(chatId: string) {
    if (!token.value) return
    try {
      const j = await fetchJson('/api/messages/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ chatId }),
      })
      const next = typeof (j as any)?.unreadCount === 'number' ? Number((j as any).unreadCount) : 0
      unreadByChatId.value = { ...unreadByChatId.value, [chatId]: Math.max(0, next) }

      // Best-effort: if user read it, close any delivered push notification.
      void closeNotificationsByTag(`lrcom-chat-${String(chatId)}`)
    } catch {
      // ignore
    }
  }

  async function markMessagesRead(chatId: string, messageIds: string[]) {
    if (!token.value) return
    const ids = Array.isArray(messageIds) ? messageIds.map(String).filter(Boolean) : []
    if (!ids.length) return
    try {
      const j = await fetchJson('/api/messages/mark-read', {
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
    const j = await fetchJson(`/api/messages/unread?chatId=${encodeURIComponent(chatId)}&limit=${encodeURIComponent(String(limit))}`, {
      headers: { ...authHeaders() },
    })
    return Array.isArray(j?.messageIds) ? j.messageIds.map(String) : []
  }

  async function deleteMessage(chatId: string, messageId: string) {
    await fetchJson('/api/messages/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, messageId }),
    })
  }

  async function updateMessage(chatId: string, messageId: string, encryptedData: string) {
    if (utf8ByteLength(encryptedData) > MAX_ENCRYPTED_MESSAGE_BYTES) throw new Error(ERR_ENCRYPTED_TOO_LARGE)

    let signature = ''
    try {
      if (signingKey.value && userId.value) {
        signature = await signEnvelope({ signingKey: signingKey.value, senderId: userId.value, chatId, encryptedData })
      }
    } catch {
      signature = ''
    }

    await fetchJson('/api/messages/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, messageId, encryptedData, signature }),
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

    const encryptedData = await encryptMessageEnvelope({
      plaintext: { text: t, atIso, replyToId, modifiedAtIso },
      recipients,
      textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
      textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
    })

    if (utf8ByteLength(encryptedData) > MAX_ENCRYPTED_MESSAGE_BYTES) throw new Error(ERR_ENCRYPTED_TOO_LARGE)

    await updateMessage(chatId, messageId, encryptedData)

    // Optimistic local patch (realtime update is best-effort).
    const next: AuthDecryptedMessage[] = cur.map((m): AuthDecryptedMessage =>
      m.id === messageId
        ? { ...m, senderId: userId.value as string, atIso, modifiedAtIso, fromUsername: username.value as string, text: t, replyToId, verification: 'verified' }
        : m,
    )
    messagesByChatId.value = { ...messagesByChatId.value, [chatId]: next }
  }

  async function deleteChat(chatId: string) {
    await fetchJson('/api/chats/delete', {
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
    sendPresenceHeartbeat()
  }

  function goHome() {
    view.value = 'contacts'
    sendPresenceHeartbeat()
  }

  function openSettings() {
    view.value = 'settings'
  }

  async function lookupAuthUserByUsername(name: string): Promise<{ userId: string; publicKey: string }> {
    const u = String(name ?? '').trim()
    if (!u) throw new Error('Username required')

    const nameToken = await voprfNameToken({ kind: 'user', input: u })
    const j = await fetchJson('/api/users/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ nameToken }),
    })

    const userIdOut = typeof (j as any)?.userId === 'string' ? String((j as any).userId) : ''
    const publicKeyOut = typeof (j as any)?.publicKey === 'string' ? String((j as any).publicKey) : ''
    if (!userIdOut || !publicKeyOut) throw new Error('not_found')
    return { userId: userIdOut, publicKey: publicKeyOut }
  }

  async function encryptChatTextToRecipients(params: {
    text: string
    recipients: Array<{ userId: string; publicKeyJwk: string }>
  }): Promise<string> {
    return await encryptMessageEnvelope({
      plaintext: { text: String(params.text ?? ''), atIso: new Date().toISOString() },
      recipients: params.recipients,
      textPadMinChars: CHAT_META_TEXT_PAD_MIN_CHARS,
      textPadMaxChars: CHAT_META_TEXT_PAD_MAX_CHARS,
    })
  }

  async function decryptChatTextFromEnvelope(enc: string): Promise<string | null> {
    if (!privateKey.value || !userId.value) return null
    const s = String(enc ?? '')
    if (!s) return null
    try {
      const plain = await decryptMessageEnvelope({
        encryptedData: s,
        myUserId: userId.value,
        myPrivateKey: privateKey.value,
        textPadMinChars: CHAT_META_TEXT_PAD_MIN_CHARS,
        textPadMaxChars: CHAT_META_TEXT_PAD_MAX_CHARS,
      })
      return typeof plain?.text === 'string' ? plain.text : ''
    } catch {
      return null
    }
  }

  async function buildNamesJson(params: {
    recipients: Array<{ userId: string; publicKeyJwk: string }>
    namesPlainByUserId: Record<string, string>
  }): Promise<Record<string, string>> {
    const out: Record<string, string> = {}
    for (const [uid, nm] of Object.entries(params.namesPlainByUserId ?? {})) {
      const key = String(uid)
      if (!key) continue
      out[key] = await encryptChatTextToRecipients({ text: String(nm ?? ''), recipients: params.recipients })
    }
    return out
  }

  async function resolveDisplayNameInChat(chatId: string, subjectUserId: string): Promise<string> {
    const uid = String(subjectUserId ?? '')
    if (!uid) return ''

    if (userId.value && username.value && String(uid) === String(userId.value)) return username.value

    const chat = getChat(chatId)
    if (!chat) return uid

    const names = (chat.names && typeof chat.names === 'object') ? chat.names : null
    const enc = names && typeof (names as any)[uid] === 'string' ? String((names as any)[uid]) : ''
    const dec = await decryptChatTextFromEnvelope(enc)
    if (dec) return dec

    if (chat.type === 'personal' && chat.otherUserId && String(chat.otherUserId) === uid && typeof chat.name === 'string' && chat.name) {
      return chat.name
    }

    return uid
  }

  function resolveSenderPublicKeyJwk(chatId: string, senderId: string): string | null {
    const sid = String(senderId ?? '')
    if (!sid) return null

    if (userId.value && publicKeyJwk.value && String(sid) === String(userId.value)) {
      return publicKeyJwk.value
    }

    const chat = getChat(chatId)
    if (!chat) return null

    if (chat.type === 'personal') {
      if (chat.otherUserId && String(chat.otherUserId) === sid && chat.otherPublicKey) return String(chat.otherPublicKey)
      return null
    }

    const members = membersByChatId.value[chatId] ?? []
    const m = members.find((x) => String(x.userId) === sid)
    return m?.publicKey ? String(m.publicKey) : null
  }

  async function verifyIncomingEnvelope(params: {
    chatId: string
    senderId: string
    encryptedData: string
    signature: string
  }): Promise<boolean | null> {
    const sig = String(params.signature ?? '')
    if (!sig) return null

    let pubJwk = resolveSenderPublicKeyJwk(params.chatId, params.senderId)
    if (!pubJwk) {
      const chat = getChat(params.chatId)
      if (chat?.type === 'group') {
        try {
          await ensureChatMembers(params.chatId)
        } catch {
          // ignore
        }
        pubJwk = resolveSenderPublicKeyJwk(params.chatId, params.senderId)
      }
    }
    if (!pubJwk) return null

    const verifyKey = await getVerifyKeyFromPublicJwk(pubJwk)
    return await verifyEnvelope({
      verifyKey,
      signatureB64: sig,
      senderId: String(params.senderId),
      chatId: String(params.chatId),
      encryptedData: String(params.encryptedData),
    })
  }

  async function getIncomingEnvelopeVerification(params: {
    chatId: string
    senderId: string
    encryptedData: string
    signature: string
  }): Promise<AuthMessageVerification | 'invalid'> {
    try {
      const ok = await verifyIncomingEnvelope(params)
      if (ok === false) return 'invalid'
      return ok === true ? 'verified' : 'unverifiable'
    } catch {
      return 'unverifiable'
    }
  }

  async function createPersonalChat(friendUsername: string) {
    const u = friendUsername.trim()
    if (!u) throw new Error('Username required')

    if (!userId.value || !username.value || !publicKeyJwk.value) throw new Error('Not logged in')

    // Avoid creating a private chat with yourself.
    if (username.value && u.toLowerCase() === String(username.value).toLowerCase()) {
      throw new Error('self')
    }

    const other = await lookupAuthUserByUsername(u)

    const recipients = [
      { userId: userId.value, publicKeyJwk: publicKeyJwk.value },
      { userId: other.userId, publicKeyJwk: other.publicKey },
    ]

    const names = await buildNamesJson({
      recipients,
      namesPlainByUserId: {
        [userId.value]: username.value,
        [other.userId]: u,
      },
    })

    const j = await fetchJson('/api/chats/create-personal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ otherUserId: other.userId, names }),
    })

    await refreshChats()

    if (j?.chat?.id) {
      await openChat(String(j.chat.id))
    }

  }

  async function createGroupChat(name: string) {
    const n = name.trim()
    if (!n) throw new Error('Name required')

    if (!userId.value || !username.value || !publicKeyJwk.value) throw new Error('Not logged in')

    const recipients = [{ userId: userId.value, publicKeyJwk: publicKeyJwk.value }]
    const chatNameEnc = await encryptChatTextToRecipients({ text: n, recipients })
    const names = await buildNamesJson({ recipients, namesPlainByUserId: { [userId.value]: username.value } })

    const j = await fetchJson('/api/chats/create-group', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatNameEnc, names }),
    })

    await refreshChats()
    if (j?.chat?.id) await openChat(String(j.chat.id))
  }

  async function addGroupMember(chatId: string, memberUsername: string) {
    const u = memberUsername.trim()
    if (!u) throw new Error('Username required')

    if (!userId.value || !username.value || !publicKeyJwk.value) throw new Error('Not logged in')

    const chat = getChat(chatId)
    if (!chat || chat.type !== 'group') throw new Error('not_group')

    const other = await lookupAuthUserByUsername(u)

    const curMembers = await ensureChatMembers(chatId)
    const recipients: Array<{ userId: string; publicKeyJwk: string }> = [
      ...curMembers.map((m) => ({ userId: m.userId, publicKeyJwk: m.publicKey })),
      { userId: other.userId, publicKeyJwk: other.publicKey },
    ]

    const groupNamePlain =
      (await decryptChatTextFromEnvelope(chat.chatNameEnc ?? '')) ??
      (typeof chat.name === 'string' ? chat.name : '')

    const chatNameEnc = await encryptChatTextToRecipients({ text: groupNamePlain || 'Group', recipients })

    // Re-encrypt all existing per-user name blobs to include the new recipient,
    // and add a blob for the new member using the entered username.
    const curNames = (chat.names && typeof chat.names === 'object') ? chat.names : {}
    const namesPlainByUserId: Record<string, string> = {}
    for (const [uid, enc] of Object.entries(curNames)) {
      const t = await decryptChatTextFromEnvelope(typeof enc === 'string' ? enc : '')
      namesPlainByUserId[String(uid)] = t ?? String(uid)
    }
    namesPlainByUserId[other.userId] = u

    const names = await buildNamesJson({ recipients, namesPlainByUserId })

    const j = await fetchJson('/api/chats/add-member', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, otherUserId: other.userId, chatNameEnc, names }),
    })

    // Best-effort: update cached members.
    const member = j?.member
    if (member && typeof member.userId === 'string' && typeof member.publicKey === 'string') {
      const cur = membersByChatId.value[chatId] ?? []
      const exists = cur.some((m) => m.userId === String(member.userId))
      if (!exists) {
        membersByChatId.value = {
          ...membersByChatId.value,
          [chatId]: [...cur, { userId: String(member.userId), publicKey: String(member.publicKey) }],
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

    const members = await ensureChatMembers(cid)
    const recipients = members.map((m) => ({ userId: m.userId, publicKeyJwk: m.publicKey }))
    const chatNameEnc = await encryptChatTextToRecipients({ text: n, recipients })

    const j = await fetchJson('/api/chats/rename-group', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId: cid, chatNameEnc }),
    })

    const chat = j?.chat
    if (!chat || typeof chat.id !== 'string') throw new Error('Bad response')

    // Best-effort: update local chat list.
    chats.value = chats.value.map((c) => (String(c.id) === String(chat.id) ? { ...c, name: n, chatNameEnc } : c))
    return chat
  }

  async function loadMessages(chatId: string, limit = 50) {
    const lim = Math.max(1, Math.min(200, Number(limit) || 50))

    const j = await fetchJson(`/api/messages?chatId=${encodeURIComponent(chatId)}&limit=${encodeURIComponent(String(lim))}`, {
      headers: { ...authHeaders() },
    })

    const wire: any[] = Array.isArray(j.messages) ? j.messages : []
    const list: AuthMessage[] = wire
      .map((m: any) => {
        const id = typeof m?.id === 'string' ? String(m.id) : ''
        const senderId = typeof m?.senderId === 'string' ? String(m.senderId) : ''
        const encryptedData = typeof m?.encryptedData === 'string' ? String(m.encryptedData) : ''
        const signature = typeof m?.signature === 'string' ? String(m.signature) : ''
        if (!id || !senderId || !encryptedData) return null
        const out: AuthMessage = { id, chatId, senderId, encryptedData, signature: signature || undefined }
        return out
      })
      .filter((x): x is AuthMessage => x !== null)

    if (!privateKey.value || !userId.value) {
      messagesByChatId.value = { ...messagesByChatId.value, [chatId]: [] }
      const { [chatId]: _o, ...restOldest } = messagesOldestIdByChatId.value
      messagesOldestIdByChatId.value = restOldest
      messagesHasMoreByChatId.value = { ...messagesHasMoreByChatId.value, [chatId]: false }
      return { count: 0, hasMore: false, oldestId: null as string | null }
    }

    const out: AuthDecryptedMessage[] = []
    let blocked = 0
    for (const m of list) {
      try {
        const verification = await getIncomingEnvelopeVerification({
          chatId,
          senderId: String(m.senderId),
          encryptedData: String(m.encryptedData),
          signature: typeof m.signature === 'string' ? m.signature : '',
        })
        if (verification === 'invalid') {
          blocked += 1
          continue
        }

        const plain = await decryptMessageEnvelope({
          encryptedData: m.encryptedData,
          myUserId: userId.value,
          myPrivateKey: privateKey.value,
          textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
          textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
        })
        const displayName = await resolveDisplayNameInChat(chatId, String(m.senderId))
        out.push({
          id: m.id,
          chatId,
          senderId: String(m.senderId),
          atIso: plain.atIso,
          modifiedAtIso: plain.modifiedAtIso,
          fromUsername: displayName,
          text: plain.text,
          replyToId: plain.replyToId,
          verification,
        })
      } catch {
        // ignore undecryptable messages
      }
    }

    if (blocked) {
      toast.push({
        title: 'Unverified messages',
        message: `Blocked ${blocked} message${blocked === 1 ? '' : 's'} with invalid signatures.`,
        variant: 'error',
        timeoutMs: 8000,
      })
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
        `/api/messages?chatId=${encodeURIComponent(chatId)}&limit=${encodeURIComponent(String(lim))}&before=${encodeURIComponent(before)}`,
        { headers: { ...authHeaders() } },
      )

      const wire: any[] = Array.isArray(j.messages) ? j.messages : []
      const list: AuthMessage[] = wire
        .map((m: any) => {
          const id = typeof m?.id === 'string' ? String(m.id) : ''
          const senderId = typeof m?.senderId === 'string' ? String(m.senderId) : ''
          const encryptedData = typeof m?.encryptedData === 'string' ? String(m.encryptedData) : ''
          const signature = typeof m?.signature === 'string' ? String(m.signature) : ''
          if (!id || !senderId || !encryptedData) return null
          const out: AuthMessage = { id, chatId, senderId, encryptedData, signature: signature || undefined }
          return out
        })
        .filter((x): x is AuthMessage => x !== null)

      const decoded: AuthDecryptedMessage[] = []
      let blocked = 0
      for (const m of list) {
        try {
          const verification = await getIncomingEnvelopeVerification({
            chatId,
            senderId: String(m.senderId),
            encryptedData: String(m.encryptedData),
            signature: typeof m.signature === 'string' ? m.signature : '',
          })
          if (verification === 'invalid') {
            blocked += 1
            continue
          }

          const plain = await decryptMessageEnvelope({
            encryptedData: m.encryptedData,
            myUserId: userId.value,
            myPrivateKey: privateKey.value,
            textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
            textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
          })
          const displayName = await resolveDisplayNameInChat(chatId, String(m.senderId))
          decoded.push({
            id: m.id,
            chatId,
            senderId: String(m.senderId),
            atIso: plain.atIso,
            modifiedAtIso: plain.modifiedAtIso,
            fromUsername: displayName,
            text: plain.text,
            replyToId: plain.replyToId,
            verification,
          })
        } catch {
          // ignore
        }
      }

      if (blocked) {
        toast.push({
          title: 'Unverified messages',
          message: `Blocked ${blocked} message${blocked === 1 ? '' : 's'} with invalid signatures.`,
          variant: 'error',
          timeoutMs: 8000,
        })
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
    if (!signingKey.value) throw new Error('Not unlocked')

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

    const encryptedData = await encryptMessageEnvelope({
      plaintext: { text: t, atIso, replyToId, modifiedAtIso: null },
      recipients,
      textPadMinChars: MESSAGE_TEXT_PAD_MIN_CHARS,
      textPadMaxChars: MESSAGE_TEXT_PAD_MAX_CHARS,
    })

    const signature = await signEnvelope({ signingKey: signingKey.value, senderId: userId.value, chatId, encryptedData })

    if (utf8ByteLength(encryptedData) > MAX_ENCRYPTED_MESSAGE_BYTES) throw new Error(ERR_ENCRYPTED_TOO_LARGE)

    const j = await fetchJson('/api/messages/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ chatId, encryptedData, signature }),
    })

    const msgId = typeof j.messageId === 'string' ? j.messageId : null
    if (!msgId) return

    // Append optimistically (it will also arrive via realtime events, but those are best-effort).
    const cur = messagesByChatId.value[chatId] ?? []
    if (cur.some((m) => m.id === msgId)) return
    messagesByChatId.value = {
      ...messagesByChatId.value,
      [chatId]: [...cur, { id: msgId, chatId, senderId: userId.value, atIso, modifiedAtIso: null, fromUsername: username.value, text: t, replyToId, verification: 'verified' }],
    }
  }

  async function register(params: { username: string; password: string; expirationDays: number }) {
    const u = params.username.trim()
    if (!u) throw new Error('Username required')
    if (u.length < 3 || u.length > 64) throw new Error('Username must be between 3 and 64 characters')
    assertUsernameIsXssSafe(u)

    if (!params.password) throw new Error('Password required')
    if (params.password.length < 8) throw new Error('Password must be at least 8 characters')
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    const exp = Number(params.expirationDays)
    if (!Number.isFinite(exp) || exp < 7 || exp > 365) {
      throw new Error('Expiration days must be between 7 and 365')
    }

    const nameToken = await voprfNameToken({ kind: 'user', input: u })

    // Check name-token availability before generating/storing key material.
    const check = await fetchJson('/api/auth/check-name-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nameToken }),
    })
    if (check && check.exists === true) {
      throw new Error('Username already exists')
    }

    storeLastUsername(u)

    const { publicJwk, privateJwk } = await generateRsaKeyPair()

    // Cache JWK for optional stay-login auto-unlock.
    lastPrivateJwkJsonForStay = privateJwk

    // Import private key before setting token/userId so App.vue doesn't interpret
    // the session as "authenticated but locked" mid-register and auto-logout.
    const importedPrivateKey = await importRsaPrivateKeyJwk(privateJwk)
    const importedSigningKey = await importRsaPssPrivateKeyJwk(privateJwk)

    const vaultJson = makeVaultJson(exp)
    const vaultEnc = await encryptSmallStringWithPublicKeyJwk({ plaintext: vaultJson, publicKeyJwkJson: publicJwk })
    const removeDate = computeRemoveDateIsoForNow(exp)

    const j = await fetchJson('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nameToken,
        publicKey: publicJwk,
        removeDate,
        vault: vaultEnc,
      }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk

    vaultEncrypted.value = vaultEnc
    vaultPlain.value = parseVaultPlain(vaultJson)
    storeVaultPlain(vaultJson)

    removeDateIso.value = removeDate
    storeRemoveDateIso(removeDate)

    privateKey.value = importedPrivateKey
    signingKey.value = importedSigningKey

    // Persist key material only after server registration succeeds.
    await saveLocalKeyForUser({ username: u, password: params.password, privateKeyMaterial: privateJwk })

    if (token.value && userId.value && username.value) {
      storeSession(
        { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
        token.value,
        expiresAtMs.value,
      )
    }

    // Variant B: if stay mode is enabled, persist auto-unlock blob from private JWK.
    void persistStayUnlockBlobFromPrivateJwk(privateJwk)

    await refreshChats()
    await connectWs()
    void maybeAddChatFromUrl()
    void maybeOpenChatFromUrl()
    scheduleTokenRefresh()
    startRemoveDateSyncTimer()
    void trySyncPushSubscription()
    view.value = 'contacts'
  }

  async function login(params: { username: string; password: string }) {
    const u = params.username.trim()
    if (!u) throw new Error('Username required')
    assertUsernameIsXssSafe(u)
    if (!params.password) throw new Error('Password required')
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    storeLastUsername(u)

    const localKey = await findLocalKeyMaterialForLogin({ username: u, password: params.password })
    if (!localKey) throw new Error('No local key found')

    const privateJwk = localKey.privateKeyMaterial
    const signingJwk = localKey.signingKeyMaterial
    // Cache JWK for optional stay-login auto-unlock.
    lastPrivateJwkJsonForStay = privateJwk
    const priv = await importRsaPrivateKeyJwk(privateJwk)
    const signPriv = await importRsaPssPrivateKeyJwk(signingJwk)

    const publicJwk = publicJwkFromPrivateJwk(privateJwk)

    const nameToken = await voprfNameToken({ kind: 'user', input: u })

    const init = await fetchJson('/api/auth/login-init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nameToken, publicKey: publicJwk }),
    })

    const challengeId = typeof (init as any)?.challengeId === 'string' ? String((init as any).challengeId) : ''
    const encryptedChallengeB64 = typeof (init as any)?.encryptedChallengeB64 === 'string' ? String((init as any).encryptedChallengeB64) : ''
    if (!challengeId || !encryptedChallengeB64) throw new Error('Login failed')

    const challengePlain = await decryptSmallStringWithPrivateKey({ ciphertextB64: encryptedChallengeB64, privateKey: priv })

    const j = await fetchJson('/api/auth/login-final', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId, response: challengePlain }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk
    privateKey.value = priv
    signingKey.value = signPriv

    vaultEncrypted.value = typeof (j as any)?.vault === 'string' ? String((j as any).vault) : ''
    if (vaultEncrypted.value) {
      try {
        const vaultJson = await decryptSmallStringWithPrivateKey({ ciphertextB64: vaultEncrypted.value, privateKey: priv })
        const parsed = parseVaultPlain(vaultJson)
        vaultPlain.value = parsed
        if (parsed) storeVaultPlain(vaultJson)
      } catch {
        // ignore
      }
    }
    if (!vaultPlain.value) {
      vaultPlain.value = loadVaultPlain()
    }

    if (token.value && userId.value && username.value) {
      storeSession(
        { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
        token.value,
        expiresAtMs.value,
      )
    }

    // Variant B: if stay mode is enabled, persist auto-unlock blob from private JWK.
    void persistStayUnlockBlobFromPrivateJwk(privateJwk)

    // Migrate/ensure low-profile local storage now that we have the password.
    await saveLocalKeyForUser({
      username: u,
      password: params.password,
      privateKeyMaterial: privateJwk,
      signingKeyMaterial: signingJwk !== privateJwk ? signingJwk : undefined,
    })

    await refreshChats()
    await connectWs()
    void maybeAddChatFromUrl()
    void maybeOpenChatFromUrl()
    scheduleTokenRefresh()
    // Separate call after login.
    void bestEffortSyncRemoveDateNow()
    startRemoveDateSyncTimer()
    void trySyncPushSubscription()
    view.value = 'contacts'
  }

  async function recreateAccount(params: { username: string; password: string; expirationDays: number }) {
    const u = params.username.trim()
    if (!u) throw new Error('Username required')
    if (u.length < 3 || u.length > 64) throw new Error('Username must be between 3 and 64 characters')
    assertUsernameIsXssSafe(u)

    if (!params.password) throw new Error('Password required')
    if (params.password.length < 8) throw new Error('Password must be at least 8 characters')
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)

    const exp = Number(params.expirationDays)
    if (!Number.isFinite(exp) || exp < 7 || exp > 365) {
      throw new Error('Expiration days must be between 7 and 365')
    }

    storeLastUsername(u)

    const localKey = await findLocalKeyMaterialForLogin({ username: u, password: params.password })
    if (!localKey) throw new Error('No local key found')

    const privateJwk = localKey.privateKeyMaterial
    const signingJwk = localKey.signingKeyMaterial
    // Cache JWK for optional stay-login auto-unlock.
    lastPrivateJwkJsonForStay = privateJwk
    const priv = await importRsaPrivateKeyJwk(privateJwk)
    const signPriv = await importRsaPssPrivateKeyJwk(signingJwk)
    const publicJwk = publicJwkFromPrivateJwk(privateJwk)

    const vaultJson = makeVaultJson(exp)
    const vaultEnc = await encryptSmallStringWithPublicKeyJwk({ plaintext: vaultJson, publicKeyJwkJson: publicJwk })
    const removeDate = computeRemoveDateIsoForNow(exp)

    const nameToken = await voprfNameToken({ kind: 'user', input: u })

    const j = await fetchJson('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nameToken,
        publicKey: publicJwk,
        removeDate,
        vault: vaultEnc,
      }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk

    vaultEncrypted.value = vaultEnc
    vaultPlain.value = parseVaultPlain(vaultJson)
    storeVaultPlain(vaultJson)

    removeDateIso.value = removeDate
    storeRemoveDateIso(removeDate)

    privateKey.value = priv
    signingKey.value = signPriv

    if (token.value && userId.value && username.value) {
      storeSession(
        { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
        token.value,
        expiresAtMs.value,
      )
    }

    // Variant B: if stay mode is enabled, persist auto-unlock blob from private JWK.
    void persistStayUnlockBlobFromPrivateJwk(privateJwk)

    // Ensure low-profile local storage now that we have the password.
    await saveLocalKeyForUser({
      username: u,
      password: params.password,
      privateKeyMaterial: privateJwk,
      signingKeyMaterial: signingJwk !== privateJwk ? signingJwk : undefined,
    })

    await refreshChats()
    await connectWs()
    void maybeAddChatFromUrl()
    void maybeOpenChatFromUrl()
    scheduleTokenRefresh()
    // Separate call after login.
    void bestEffortSyncRemoveDateNow()
    startRemoveDateSyncTimer()
    void trySyncPushSubscription()
    view.value = 'contacts'
  }

  function logout(wipeSessionStorage = false) {
    // Best-effort: wipe push state on logout.
    void disablePushNotifications()

    // Best-effort: update remove_date on logout.
    try {
      const exp = vaultPlain.value?.expirationDays
      const currentToken = token.value
      if (currentToken && exp && Number.isFinite(exp)) {
        const iso = computeRemoveDateIsoForNow(exp)
        const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${currentToken}` }
        void fetch('/api/account/update', { method: 'POST', headers, body: JSON.stringify({ removeDate: iso }) }).catch(() => {})
      }
    } catch {
      // ignore
    }

    wsShouldReconnect.value = false
    wsPermanentlyFailed.value = false
    clearWsReconnectTimer()
    clearPresenceTimer()
    disconnectWs()
    clearTokenRefreshTimer()
    clearRemoveDateSyncTimer()
    token.value = null
    expiresAtMs.value = null
    userId.value = null
    username.value = null
    hiddenMode.value = false
    introvertMode.value = false
    publicKeyJwk.value = null
    privateKey.value = null
    signingKey.value = null
    vaultEncrypted.value = ''
    vaultPlain.value = null
    removeDateIso.value = null
    chats.value = []
    unreadByChatId.value = {}
    messagesByChatId.value = {}
    membersByChatId.value = {}
    activeChatId.value = null
    view.value = 'contacts'

    if (wipeSessionStorage) {
      lastUsername.value = ''
      pendingAddUsername.value = ''

      // Settings logout should wipe everything except encrypted key material.
      // Keep: encrypted key entries
      // Remove: all registered session/vault/prefs and stay-login artifacts.
      void localData.cleanup('logout_wipe')

      stayLoggedIn.value = false
      localData.setAuthStayLoggedIn(false)
    } else {
      clearSession()
    }

    clearVaultPlain()
    clearRemoveDateIso()
  }

  async function deleteAccount() {
    // Requires an active auth session.
    if (!token.value) throw new Error('Not logged in')

    await fetchJson('/api/account/delete', {
      method: 'POST',
      headers: { ...authHeaders() },
    })

    // Clear all local traces for this auth identity.
    // Without a stable plaintext identifier, prefer privacy: remove all stored auth keys.
    clearAllKeyMaterial()
    storeLastUsername('')
    logout(true)
  }

  async function logoutOtherDevices() {
    if (!token.value) throw new Error('Not logged in')
    await fetchJson('/api/session/logout-other-devices', {
      method: 'POST',
      headers: { ...authHeaders() },
    })
  }

  async function logoutAndRemoveKeyOtherDevices() {
    if (!token.value) throw new Error('Not logged in')
    await fetchJson('/api/session/logout-and-remove-key-other-devices', {
      method: 'POST',
      headers: { ...authHeaders() },
    })
  }

  // Attempt to restore token+user on refresh. In stay mode we will also restore
  // the private key via a device-bound auto-unlock blob in IndexedDB.
  const restored = loadSession()
  if (restored) {
    token.value = restored.t
    userId.value = restored.u.userId
    username.value = restored.u.username
    hiddenMode.value = Boolean(restored.u.hiddenMode)
    introvertMode.value = Boolean(restored.u.introvertMode)
    expiresAtMs.value = restored.e
    publicKeyJwk.value = null
    vaultPlain.value = loadVaultPlain()
    removeDateIso.value = loadRemoveDateIso()
    startRemoveDateSyncTimer()
  }

  // If not in stay mode, do not keep a "locked" session after refresh.
  if (restored && !stayLoggedIn.value) {
    try {
      logout(false)
    } catch {
      // ignore
    }
  }

  // Capture invite links on initial load, before login/register.
  pendingAddUsername.value = loadPendingAddUsername()
  if (!pendingAddUsername.value) capturePendingAddFromUrl()

  // Variant B: async restore from IndexedDB when stay mode is enabled.
  void (async () => {
    try {
      if (!stayLoggedIn.value) return

      if (!token.value) {
        const sess = await localData.idbGet<{ u: StoredUser; t: string; e: number | null }>(LocalEntity.IdbStaySession)
        if (sess && sess.u?.userId && sess.u?.username && sess.t) {
          token.value = sess.t
          userId.value = sess.u.userId
          username.value = sess.u.username
          hiddenMode.value = Boolean(sess.u.hiddenMode)
          introvertMode.value = Boolean(sess.u.introvertMode)
          expiresAtMs.value = typeof sess.e === 'number' && Number.isFinite(sess.e) ? sess.e : null

          // Repopulate sessionStorage so refreshes stay consistent.
          storeSession(
            { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
            token.value,
            expiresAtMs.value,
          )
        }
      }

      if (!vaultPlain.value) {
        const vaultRaw = await localData.idbGet<string>(LocalEntity.IdbStayVault)
        if (vaultRaw) {
          const parsed = parseVaultPlain(vaultRaw)
          if (parsed) {
            vaultPlain.value = parsed
            // Keep sessionStorage in sync.
            storeVaultPlain(String(vaultRaw))
          }
        }
      }

      if (!removeDateIso.value) {
        const removeRaw = await localData.idbGet<string>(LocalEntity.IdbStayRemoveDate)
        if (removeRaw) {
          const v = String(removeRaw).trim()
          removeDateIso.value = v ? v : null
          if (removeDateIso.value) storeRemoveDateIso(removeDateIso.value)
        }
      }

      await tryRestoreStayUnlockBlob()

      // Variant B requirement: stay mode must never leave us in a auth-but-locked state.
      if (token.value && userId.value && username.value && !privateKey.value) {
        try {
          // Do not wipe local artifacts here; restore failures can be transient.
          logout(false)
        } catch {
          // ignore
        }
        return
      }

      if (token.value && userId.value && username.value && privateKey.value) {
        try {
          await refreshChats()
          await connectWs()
          void maybeAddChatFromUrl()
          void maybeOpenChatFromUrl()
          scheduleTokenRefresh()
          startRemoveDateSyncTimer()
          void trySyncPushSubscription()
          view.value = 'contacts'
        } catch {
          // Do not wipe local state here. fetchJson() already clears the session on 401.
          // Other errors (offline/transient) should not destroy stay-login artifacts.
        }
      }
    } finally {
      restoring.value = false
    }
  })()

  // Keep stay-login mirrors updated whenever relevant state changes.
  watch([token, userId, username, expiresAtMs, hiddenMode, introvertMode, stayLoggedIn], () => scheduleStayMirrorSync(), { flush: 'post' })
  watch(
    () => vaultPlain.value?.expirationDays,
    () => scheduleStayMirrorSync(),
    { flush: 'post' },
  )
  watch(removeDateIso, () => scheduleStayMirrorSync(), { flush: 'post' })
  watch(privateKey, () => scheduleStayMirrorSync(), { flush: 'post' })

  if (!stayLoggedIn.value) restoring.value = false

  async function updateHiddenMode(next: boolean) {
    if (!token.value) throw new Error('Not logged in')
    const prev = hiddenMode.value
    hiddenMode.value = Boolean(next)
    try {
      await updateAccount({ hiddenMode: hiddenMode.value })

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
      await updateAccount({ introvertMode: introvertMode.value })

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

  async function updateExpirationDays(next: number) {
    if (!token.value) throw new Error('Not logged in')
    if (!publicKeyJwk.value) throw new Error('Missing public key')

    const exp = Number(next)
    if (!Number.isFinite(exp) || exp < 7 || exp > 365) {
      throw new Error('Expiration days must be between 7 and 365')
    }

    const vaultJson = makeVaultJson(exp)
    const vaultEnc = await encryptSmallStringWithPublicKeyJwk({ plaintext: vaultJson, publicKeyJwkJson: publicKeyJwk.value })
    const removeDate = computeRemoveDateIsoForNow(exp)

    await updateAccount({ vault: vaultEnc, removeDate })

    vaultEncrypted.value = vaultEnc
    vaultPlain.value = parseVaultPlain(vaultJson)
    storeVaultPlain(vaultJson)

    removeDateIso.value = removeDate
    storeRemoveDateIso(removeDate)
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
    vaultPlain,
    removeDateIso,
    notificationsEnabled,
    pushNotificationsEnabled,
    restoring,
    stayLoggedIn,
    setStayLoggedIn,
    publicKeyJwk,
    privateKey,
    locked,
    unlocking,
    ws,
    wsPermanentlyFailed,
    transportFatalReason,
      clientVersion,
      serverVersion,
      serverUpdateModalOpen,
      serverUpdatedFrom,
      serverUpdatedTo,
      applyServerVersion,
      dismissServerUpdateModal,
    turnConfig,
    authIn,
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
    logoutOtherDevices,
    logoutAndRemoveKeyOtherDevices,
    updateHiddenMode,
    updateIntrovertMode,
    updateExpirationDays,
    recreateAccount,
    refreshChats,
    fetchChatMembers,
    openChat,
    goHome,
    openSettings,
    setNotificationsEnabledLocal,
    setPushNotificationsEnabledLocal,
    trySyncPushSubscription,
    disablePushNotifications,
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
    sendPresenceHeartbeat,
    getChatOnlineState,
    getChatLastMessagePreview,
    getChatLastMessageTsMs,
    ensureTurnConfig,
    sendReliableMessage,
    sendDatagram,
    sendWs,
    registerInboundHandler,
    registerDisconnectHandler,
    connectWs,
    disconnectWs,
    unlock,
    bestEffortResumeSync,
  }
})
