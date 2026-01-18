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
  decryptLocalUsername,
  decryptPrivateKeyJwk,
  decryptSmallStringWithPrivateKey,
  decryptSignedMessage,
  encryptLocalUsername,
  encryptPrivateKeyJwk,
  encryptSmallStringWithPublicKeyJwk,
  encryptSignedMessage,
  generateRsaKeyPair,
  importRsaPrivateKeyJwk,
  publicJwkFromPrivateJwk,
} from '../utils/signedCrypto'
import { LocalEntity, localData } from '../utils/localData'
import { APP_VERSION as CLIENT_APP_VERSION } from '../appVersion'
import { useToastStore } from './toast'

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

// NOTE: All locally persisted entities must be accessed via LocalData.

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

function assertUsernameIsXssSafe(username: string) {
  const u = String(username ?? '')
  // Vue text bindings escape HTML, but usernames can still end up in other contexts
  // (notifications, attributes, logs). Reject the most dangerous characters early.
  if (u.includes('<') || u.includes('>')) throw new Error('Username contains unsafe characters')
  // Disallow ASCII control characters (including newlines/tabs) which can cause UI or parsing issues.
  if (/[\u0000-\u001F\u007F]/.test(u)) throw new Error('Username contains unsafe characters')
}

type StoredKeyV2 = {
  v: 2
  encryptedUsername: string
  encryptedPrivateKey: string
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

export const useSignedStore = defineStore('signed', () => {
  const toast = useToastStore()
  const token = ref<string | null>(null)
  const expiresAtMs = ref<number | null>(null)
  const userId = ref<string | null>(null)
  const username = ref<string | null>(null)
  const hiddenMode = ref<boolean>(false)
  const introvertMode = ref<boolean>(false)
  const publicKeyJwk = ref<string | null>(null)
  const privateKey = ref<CryptoKey | null>(null)

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
  stayLoggedIn.value = localData.getSignedStayLoggedIn()

  // Only show a restore/loading state when stay mode is enabled.
  restoring.value = stayLoggedIn.value

  async function syncStayMirrorNow() {
    try {
      if (!stayLoggedIn.value) return

      // Mirror session details.
      if (token.value && userId.value && username.value) {
        await localData.mirrorSignedSessionToIdb({
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
    localData.setSignedStayLoggedIn(stayLoggedIn.value)

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

      // Variant B: if we already have key material in-memory (e.g. settings toggle while signed in),
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

  const ws = ref<WebSocket | null>(null)
  const wsShouldReconnect = ref(false)
  const wsReconnectAttempt = ref(0)
  const wsPermanentlyFailed = ref(false)
  let wsReconnectTimer: number | null = null
  let wsGeneration = 0

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
  const locked = computed(() => Boolean(signedIn.value && !privateKey.value))
  const unlocking = ref(false)
  const signedReadyForPresence = computed(() => Boolean(token.value && userId.value && username.value && privateKey.value && !wsPermanentlyFailed.value))
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

  // Presence polling should not depend on WS open: if WS is delayed/blocked
  // we still want to query presence for known correspondents.
  watch(
    () => signedReadyForPresence.value,
    (ready) => {
      if (ready) startPresencePolling()
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

  function computeRemoveDateIsoForNow(expirationDays: number) {
    const jitterSeconds = randomIntInclusive(0, 86400)
    const ms = Date.now() + expirationDays * 86400_000 + jitterSeconds * 1000
    return new Date(ms).toISOString()
  }

  function storeVaultPlain(rawJson: string) {
    localData.setString(LocalEntity.SignedVault, rawJson)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayVault, rawJson)
  }

  function loadVaultPlain(): VaultPlain | null {
    const raw = String(localData.getString(LocalEntity.SignedVault) ?? '')
    return raw ? parseVaultPlain(raw) : null
  }

  function clearVaultPlain() {
    localData.remove(LocalEntity.SignedVault)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayVault, null)
  }

  function storeRemoveDateIso(iso: string) {
    localData.setString(LocalEntity.SignedRemoveDate, iso)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayRemoveDate, iso)
  }

  function loadRemoveDateIso(): string | null {
    const raw = String(localData.getString(LocalEntity.SignedRemoveDate) ?? '').trim()
    return raw ? raw : null
  }

  function clearRemoveDateIso() {
    localData.remove(LocalEntity.SignedRemoveDate)
    if (stayLoggedIn.value) void localData.idbSet(LocalEntity.IdbStayRemoveDate, null)
  }

  async function updateAccount(fields: {
    hiddenMode?: boolean
    introvertMode?: boolean
    removeDate?: string
    vault?: string
  }) {
    await fetchJson('/api/signed/account/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify(fields),
    })
  }

  async function bestEffortSyncRemoveDateNow() {
    if (!signedIn.value) return
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

  function setPushNotificationsEnabledLocal(next: boolean) {
    pushNotificationsEnabled.value = Boolean(next)
    setPushNotificationsEnabled(Boolean(next))
  }

  async function disablePushNotifications() {
    // Wipe preference, server state, and local browser subscription.
    setPushNotificationsEnabledLocal(false)

    try {
      if (token.value) {
        await fetchJson('/api/signed/push/disable', {
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

    // Always send a presence request, even if there are no contacts.
    // If there are no contacts, send an empty list to act as a keepalive.
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

    // Always send the request, even if list is empty.

    try {
      const j = await fetchJson('/api/signed/presence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ userIds: list }),
      })

      // Server version should be present on every response.
      applyServerVersion((j as any)?.serverVersion)

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
    // If list is empty, still update state to empty objects (no one online/busy)
    if (!list.length) {
      onlineByUserId.value = {}
      busyByUserId.value = {}
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

  function loadKeyEntries(): StoredKeyV2[] {
    const arr = localData.getJson<any[]>(LocalEntity.SignedKeys)
    if (!Array.isArray(arr)) return []
    const out: StoredKeyV2[] = []
    for (const it of arr) {
      if (it && it.v === 2 && typeof it.encryptedUsername === 'string' && typeof it.encryptedPrivateKey === 'string') {
        out.push({ v: 2, encryptedUsername: it.encryptedUsername, encryptedPrivateKey: it.encryptedPrivateKey })
      }
    }
    return out
  }

  function saveKeyEntries(next: StoredKeyV2[]) {
    localData.setJson(LocalEntity.SignedKeys, next)
  }


  function clearAllKeyMaterial() {
    localData.remove(LocalEntity.SignedKeys)
  }

  async function saveLocalKeyForUser(params: { username: string; password: string; encryptedPrivateKey: string }) {
    if (params.password.length > MAX_PASSWORD_LEN) throw new Error(`Password must be at most ${MAX_PASSWORD_LEN} characters`)
    const encryptedUsername = await encryptLocalUsername({ username: params.username, password: params.password })

    const cur = loadKeyEntries()
    const kept: StoredKeyV2[] = []
    for (const e of cur) {
      try {
        const u = await decryptLocalUsername({ encrypted: e.encryptedUsername, password: params.password })
        if (u === params.username) continue
      } catch {
        // If it can't be decrypted with this password, keep it.
      }
      kept.push(e)
    }

    kept.push({ v: 2, encryptedUsername, encryptedPrivateKey: params.encryptedPrivateKey })
    saveKeyEntries(kept)

    // No legacy key storage is supported.
  }

  async function findEncryptedPrivateKeyForLogin(params: { username: string; password: string }) {
    const list = loadKeyEntries()
    for (const e of list) {
      try {
        const u = await decryptLocalUsername({ encrypted: e.encryptedUsername, password: params.password })
        if (u === params.username) return e.encryptedPrivateKey
      } catch {
        // ignore
      }
    }

    return null
  }

  function storeSession(u: StoredUser, t: string, expiresAt?: number | null) {
    localData.setSignedSession({ user: u, token: t, expiresAtMs: expiresAt })
    if (stayLoggedIn.value) void localData.mirrorSignedSessionToIdb({ user: u, token: t, expiresAtMs: expiresAt })
  }

  function loadSession(): { u: StoredUser; t: string; e: number | null } | null {
    const s = localData.getSignedSession()
    if (!s?.token || !s.user) return null
    const u = s.user as StoredUser
    if (!u?.userId || !u?.username) return null
    return { u, t: s.token, e: typeof s.expiresAtMs === 'number' && Number.isFinite(s.expiresAtMs) ? s.expiresAtMs : null }
  }

  function clearSession() {
    localData.clearSignedSession()
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
      localData.setSignedStayLoggedIn(false)
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
      publicKeyJwk.value = publicJwkFromPrivateJwk(jwkJson)
      return true
    } catch {
      return false
    }
  }

  function loadLastUsername(): string {
    return String(localData.getString(LocalEntity.SignedUsername) ?? '').trim()
  }

  function storeLastUsername(u: string) {
    const v = (u ?? '').trim()
    lastUsername.value = v
    localData.setString(LocalEntity.SignedUsername, v)
  }

  function loadPendingAddUsername(): string {
    return String(localData.getString(LocalEntity.SignedAddUsername) ?? '').trim()
  }

  function storePendingAddUsername(u: string) {
    const v = String(u ?? '').trim()
    pendingAddUsername.value = v
    localData.setString(LocalEntity.SignedAddUsername, v)
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
    lastPrivateJwkJsonForStay = privateJwk
    privateKey.value = await importRsaPrivateKeyJwk(privateJwk)
    publicKeyJwk.value = publicJwkFromPrivateJwk(privateJwk)

    // Variant B: if stay mode is enabled, persist auto-unlock blob from private JWK.
    void persistStayUnlockBlobFromPrivateJwk(privateJwk)

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

        const initRes = await fetch(`${apiBase()}/api/auth/login-init`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username.value, publicKey: publicJwk }),
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
        username.value = typeof (finalJson as any)?.username === 'string' ? String((finalJson as any).username) : username.value
        hiddenMode.value = Boolean((finalJson as any)?.hiddenMode)
        introvertMode.value = Boolean((finalJson as any)?.introvertMode)
        publicKeyJwk.value = publicJwk

        if (token.value && userId.value && username.value) {
          storeSession(
            { userId: userId.value, username: username.value, hiddenMode: hiddenMode.value, introvertMode: introvertMode.value },
            token.value,
            expiresAtMs.value,
          )
          void localData.mirrorSignedSessionToIdb({
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
    // Bump generation first so close/error events from older sockets are ignored.
    wsGeneration += 1
    const gen = wsGeneration

    wsShouldReconnect.value = true
    wsPermanentlyFailed.value = false
    clearWsReconnectTimer()
    disconnectWs()
    if (!token.value) return

    const sock = new WebSocket(wsSignedUrl(token.value))
    ws.value = sock

    sock.addEventListener('open', () => {
      if (gen !== wsGeneration) return
      wsReconnectAttempt.value = 0
      // Presence polling is disabled after permanent WS failure.
      if (!wsPermanentlyFailed.value) startPresencePolling()
      void syncAfterConnect()
      void trySyncPushSubscription()
    })

    sock.addEventListener('close', () => {
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
    })

    sock.addEventListener('error', () => {
      if (gen !== wsGeneration) return
      // Some browsers fire error without a close; force close and let the close handler schedule reconnect.
      try {
        sock.close()
      } catch {
        // ignore
      }
    })

    sock.addEventListener('message', async (ev) => {
      let obj: any
      try {
        obj = JSON.parse(String(ev.data))
      } catch {
        return
      }
      if (!obj || typeof obj.type !== 'string') return

      if (obj.type === 'signedForceLogout') {
        const msgId = typeof (obj as any)?.msgId === 'string' ? String((obj as any).msgId) : ''
        if (msgId) sendWs({ type: 'ack', msgId })

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

      if (obj.type === 'signedAccountUpdated') {
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
        const msgId = typeof (obj as any)?.msgId === 'string' ? String((obj as any).msgId) : ''
        if (msgId) sendWs({ type: 'ack', msgId })
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
    const encryptedPrivateKey = await encryptPrivateKeyJwk({ privateJwk, password: params.password })

    // Cache JWK for optional stay-login auto-unlock.
    lastPrivateJwkJsonForStay = privateJwk

    // Import private key before setting token/userId so App.vue doesn't interpret
    // the session as "signed in but locked" mid-register and auto-logout.
    const importedPrivateKey = await importRsaPrivateKeyJwk(privateJwk)

    const vaultJson = makeVaultJson(exp)
    const vaultEnc = await encryptSmallStringWithPublicKeyJwk({ plaintext: vaultJson, publicKeyJwkJson: publicJwk })
    const removeDate = computeRemoveDateIsoForNow(exp)

    const j = await fetchJson('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: u,
        publicKey: publicJwk,
        removeDate,
        vault: vaultEnc,
      }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = typeof j.username === 'string' ? j.username : u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk

    vaultEncrypted.value = vaultEnc
    vaultPlain.value = parseVaultPlain(vaultJson)
    storeVaultPlain(vaultJson)

    removeDateIso.value = removeDate
    storeRemoveDateIso(removeDate)

    privateKey.value = importedPrivateKey

    // Persist key material only after server registration succeeds.
    await saveLocalKeyForUser({ username: u, password: params.password, encryptedPrivateKey })

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

    const encryptedPrivateKey = await findEncryptedPrivateKeyForLogin({ username: u, password: params.password })
    if (!encryptedPrivateKey) throw new Error('No local key found')

    const privateJwk = await decryptPrivateKeyJwk({ encrypted: encryptedPrivateKey, password: params.password })
    // Cache JWK for optional stay-login auto-unlock.
    lastPrivateJwkJsonForStay = privateJwk
    const priv = await importRsaPrivateKeyJwk(privateJwk)

    const publicJwk = publicJwkFromPrivateJwk(privateJwk)

    const init = await fetchJson('/api/auth/login-init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, publicKey: publicJwk }),
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
    username.value = typeof j.username === 'string' ? j.username : u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk
    privateKey.value = priv

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
    await saveLocalKeyForUser({ username: u, password: params.password, encryptedPrivateKey })

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

    const encryptedPrivateKey = await findEncryptedPrivateKeyForLogin({ username: u, password: params.password })
    if (!encryptedPrivateKey) throw new Error('No local key found')

    const privateJwk = await decryptPrivateKeyJwk({ encrypted: encryptedPrivateKey, password: params.password })
    // Cache JWK for optional stay-login auto-unlock.
    lastPrivateJwkJsonForStay = privateJwk
    const priv = await importRsaPrivateKeyJwk(privateJwk)
    const publicJwk = publicJwkFromPrivateJwk(privateJwk)

    const vaultJson = makeVaultJson(exp)
    const vaultEnc = await encryptSmallStringWithPublicKeyJwk({ plaintext: vaultJson, publicKeyJwkJson: publicJwk })
    const removeDate = computeRemoveDateIsoForNow(exp)

    const j = await fetchJson('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: u,
        publicKey: publicJwk,
        removeDate,
        vault: vaultEnc,
      }),
    })

    token.value = typeof j.token === 'string' ? j.token : null
    expiresAtMs.value = typeof (j as any)?.expiresAt === 'number' ? Number((j as any).expiresAt) : null
    userId.value = typeof j.userId === 'string' ? j.userId : null
    username.value = typeof j.username === 'string' ? j.username : u
    hiddenMode.value = Boolean(j?.hiddenMode)
    introvertMode.value = Boolean(j?.introvertMode)
    publicKeyJwk.value = publicJwk

    vaultEncrypted.value = vaultEnc
    vaultPlain.value = parseVaultPlain(vaultJson)
    storeVaultPlain(vaultJson)

    removeDateIso.value = removeDate
    storeRemoveDateIso(removeDate)

    privateKey.value = priv

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
    await saveLocalKeyForUser({ username: u, password: params.password, encryptedPrivateKey })

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
        void fetch('/api/signed/account/update', { method: 'POST', headers, body: JSON.stringify({ removeDate: iso }) }).catch(() => {})
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
      localData.setSignedStayLoggedIn(false)
    } else {
      clearSession()
    }

    clearVaultPlain()
    clearRemoveDateIso()
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

  async function logoutOtherDevices() {
    if (!token.value) throw new Error('Not logged in')
    await fetchJson('/api/signed/session/logout-other-devices', {
      method: 'POST',
      headers: { ...authHeaders() },
    })
  }

  async function logoutAndRemoveKeyOtherDevices() {
    if (!token.value) throw new Error('Not logged in')
    await fetchJson('/api/signed/session/logout-and-remove-key-other-devices', {
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

      // Variant B requirement: stay mode must never leave us in a signed-but-locked state.
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
      clientVersion,
      serverVersion,
      serverUpdateModalOpen,
      serverUpdatedFrom,
      serverUpdatedTo,
      applyServerVersion,
      dismissServerUpdateModal,
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
