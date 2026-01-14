import { decryptStayString, encryptStayString, stayDbGet, stayDbSet, wipeStayUnlockDb } from './stayUnlock'

export const LocalEntity = {
  NotificationsEnabled: 'notifications.enabled',
  UiTheme: 'ui.theme',
  Locale: 'i18n.locale',

  SignedStay: 'signed.stay',
  SignedKeys: 'signed.keys',

  SignedToken: 'signed.session.token',
  SignedUser: 'signed.session.user',
  SignedExpiresAt: 'signed.session.expiresAt',

  SignedVault: 'signed.vault',
  SignedRemoveDate: 'signed.removeDate',
  SignedLastUsername: 'signed.lastUsername',
  SignedAddUsername: 'signed.addUsername',

  IdbStaySession: 'idb.stay.session',
  IdbStayVault: 'idb.stay.vault',
  IdbStayRemoveDate: 'idb.stay.removeDate',
  IdbStayUnlockBlob: 'idb.stay.unlockBlob',
} as const

export type LocalEntityId = (typeof LocalEntity)[keyof typeof LocalEntity]

type StorageBackend = 'localStorage' | 'sessionStorage' | 'cookie' | 'indexedDb'

type CodecKind = 'string' | 'json' | 'bool01' | 'number'

type EntityDef = {
  id: LocalEntityId
  backend: StorageBackend
  key: string
  codec: CodecKind
  removeOnLogout: boolean
  removeOnLogoutWipe: boolean
  removeOnAccountDelete: boolean
}

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined'
}

function safeGetStorage(backend: 'localStorage' | 'sessionStorage'): Storage | null {
  if (!isBrowser()) return null
  try {
    return backend === 'localStorage' ? window.localStorage : window.sessionStorage
  } catch {
    return null
  }
}

function cookieGet(name: string): string | null {
  if (!isBrowser()) return null
  try {
    const all = String(document.cookie ?? '')
    if (!all) return null
    const parts = all.split(';')
    for (const p of parts) {
      const idx = p.indexOf('=')
      if (idx < 0) continue
      const k = p.slice(0, idx).trim()
      if (k !== name) continue
      return decodeURIComponent(p.slice(idx + 1))
    }
    return null
  } catch {
    return null
  }
}

function cookieSet(name: string, value: string, opts?: { maxAgeSeconds?: number; path?: string; sameSite?: 'Lax' | 'Strict' | 'None'; secure?: boolean }) {
  if (!isBrowser()) return
  try {
    const path = opts?.path ?? '/'
    const sameSite = opts?.sameSite ?? 'Lax'
    const secure = opts?.secure ?? (location.protocol === 'https:')
    const maxAge = typeof opts?.maxAgeSeconds === 'number' ? `; Max-Age=${Math.floor(opts.maxAgeSeconds)}` : ''
    const sec = secure ? '; Secure' : ''
    document.cookie = `${name}=${encodeURIComponent(value)}${maxAge}; Path=${path}; SameSite=${sameSite}${sec}`
  } catch {
    // ignore
  }
}

function cookieRemove(name: string) {
  // Expire in the past.
  cookieSet(name, '', { maxAgeSeconds: 0 })
}

function decodeBool01(raw: string | null): boolean | null {
  if (raw == null) return null
  if (raw === '1' || raw === 'true') return true
  if (raw === '0' || raw === 'false') return false
  return null
}

function encodeBool01(v: boolean): string {
  return v ? '1' : '0'
}

function decodeNumber(raw: string | null): number | null {
  if (raw == null) return null
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}

const REGISTRY: Record<LocalEntityId, EntityDef> = {
  [LocalEntity.NotificationsEnabled]: {
    id: LocalEntity.NotificationsEnabled,
    backend: 'localStorage',
    key: 'lrcom-notifications-enabled',
    codec: 'bool01',
    removeOnLogout: false,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.UiTheme]: {
    id: LocalEntity.UiTheme,
    backend: 'sessionStorage',
    key: 'lrcom-theme',
    codec: 'string',
    removeOnLogout: false,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.Locale]: {
    id: LocalEntity.Locale,
    backend: 'sessionStorage',
    key: 'lrcom-locale',
    codec: 'string',
    removeOnLogout: false,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },

  [LocalEntity.SignedStay]: {
    id: LocalEntity.SignedStay,
    backend: 'localStorage',
    key: 'lrcom-signed-stay',
    codec: 'bool01',
    removeOnLogout: false,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.SignedKeys]: {
    id: LocalEntity.SignedKeys,
    backend: 'localStorage',
    key: 'lrcom-signed-keys',
    codec: 'json',
    removeOnLogout: false,
    removeOnLogoutWipe: false, // settings logout keeps encrypted key material
    removeOnAccountDelete: true,
  },

  [LocalEntity.SignedToken]: {
    id: LocalEntity.SignedToken,
    backend: 'sessionStorage',
    key: 'lrcom-signed-token',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.SignedUser]: {
    id: LocalEntity.SignedUser,
    backend: 'sessionStorage',
    key: 'lrcom-signed-user',
    codec: 'json',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.SignedExpiresAt]: {
    id: LocalEntity.SignedExpiresAt,
    backend: 'sessionStorage',
    key: 'lrcom-signed-expires-at',
    codec: 'number',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },

  [LocalEntity.SignedVault]: {
    id: LocalEntity.SignedVault,
    backend: 'sessionStorage',
    key: 'lrcom-signed-vault',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.SignedRemoveDate]: {
    id: LocalEntity.SignedRemoveDate,
    backend: 'sessionStorage',
    key: 'lrcom-signed-remove-date',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },

  [LocalEntity.SignedLastUsername]: {
    id: LocalEntity.SignedLastUsername,
    backend: 'sessionStorage',
    key: 'lrcom-signed-last-username',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.SignedAddUsername]: {
    id: LocalEntity.SignedAddUsername,
    backend: 'sessionStorage',
    key: 'lrcom-add-username',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },

  // IndexedDB keys are managed through stayUnlock's kv store.
  [LocalEntity.IdbStaySession]: {
    id: LocalEntity.IdbStaySession,
    backend: 'indexedDb',
    key: 'stay-session',
    codec: 'json',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.IdbStayVault]: {
    id: LocalEntity.IdbStayVault,
    backend: 'indexedDb',
    key: 'stay-vault',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.IdbStayRemoveDate]: {
    id: LocalEntity.IdbStayRemoveDate,
    backend: 'indexedDb',
    key: 'stay-remove-date',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
  [LocalEntity.IdbStayUnlockBlob]: {
    id: LocalEntity.IdbStayUnlockBlob,
    backend: 'indexedDb',
    key: 'stay-unlock-blob',
    codec: 'string',
    removeOnLogout: true,
    removeOnLogoutWipe: true,
    removeOnAccountDelete: true,
  },
}

export type CleanupReason = 'logout' | 'logout_wipe' | 'account_delete'

export class LocalData {
  listEntities(): EntityDef[] {
    return Object.values(REGISTRY)
  }

  // -----------------
  // Low-level sync API
  // -----------------

  has(id: LocalEntityId): boolean {
    const def = REGISTRY[id]
    if (!def) return false

    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return false
      try {
        return s.getItem(def.key) != null
      } catch {
        return false
      }
    }

    if (def.backend === 'cookie') return cookieGet(def.key) != null

    // For IndexedDB, presence is async.
    return false
  }

  getString(id: LocalEntityId): string | null {
    const def = REGISTRY[id]
    if (!def) return null
    if (def.codec !== 'string') return null

    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return null
      try {
        const v = s.getItem(def.key)
        return v == null ? null : String(v)
      } catch {
        return null
      }
    }

    if (def.backend === 'cookie') return cookieGet(def.key)
    return null
  }

  setString(id: LocalEntityId, value: string | null | undefined) {
    const def = REGISTRY[id]
    if (!def) return
    if (def.codec !== 'string') return

    const v = value == null ? '' : String(value)

    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return
      try {
        if (!v) s.removeItem(def.key)
        else s.setItem(def.key, v)
      } catch {
        // ignore
      }
      return
    }

    if (def.backend === 'cookie') {
      if (!v) cookieRemove(def.key)
      else cookieSet(def.key, v)
    }
  }

  getBool(id: LocalEntityId, defaultValue: boolean): boolean {
    const def = REGISTRY[id]
    if (!def) return defaultValue
    if (def.codec !== 'bool01') return defaultValue

    let raw: string | null = null
    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return defaultValue
      try {
        raw = s.getItem(def.key)
      } catch {
        return defaultValue
      }
    } else if (def.backend === 'cookie') {
      raw = cookieGet(def.key)
    }

    const parsed = decodeBool01(raw)
    return parsed == null ? defaultValue : parsed
  }

  setBool(id: LocalEntityId, value: boolean | null | undefined) {
    const def = REGISTRY[id]
    if (!def) return
    if (def.codec !== 'bool01') return

    if (value == null) {
      this.remove(id)
      return
    }

    const v = encodeBool01(Boolean(value))

    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return
      try {
        s.setItem(def.key, v)
      } catch {
        // ignore
      }
      return
    }

    if (def.backend === 'cookie') cookieSet(def.key, v)
  }

  getNumber(id: LocalEntityId): number | null {
    const def = REGISTRY[id]
    if (!def) return null
    if (def.codec !== 'number') return null

    let raw: string | null = null
    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return null
      try {
        raw = s.getItem(def.key)
      } catch {
        return null
      }
    } else if (def.backend === 'cookie') {
      raw = cookieGet(def.key)
    }

    return decodeNumber(raw)
  }

  setNumber(id: LocalEntityId, value: number | null | undefined) {
    const def = REGISTRY[id]
    if (!def) return
    if (def.codec !== 'number') return

    if (value == null || !Number.isFinite(value)) {
      this.remove(id)
      return
    }

    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return
      try {
        s.setItem(def.key, String(value))
      } catch {
        // ignore
      }
      return
    }

    if (def.backend === 'cookie') cookieSet(def.key, String(value))
  }

  getJson<T>(id: LocalEntityId): T | null {
    const def = REGISTRY[id]
    if (!def) return null
    if (def.codec !== 'json') return null

    const raw = this.getRaw(def)
    if (!raw) return null
    try {
      return JSON.parse(raw) as T
    } catch {
      return null
    }
  }

  setJson(id: LocalEntityId, value: unknown) {
    const def = REGISTRY[id]
    if (!def) return
    if (def.codec !== 'json') return

    if (value == null) {
      this.remove(id)
      return
    }

    let raw = ''
    try {
      raw = JSON.stringify(value)
    } catch {
      return
    }

    this.setRaw(def, raw)
  }

  remove(id: LocalEntityId) {
    const def = REGISTRY[id]
    if (!def) return

    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return
      try {
        s.removeItem(def.key)
      } catch {
        // ignore
      }
      return
    }

    if (def.backend === 'cookie') cookieRemove(def.key)
  }

  private getRaw(def: EntityDef): string | null {
    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return null
      try {
        return s.getItem(def.key)
      } catch {
        return null
      }
    }

    if (def.backend === 'cookie') return cookieGet(def.key)

    return null
  }

  private setRaw(def: EntityDef, raw: string) {
    if (def.backend === 'localStorage' || def.backend === 'sessionStorage') {
      const s = safeGetStorage(def.backend)
      if (!s) return
      try {
        if (!raw) s.removeItem(def.key)
        else s.setItem(def.key, raw)
      } catch {
        // ignore
      }
      return
    }

    if (def.backend === 'cookie') {
      if (!raw) cookieRemove(def.key)
      else cookieSet(def.key, raw)
    }
  }

  // -----------------
  // IndexedDB API (async)
  // -----------------

  async idbGet<T>(id: LocalEntityId): Promise<T | null> {
    const def = REGISTRY[id]
    if (!def || def.backend !== 'indexedDb') return null
    return await stayDbGet<T>(def.key)
  }

  async idbSet(id: LocalEntityId, value: unknown): Promise<void> {
    const def = REGISTRY[id]
    if (!def || def.backend !== 'indexedDb') return
    await stayDbSet(def.key, value)
  }

  async idbRemove(id: LocalEntityId): Promise<void> {
    await this.idbSet(id, null)
  }

  async wipeIndexedDb(): Promise<void> {
    await wipeStayUnlockDb()
  }

  async encryptStayString(plaintext: string): Promise<string> {
    return await encryptStayString(plaintext)
  }

  async decryptStayString(blob: string): Promise<string> {
    return await decryptStayString(blob)
  }

  // -----------------
  // High-level helpers
  // -----------------

  getSignedStayLoggedIn(): boolean {
    return this.getBool(LocalEntity.SignedStay, false)
  }

  setSignedStayLoggedIn(next: boolean) {
    this.setBool(LocalEntity.SignedStay, Boolean(next))
  }

  setSignedSession(params: { user: unknown; token: string; expiresAtMs?: number | null }) {
    this.setString(LocalEntity.SignedToken, params.token)
    this.setJson(LocalEntity.SignedUser, params.user)
    if (typeof params.expiresAtMs === 'number' && Number.isFinite(params.expiresAtMs)) this.setNumber(LocalEntity.SignedExpiresAt, params.expiresAtMs)
    else this.remove(LocalEntity.SignedExpiresAt)
  }

  getSignedSession(): { user: any; token: string; expiresAtMs: number | null } | null {
    const token = this.getString(LocalEntity.SignedToken)
    const user = this.getJson<any>(LocalEntity.SignedUser)
    if (!token || !user) return null
    const e = this.getNumber(LocalEntity.SignedExpiresAt)
    return { user, token, expiresAtMs: e }
  }

  clearSignedSession() {
    this.remove(LocalEntity.SignedToken)
    this.remove(LocalEntity.SignedUser)
    this.remove(LocalEntity.SignedExpiresAt)
  }

  async mirrorSignedSessionToIdb(params: { user: unknown; token: string; expiresAtMs?: number | null }) {
    await this.idbSet(LocalEntity.IdbStaySession, {
      u: params.user,
      t: params.token,
      e: typeof params.expiresAtMs === 'number' && Number.isFinite(params.expiresAtMs) ? params.expiresAtMs : null,
    })
  }

  async clearIdbStaySession() {
    await this.idbSet(LocalEntity.IdbStaySession, null)
  }

  async cleanup(reason: CleanupReason) {
    const defs = this.listEntities()

    for (const def of defs) {
      const shouldRemove =
        reason === 'logout'
          ? def.removeOnLogout
          : reason === 'logout_wipe'
            ? def.removeOnLogoutWipe
            : def.removeOnAccountDelete

      if (!shouldRemove) continue

      if (def.backend === 'indexedDb') {
        // Normal logout clears only registered IDB entities; full DB wipe is reserved for wipe/account-delete.
        await stayDbSet(def.key, null)
      } else {
        this.remove(def.id)
      }
    }

    // IndexedDB: wipe the whole DB only on explicit wipe/account-delete flows.
    if (reason === 'logout_wipe' || reason === 'account_delete') await this.wipeIndexedDb()
  }
}

export const localData = new LocalData()
