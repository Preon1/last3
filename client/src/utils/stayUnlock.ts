const DB_NAME = 'lrcom'
const DB_VERSION = 1
const STORE = 'kv'
const DEVICE_KEY_ID = 'stay-device-key'

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function idbGet<T = unknown>(key: string): Promise<T | null> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly')
    const store = tx.objectStore(STORE)
    const req = store.get(key)
    req.onsuccess = () => resolve((req.result as T) ?? null)
    req.onerror = () => reject(req.error)
  })
}

async function idbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite')
    const store = tx.objectStore(STORE)
    const req = store.put(value, key)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function stayDbGet<T = unknown>(key: string): Promise<T | null> {
  try {
    return await idbGet<T>(key)
  } catch {
    return null
  }
}

export async function stayDbSet(key: string, value: unknown): Promise<void> {
  try {
    await idbSet(key, value)
  } catch {
    // ignore
  }
}

export async function wipeStayUnlockDb(): Promise<void> {
  // Forced logout should wipe the entire local IndexedDB used by this app.
  // Today it's only used for opt-in stay-login state (device key), but deleting
  // the full DB matches the "wipe everything" requirement.
  try {
    await new Promise<void>((resolve) => {
      const req = indexedDB.deleteDatabase(DB_NAME)
      req.onsuccess = () => resolve()
      req.onerror = () => resolve()
      req.onblocked = () => resolve()
    })
  } catch {
    // ignore
  }
}

async function getOrCreateDeviceKey(): Promise<CryptoKey> {
  const existing = await idbGet<CryptoKey>(DEVICE_KEY_ID)
  if (existing) return existing

  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  await idbSet(DEVICE_KEY_ID, key)
  return key
}

function b64Encode(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0)
  return btoa(bin)
}

function b64Decode(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export async function encryptStayString(plaintext: string): Promise<string> {
  const key = await getOrCreateDeviceKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const pt = new TextEncoder().encode(String(plaintext ?? ''))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt)
  return `${b64Encode(iv)}.${b64Encode(new Uint8Array(ct))}`
}

export async function decryptStayString(blob: string): Promise<string> {
  const raw = String(blob ?? '')
  const parts = raw.split('.')
  if (parts.length !== 2) throw new Error('Bad stay blob')
  const iv = b64Decode(parts[0] ?? '')
  const ct = b64Decode(parts[1] ?? '')
  const key = await getOrCreateDeviceKey()
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, new Uint8Array(ct).buffer)
  return new TextDecoder().decode(pt)
}
