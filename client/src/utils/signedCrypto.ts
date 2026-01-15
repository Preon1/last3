type StoredEncryptedBlobV1 = {
  v: 1
  kdf: 'PBKDF2-SHA256'
  iterations: number
  saltB64: string
  ivB64: string
  ctB64: string
}

export const LOCAL_KEY_USERNAME_ITERATIONS = 1_212_123
export const LOCAL_KEY_PRIVATE_KEY_ITERATIONS = 612_345

const LOCAL_USERNAME_PAD_TOTAL_LEN = 75
const LOCAL_USERNAME_PAD_PREFIX = 'LP'
const LOCAL_USERNAME_PAD_LEN_HEX_WIDTH = 4

const LOCAL_USERNAME_PAD_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()-_=+[]{};:,.<>/?'

const LOCAL_USERNAME_PAD_ALPHABET_SET = new Set(LOCAL_USERNAME_PAD_ALPHABET.split(''))

function isStringFromAlphabet(s: string, alphabetSet: Set<string>) {
  const str = String(s ?? '')
  for (let i = 0; i < str.length; i++) {
    const ch = str[i]!
    if (!alphabetSet.has(ch)) return false
  }
  return true
}

function encUtf8(s: string) {
  return new TextEncoder().encode(s)
}

function decUtf8(b: ArrayBuffer) {
  return new TextDecoder().decode(new Uint8Array(b))
}

function b64(bytes: ArrayBuffer | Uint8Array) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let bin = ''
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]!)
  return btoa(bin)
}

function unb64(s: string) {
  const bin = atob(s)
  const u8 = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
  return u8
}

function randomStringFromAlphabet(len: number, alphabet: string) {
  if (len <= 0) return ''
  const a = String(alphabet ?? '')
  if (!a.length) throw new Error('Alphabet must not be empty')

  const u8 = crypto.getRandomValues(new Uint8Array(len))
  let out = ''
  for (let i = 0; i < u8.length; i++) out += a[u8[i]! % a.length]
  return out
}

function padUsernameForLocalKey(username: string) {
  const u = String(username ?? '')

  const lenHex = u.length.toString(16).padStart(LOCAL_USERNAME_PAD_LEN_HEX_WIDTH, '0')
  if (lenHex.length !== LOCAL_USERNAME_PAD_LEN_HEX_WIDTH || !/^[0-9a-fA-F]{4}$/.test(lenHex)) {
    throw new Error('Username too long to pad')
  }

  const base = `${LOCAL_USERNAME_PAD_PREFIX}${lenHex}${u}`
  const padLen = LOCAL_USERNAME_PAD_TOTAL_LEN - base.length
  if (padLen < 0) throw new Error('Username too long to pad')
  return base + randomStringFromAlphabet(padLen, LOCAL_USERNAME_PAD_ALPHABET)
}

function unpadUsernameFromLocalKey(padded: string) {
  const s = String(padded ?? '')

  // New format: LP + 4-hex-length + username + random padding.
  // Only treat it as LP-format if it looks like a padded blob.
  if (s.length === LOCAL_USERNAME_PAD_TOTAL_LEN && s.startsWith(LOCAL_USERNAME_PAD_PREFIX)) {
    const start = LOCAL_USERNAME_PAD_PREFIX.length
    const lenHex = s.slice(start, start + LOCAL_USERNAME_PAD_LEN_HEX_WIDTH)
    if (/^[0-9a-fA-F]{4}$/.test(lenHex)) {
      const n = Number.parseInt(lenHex, 16)
      const uStart = start + LOCAL_USERNAME_PAD_LEN_HEX_WIDTH
      const uEnd = uStart + n
      if (Number.isFinite(n) && n >= 0 && uEnd <= s.length) {
        // Additional guard: ensure the remaining tail looks like our padding.
        const tail = s.slice(uEnd)
        if (isStringFromAlphabet(tail, LOCAL_USERNAME_PAD_ALPHABET_SET)) {
          return s.slice(uStart, uEnd)
        }
      }
    }
  }

  throw new Error('Unsupported local username format')
}

export async function generateRsaKeyPair() {
  const kp = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )

  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey)
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey)

  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    publicJwk: JSON.stringify(publicJwk),
    privateJwk: JSON.stringify(privateJwk),
  }
}

async function deriveAesKeyFromPassword(password: string, salt: Uint8Array, iterations: number) {
  const baseKey = await crypto.subtle.importKey('raw', encUtf8(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function encryptPrivateKeyJwk(params: { privateJwk: string; password: string }) {
  return encryptStringWithPassword({ plaintext: params.privateJwk, password: params.password, iterations: LOCAL_KEY_PRIVATE_KEY_ITERATIONS })
}

export async function decryptPrivateKeyJwk({ encrypted, password }: { encrypted: string; password: string }) {
  return decryptStringWithPassword({ encrypted, password })
}

export async function encryptStringWithPassword(params: { plaintext: string; password: string; iterations?: number }) {
  const iterations = typeof params.iterations === 'number' && Number.isFinite(params.iterations)
    ? Math.max(1, Math.floor(params.iterations))
    : 250_000

  let salt = crypto.getRandomValues(new Uint8Array(16))
  let iv = crypto.getRandomValues(new Uint8Array(12))

  const aesKey = await deriveAesKeyFromPassword(params.password, salt, iterations)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encUtf8(params.plaintext))

  const stored: StoredEncryptedBlobV1 = {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    saltB64: b64(salt),
    ivB64: b64(iv),
    ctB64: b64(ct),
  }

  return JSON.stringify(stored)
}

export async function decryptStringWithPassword(params: { encrypted: string; password: string }) {
  const parsed = JSON.parse(params.encrypted) as StoredEncryptedBlobV1
  if (!parsed || parsed.v !== 1) throw new Error('Unsupported format')

  const salt = unb64(parsed.saltB64)
  const iv = unb64(parsed.ivB64)
  const ct = unb64(parsed.ctB64)

  const aesKey = await deriveAesKeyFromPassword(params.password, salt, parsed.iterations)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct)
  return decUtf8(pt)
}

export async function encryptLocalUsername(params: { username: string; password: string }) {
  const padded = padUsernameForLocalKey(params.username)
  return encryptStringWithPassword({
    plaintext: padded,
    password: params.password,
    iterations: LOCAL_KEY_USERNAME_ITERATIONS,
  })
}

export async function decryptLocalUsername(params: { encrypted: string; password: string }) {
  const padded = await decryptStringWithPassword({ encrypted: params.encrypted, password: params.password })
  return unpadUsernameFromLocalKey(padded)
}

export function publicJwkFromPrivateJwk(privateJwkJson: string) {
  const jwk = JSON.parse(privateJwkJson)
  const kty = typeof jwk?.kty === 'string' ? jwk.kty : null
  const n = typeof jwk?.n === 'string' ? jwk.n : null
  const e = typeof jwk?.e === 'string' ? jwk.e : null
  if (kty !== 'RSA' || !n || !e) throw new Error('Invalid private JWK')

  // Minimal RSA public JWK; WebCrypto import accepts this for RSA-OAEP.
  const pub = { kty: 'RSA', n, e, ext: true, key_ops: ['encrypt'] }
  return JSON.stringify(pub)
}

export async function importRsaPublicKeyJwk(jwkJson: string) {
  const jwk = JSON.parse(jwkJson)
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  )
}

export async function importRsaPrivateKeyJwk(jwkJson: string) {
  const jwk = JSON.parse(jwkJson)
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  )
}

export async function encryptSmallStringWithPublicKeyJwk(params: {
  plaintext: string
  publicKeyJwkJson: string
}) {
  const pt = String(params.plaintext)
  // RSA-OAEP has a maximum plaintext size; keep this bounded.
  if (pt.length > 1024) throw new Error('Plaintext too large')
  const pub = await importRsaPublicKeyJwk(params.publicKeyJwkJson)
  const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, encUtf8(pt))
  return b64(ct)
}

export async function decryptSmallStringWithPrivateKey(params: {
  ciphertextB64: string
  privateKey: CryptoKey
}) {
  const wrapped = unb64(String(params.ciphertextB64))
  const pt = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, params.privateKey, wrapped)
  return decUtf8(pt)
}

export async function encryptSignedMessage(params: {
  plaintext: {
    text: string
    atIso: string
    replyToId?: string | null
    modifiedAtIso?: string | null
  }
  recipients: Array<{ userId: string; publicKeyJwk: string }>
}) {
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const pt = JSON.stringify(params.plaintext)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encUtf8(pt))

  const rawKey = await crypto.subtle.exportKey('raw', aesKey)

  const keys: Record<string, string> = {}
  for (const r of params.recipients) {
    const pub = await importRsaPublicKeyJwk(r.publicKeyJwk)
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawKey)
    keys[String(r.userId)] = b64(wrapped)
  }

  return JSON.stringify({ v: 1, alg: 'A256GCM+RSA-OAEP-256', ivB64: b64(iv), ctB64: b64(ct), keys })
}

export async function decryptSignedMessage(params: {
  encryptedData: string
  myUserId: string
  myPrivateKey: CryptoKey
}) {
  const obj = JSON.parse(params.encryptedData) as {
    v: number
    ivB64: string
    ctB64: string
    keys: Record<string, string>
  }

  if (!obj || obj.v !== 1) throw new Error('Unsupported message format')

  const wrappedB64 = obj.keys?.[String(params.myUserId)]
  if (!wrappedB64) throw new Error('No key for recipient')

  const wrapped = unb64(wrappedB64)
  const rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, params.myPrivateKey, wrapped)
  const aesKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt'])

  const iv = unb64(obj.ivB64)
  const ct = unb64(obj.ctB64)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct)

  const parsed = JSON.parse(decUtf8(pt)) as {
    text: unknown
    atIso: unknown
    replyToId?: unknown
    modifiedAtIso?: unknown
  }

  return {
    text: typeof parsed?.text === 'string' ? parsed.text : '',
    atIso: typeof parsed?.atIso === 'string' ? parsed.atIso : new Date().toISOString(),
    replyToId: typeof parsed?.replyToId === 'string' ? parsed.replyToId : null,
    modifiedAtIso: typeof parsed?.modifiedAtIso === 'string' ? parsed.modifiedAtIso : null,
  }
}
