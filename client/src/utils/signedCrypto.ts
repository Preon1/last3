export const LOCAL_KEY_PRIVATE_KEY_ITERATIONS = 612_345
const PBE_SALT_BYTES = 16
const PBE_IV_BYTES = 12
const AES_GCM_TAG_BYTES = 16
const PBE_SALT_B64_LEN = Math.ceil(PBE_SALT_BYTES / 3) * 4
const PBE_IV_B64_LEN = Math.ceil(PBE_IV_BYTES / 3) * 4
const PBE_CT_MIN_B64_LEN = Math.ceil(AES_GCM_TAG_BYTES / 3) * 4
const PBE_BLOB_MIN_LEN = PBE_SALT_B64_LEN + PBE_IV_B64_LEN + PBE_CT_MIN_B64_LEN

const ENVELOPE_IV_BYTES = 12
const ENVELOPE_RECIPIENT_COUNT_BYTES = 2
const ENVELOPE_RECIPIENT_ID_BYTES = 16
const ENVELOPE_WRAPPED_KEY_BYTES = 512
const ENVELOPE_ENTRY_BYTES = ENVELOPE_RECIPIENT_ID_BYTES + ENVELOPE_WRAPPED_KEY_BYTES
const ENVELOPE_MIN_CT_BYTES = AES_GCM_TAG_BYTES
const ENVELOPE_MAX_RECIPIENTS = 65_535

const SIGNED_TEXT_PAD_PREFIX = 'STP'
const SIGNED_TEXT_PAD_LEN_HEX_WIDTH = 4
const SIGNED_TEXT_PAD_HARD_MAX_RANDOM_LEN = 4096

const TEXT_PAD_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()-_=+[]{};:,.<>/?'

const TEXT_PAD_ALPHABET_SET = new Set(TEXT_PAD_ALPHABET.split(''))

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

function b64Url(bytes: ArrayBuffer | Uint8Array) {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function unb64Url(s: string) {
  const raw = String(s ?? '').replace(/-/g, '+').replace(/_/g, '/')
  const padLen = (4 - (raw.length % 4)) % 4
  const padded = `${raw}${'='.repeat(padLen)}`
  return unb64(padded)
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

function randomIntInclusive(min: number, max: number) {
  const lo = Math.min(min, max)
  const hi = Math.max(min, max)
  const span = hi - lo + 1
  if (span <= 1) return lo
  const u32 = crypto.getRandomValues(new Uint32Array(1))
  return lo + ((u32[0] ?? 0) % span)
}

function parseUuidToBytes(uuid: string) {
  const raw = String(uuid ?? '').trim().toLowerCase()
  const hex = raw.replace(/-/g, '')
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error('Invalid user id in envelope')
  const out = new Uint8Array(ENVELOPE_RECIPIENT_ID_BYTES)
  for (let i = 0; i < ENVELOPE_RECIPIENT_ID_BYTES; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.byteLength !== b.byteLength) return false
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function packMessageEnvelopeBlob(parts: {
  iv: Uint8Array
  ct: Uint8Array
  keyEntries: Array<{ userIdBytes: Uint8Array; wrappedKeyBytes: Uint8Array }>
}) {
  const iv = parts.iv
  const ct = parts.ct
  const keyEntries = Array.isArray(parts.keyEntries) ? parts.keyEntries : []

  if (!(iv instanceof Uint8Array) || iv.byteLength !== ENVELOPE_IV_BYTES) throw new Error('Unsupported message format')
  if (!(ct instanceof Uint8Array) || ct.byteLength < ENVELOPE_MIN_CT_BYTES) throw new Error('Unsupported message format')
  if (keyEntries.length <= 0 || keyEntries.length > ENVELOPE_MAX_RECIPIENTS) throw new Error('Unsupported message format')

  const totalLen = ENVELOPE_IV_BYTES + ENVELOPE_RECIPIENT_COUNT_BYTES + keyEntries.length * ENVELOPE_ENTRY_BYTES + ct.byteLength
  const out = new Uint8Array(totalLen)
  let off = 0

  out.set(iv, off)
  off += ENVELOPE_IV_BYTES

  out[off] = (keyEntries.length >> 8) & 0xff
  out[off + 1] = keyEntries.length & 0xff
  off += ENVELOPE_RECIPIENT_COUNT_BYTES

  for (const entry of keyEntries) {
    if (entry.userIdBytes.byteLength !== ENVELOPE_RECIPIENT_ID_BYTES) throw new Error('Unsupported message format')
    if (entry.wrappedKeyBytes.byteLength !== ENVELOPE_WRAPPED_KEY_BYTES) throw new Error('Unsupported message format')
    out.set(entry.userIdBytes, off)
    off += ENVELOPE_RECIPIENT_ID_BYTES
    out.set(entry.wrappedKeyBytes, off)
    off += ENVELOPE_WRAPPED_KEY_BYTES
  }

  out.set(ct, off)
  return b64Url(out)
}

function unpackMessageEnvelopeBlob(encryptedData: string) {
  const all = unb64Url(encryptedData)
  const min = ENVELOPE_IV_BYTES + ENVELOPE_RECIPIENT_COUNT_BYTES + ENVELOPE_MIN_CT_BYTES
  if (all.byteLength < min) throw new Error('Unsupported message format')

  let off = 0
  const iv = all.slice(off, off + ENVELOPE_IV_BYTES)
  off += ENVELOPE_IV_BYTES

  const recipientCount = (all[off]! << 8) | all[off + 1]!
  off += ENVELOPE_RECIPIENT_COUNT_BYTES
  if (recipientCount <= 0) throw new Error('Unsupported message format')

  const neededForKeys = recipientCount * ENVELOPE_ENTRY_BYTES
  if (off + neededForKeys + ENVELOPE_MIN_CT_BYTES > all.byteLength) throw new Error('Unsupported message format')

  const keyEntries: Array<{ userIdBytes: Uint8Array; wrappedKeyBytes: Uint8Array }> = []
  for (let i = 0; i < recipientCount; i++) {
    const userIdBytes = all.slice(off, off + ENVELOPE_RECIPIENT_ID_BYTES)
    off += ENVELOPE_RECIPIENT_ID_BYTES
    const wrappedKeyBytes = all.slice(off, off + ENVELOPE_WRAPPED_KEY_BYTES)
    off += ENVELOPE_WRAPPED_KEY_BYTES
    keyEntries.push({ userIdBytes, wrappedKeyBytes })
  }

  const ct = all.slice(off)
  if (ct.byteLength < ENVELOPE_MIN_CT_BYTES) throw new Error('Unsupported message format')

  return { iv, ct, keyEntries }
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

function packPbeBlob(parts: { salt: Uint8Array; iv: Uint8Array; ct: ArrayBuffer | Uint8Array }) {
  return `${b64(parts.salt)}${b64(parts.iv)}${b64(parts.ct)}`
}

function unpackPbeBlob(blob: string) {
  const raw = String(blob ?? '')
  if (raw.length < PBE_BLOB_MIN_LEN) throw new Error('Unsupported encrypted blob format')

  const saltB64 = raw.slice(0, PBE_SALT_B64_LEN)
  const ivB64 = raw.slice(PBE_SALT_B64_LEN, PBE_SALT_B64_LEN + PBE_IV_B64_LEN)
  const ctB64 = raw.slice(PBE_SALT_B64_LEN + PBE_IV_B64_LEN)
  if (!ctB64) throw new Error('Unsupported encrypted blob format')

  let salt: Uint8Array
  let iv: Uint8Array
  let ct: Uint8Array
  try {
    salt = unb64(saltB64)
    iv = unb64(ivB64)
    ct = unb64(ctB64)
  } catch {
    throw new Error('Unsupported encrypted blob format')
  }

  if (salt.byteLength !== PBE_SALT_BYTES) throw new Error('Unsupported encrypted blob format')
  if (iv.byteLength !== PBE_IV_BYTES) throw new Error('Unsupported encrypted blob format')
  if (ct.byteLength < AES_GCM_TAG_BYTES) throw new Error('Unsupported encrypted blob format')

  return { salt, iv, ct }
}

export async function encryptStringWithPassword(params: { plaintext: string; password: string }) {
  const salt = crypto.getRandomValues(new Uint8Array(PBE_SALT_BYTES))
  const iv = crypto.getRandomValues(new Uint8Array(PBE_IV_BYTES))

  const aesKey = await deriveAesKeyFromPassword(params.password, salt, LOCAL_KEY_PRIVATE_KEY_ITERATIONS)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encUtf8(params.plaintext))

  return packPbeBlob({ salt, iv, ct })
}

export async function decryptStringWithPassword(params: { encrypted: string; password: string }) {
  const { salt, iv, ct } = unpackPbeBlob(params.encrypted)

  const aesKey = await deriveAesKeyFromPassword(params.password, salt, LOCAL_KEY_PRIVATE_KEY_ITERATIONS)
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    aesKey,
    ct as unknown as BufferSource,
  )
  return decUtf8(pt)
}

function normalizeTextPadBounds(minPadChars: number, maxPadChars: number) {
  const min = Number.isFinite(minPadChars) ? Math.max(0, Math.floor(minPadChars)) : NaN
  const max = Number.isFinite(maxPadChars) ? Math.max(0, Math.floor(maxPadChars)) : NaN
  if (!Number.isFinite(min) || !Number.isFinite(max) || max < min) {
    throw new Error('Invalid signed text padding range')
  }
  if (max > SIGNED_TEXT_PAD_HARD_MAX_RANDOM_LEN) {
    throw new Error('Signed text padding range too large')
  }
  return { min, max }
}

function padEnvelopeText(rawText: string, minPadChars: number, maxPadChars: number) {
  const bounds = normalizeTextPadBounds(minPadChars, maxPadChars)
  const text = String(rawText ?? '')
  const lenHex = text.length.toString(16).padStart(SIGNED_TEXT_PAD_LEN_HEX_WIDTH, '0')
  if (lenHex.length !== SIGNED_TEXT_PAD_LEN_HEX_WIDTH || !/^[0-9a-fA-F]{4}$/.test(lenHex)) {
    throw new Error('Signed text too long to pad')
  }

  const randomLen = randomIntInclusive(bounds.min, bounds.max)
  const tail = randomStringFromAlphabet(randomLen, TEXT_PAD_ALPHABET)
  return `${SIGNED_TEXT_PAD_PREFIX}${lenHex}${text}${tail}`
}

function unpadEnvelopeText(padded: string, minPadChars: number, maxPadChars: number) {
  const bounds = normalizeTextPadBounds(minPadChars, maxPadChars)
  const s = String(padded ?? '')
  if (!s.startsWith(SIGNED_TEXT_PAD_PREFIX)) throw new Error('Unsupported signed text format')

  const lenStart = SIGNED_TEXT_PAD_PREFIX.length
  const lenEnd = lenStart + SIGNED_TEXT_PAD_LEN_HEX_WIDTH
  if (s.length < lenEnd) throw new Error('Unsupported signed text format')

  const lenHex = s.slice(lenStart, lenEnd)
  if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) throw new Error('Unsupported signed text format')

  const n = Number.parseInt(lenHex, 16)
  if (!Number.isFinite(n) || n < 0) throw new Error('Unsupported signed text format')

  const textStart = lenEnd
  const textEnd = textStart + n
  if (textEnd > s.length) throw new Error('Unsupported signed text format')

  const tail = s.slice(textEnd)
  if (tail.length < bounds.min || tail.length > bounds.max) throw new Error('Unsupported signed text format')
  if (!isStringFromAlphabet(tail, TEXT_PAD_ALPHABET_SET)) throw new Error('Unsupported signed text format')

  return s.slice(textStart, textEnd)
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

function stripJwkOps(jwk: any) {
  if (!jwk || typeof jwk !== 'object') return jwk
  const out = { ...jwk }
  // Some JWKs include key_ops that can prevent re-import for different usages.
  delete (out as any).key_ops
  delete (out as any).alg
  return out
}

export async function importRsaPssPublicKeyJwk(jwkJson: string) {
  const jwk = stripJwkOps(JSON.parse(jwkJson))
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify'],
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

export async function importRsaPssPrivateKeyJwk(jwkJson: string) {
  const jwk = stripJwkOps(JSON.parse(jwkJson))
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['sign'],
  )
}

export async function signEnvelope(params: { signingKey: CryptoKey; senderId: string; chatId: string; encryptedData: string }) {
  const payload = JSON.stringify({
    v: 1,
    senderId: String(params.senderId),
    chatId: String(params.chatId),
    encryptedData: String(params.encryptedData),
  })

  const sig = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    params.signingKey,
    encUtf8(payload),
  )
  return b64(sig)
}

export async function verifyEnvelope(params: {
  verifyKey: CryptoKey
  signatureB64: string
  senderId: string
  chatId: string
  encryptedData: string
}) {
  const sigB64 = String(params.signatureB64 ?? '')
  if (!sigB64) return false

  const payload = JSON.stringify({
    v: 1,
    senderId: String(params.senderId),
    chatId: String(params.chatId),
    encryptedData: String(params.encryptedData),
  })

  try {
    const sig = unb64(sigB64)
    return await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      params.verifyKey,
      sig,
      encUtf8(payload),
    )
  } catch {
    return false
  }
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

export async function encryptMessageEnvelope(params: {
  plaintext: {
    text: string
    atIso: string
    replyToId?: string | null
    modifiedAtIso?: string | null
  }
  recipients: Array<{ userId: string; publicKeyJwk: string }>
  textPadMinChars: number
  textPadMaxChars: number
}) {
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const paddedText = padEnvelopeText(
    String(params.plaintext?.text ?? ''),
    params.textPadMinChars,
    params.textPadMaxChars,
  )
  const pt = JSON.stringify({ ...params.plaintext, text: paddedText })
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encUtf8(pt))

  const rawKey = await crypto.subtle.exportKey('raw', aesKey)

  const keyEntries: Array<{ userIdBytes: Uint8Array; wrappedKeyBytes: Uint8Array }> = []
  for (const r of params.recipients) {
    const pub = await importRsaPublicKeyJwk(r.publicKeyJwk)
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawKey)
    keyEntries.push({
      userIdBytes: parseUuidToBytes(String(r.userId)),
      wrappedKeyBytes: new Uint8Array(wrapped),
    })
  }

  return packMessageEnvelopeBlob({ iv, ct: new Uint8Array(ct), keyEntries })
}

export async function decryptMessageEnvelope(params: {
  encryptedData: string
  myUserId: string
  myPrivateKey: CryptoKey
  textPadMinChars: number
  textPadMaxChars: number
}) {
  const myUserIdBytes = parseUuidToBytes(String(params.myUserId))
  const obj = unpackMessageEnvelopeBlob(params.encryptedData)

  let wrappedBytes: Uint8Array | null = null
  for (const entry of obj.keyEntries) {
    if (equalBytes(entry.userIdBytes, myUserIdBytes)) {
      wrappedBytes = entry.wrappedKeyBytes
      break
    }
  }
  if (!wrappedBytes) throw new Error('No key for recipient')

  const rawKey = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    params.myPrivateKey,
    wrappedBytes as unknown as BufferSource,
  )
  const aesKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt'])

  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: obj.iv }, aesKey, obj.ct)

  const parsed = JSON.parse(decUtf8(pt)) as {
    text: unknown
    atIso: unknown
    replyToId?: unknown
    modifiedAtIso?: unknown
  }

  const rawText = typeof parsed?.text === 'string' ? parsed.text : ''
  const text = unpadEnvelopeText(rawText, params.textPadMinChars, params.textPadMaxChars)

  return {
    text,
    atIso: typeof parsed?.atIso === 'string' ? parsed.atIso : new Date().toISOString(),
    replyToId: typeof parsed?.replyToId === 'string' ? parsed.replyToId : null,
    modifiedAtIso: typeof parsed?.modifiedAtIso === 'string' ? parsed.modifiedAtIso : null,
  }
}
