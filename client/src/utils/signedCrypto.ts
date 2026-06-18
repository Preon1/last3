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
const ENVELOPE_TEXT_COMPRESS_MIN_INPUT_BYTES = 192
const ENVELOPE_TEXT_COMPRESS_MAX_RATIO = 0.9
const ENVELOPE_TEXT_MAX_DECOMPRESSED_BYTES = 64 * 1024

const ENVELOPE_PAD_HARD_MAX_RANDOM_LEN = 4096
const RSA_PUBLIC_EXPONENT_B64URL = 'AQAB'
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/
const RSA_MODULUS_MIN_LEN = 128
const RSA_MODULUS_MAX_LEN = 2048

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

function isLikelyRsaModulus(value: unknown) {
  if (typeof value !== 'string') return false
  if (!BASE64URL_RE.test(value)) return false
  if (value.length < RSA_MODULUS_MIN_LEN || value.length > RSA_MODULUS_MAX_LEN) return false
  return true
}

function parsePublicKeyInputToRsaJwk(publicKey: string) {
  const raw = String(publicKey ?? '').trim()
  if (!raw) throw new Error('Invalid public key')

  // Strict compact format: only RSA modulus n.
  if (!isLikelyRsaModulus(raw)) throw new Error('Invalid public key')
  return { kty: 'RSA', n: raw, e: RSA_PUBLIC_EXPONENT_B64URL }
}

function encUtf8(s: string) {
  return new TextEncoder().encode(s)
}

function decUtf8(b: ArrayBuffer | Uint8Array) {
  const u8 = b instanceof Uint8Array ? b : new Uint8Array(b)
  return new TextDecoder().decode(u8)
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

  const modulus = typeof (publicJwk as any)?.n === 'string' ? (publicJwk as any).n : null
  const exponent = typeof (publicJwk as any)?.e === 'string' ? (publicJwk as any).e : null
  if (!isLikelyRsaModulus(modulus) || exponent !== RSA_PUBLIC_EXPONENT_B64URL) {
    throw new Error('Invalid generated public key')
  }

  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    // Send/store only modulus to minimize payload size in API and chat metadata.
    publicJwk: modulus,
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

function normalizeEnvelopePadBounds(minPadChars: number, maxPadChars: number) {
  const min = Number.isFinite(minPadChars) ? Math.max(0, Math.floor(minPadChars)) : NaN
  const max = Number.isFinite(maxPadChars) ? Math.max(0, Math.floor(maxPadChars)) : NaN
  if (!Number.isFinite(min) || !Number.isFinite(max) || max < min) {
    throw new Error('Invalid envelope padding range')
  }
  if (max > ENVELOPE_PAD_HARD_MAX_RANDOM_LEN) {
    throw new Error('Envelope padding range too large')
  }
  return { min, max }
}

function makeEnvelopeObjectPadding(minPadChars: number, maxPadChars: number) {
  const bounds = normalizeEnvelopePadBounds(minPadChars, maxPadChars)
  const randomLen = randomIntInclusive(bounds.min, bounds.max)
  return randomStringFromAlphabet(randomLen, TEXT_PAD_ALPHABET)
}

function assertEnvelopeObjectPadding(padding: unknown, minPadChars: number, maxPadChars: number) {
  if (typeof padding !== 'string') throw new Error('Unsupported message format')
  const bounds = normalizeEnvelopePadBounds(minPadChars, maxPadChars)
  if (padding.length < bounds.min || padding.length > bounds.max) throw new Error('Unsupported message format')
  if (!isStringFromAlphabet(padding, TEXT_PAD_ALPHABET_SET)) throw new Error('Unsupported message format')
}

function getCompressionStreamConstructors() {
  const CompressionStreamCtor = (globalThis as { CompressionStream?: unknown }).CompressionStream
  const DecompressionStreamCtor = (globalThis as { DecompressionStream?: unknown }).DecompressionStream
  if (typeof CompressionStreamCtor !== 'function' || typeof DecompressionStreamCtor !== 'function') {
    throw new Error('Unsupported message format')
  }
  return {
    CompressionStreamCtor: CompressionStreamCtor as new (format: 'deflate') => {
      readable: ReadableStream<Uint8Array>
      writable: WritableStream<Uint8Array>
    },
    DecompressionStreamCtor: DecompressionStreamCtor as new (format: 'deflate') => {
      readable: ReadableStream<Uint8Array>
      writable: WritableStream<Uint8Array>
    },
  }
}

async function deflateBytes(input: Uint8Array) {
  const { CompressionStreamCtor } = getCompressionStreamConstructors()
  const stream = new CompressionStreamCtor('deflate')
  const writer = stream.writable.getWriter()
  await writer.write(input)
  await writer.close()
  const compressed = await new Response(stream.readable).arrayBuffer()
  return new Uint8Array(compressed)
}

async function inflateBytes(input: Uint8Array) {
  const { DecompressionStreamCtor } = getCompressionStreamConstructors()
  const stream = new DecompressionStreamCtor('deflate')
  const writer = stream.writable.getWriter()
  await writer.write(input)
  await writer.close()
  const decompressed = await new Response(stream.readable).arrayBuffer()
  return new Uint8Array(decompressed)
}

async function encodeEnvelopeMessageText(rawText: string) {
  const text = String(rawText ?? '')
  const sourceBytes = encUtf8(text)

  // Fast path: skip compression for short messages.
  if (sourceBytes.byteLength < ENVELOPE_TEXT_COMPRESS_MIN_INPUT_BYTES) {
    return { z: 0 as const, t: text }
  }

  const compressed = await deflateBytes(sourceBytes)
  if (!compressed.byteLength) return { z: 0 as const, t: text }

  const compressedB64Url = b64Url(compressed)
  const compressedLen = encUtf8(compressedB64Url).byteLength
  const sourceLen = sourceBytes.byteLength

  // Keep compressed form only if it produces a meaningful size reduction.
  if (compressedLen > Math.floor(sourceLen * ENVELOPE_TEXT_COMPRESS_MAX_RATIO)) {
    return { z: 0 as const, t: text }
  }

  return { z: 1 as const, t: compressedB64Url }
}

async function decodeEnvelopeMessageText(encodedText: string, compressionMode: 0 | 1) {
  const text = String(encodedText ?? '')
  if (compressionMode === 0) return text

  let compressedBytes: Uint8Array
  try {
    compressedBytes = unb64Url(text)
  } catch {
    throw new Error('Unsupported message format')
  }

  let decompressed: Uint8Array
  try {
    decompressed = await inflateBytes(compressedBytes)
  } catch {
    throw new Error('Unsupported message format')
  }

  if (decompressed.byteLength > ENVELOPE_TEXT_MAX_DECOMPRESSED_BYTES) {
    throw new Error('Unsupported message format')
  }

  return decUtf8(decompressed)
}

type CompactEnvelopePayload = {
  // t = plaintext message text
  t: string
  // z = text compression mode: 0 = plain UTF-8 text in t, 1 = deflate+base64url in t
  z: 0 | 1
  // ct = create time (ISO)
  ct: string
  // a = reply target message id (legacy replyToId semantic)
  a: string | null
  // mt = modification time (ISO), omitted for new messages
  mt?: string
  // p = random object-level padding
  p: string
}

export function publicJwkFromPrivateJwk(privateJwkJson: string) {
  const jwk = JSON.parse(privateJwkJson)
  const kty = typeof jwk?.kty === 'string' ? jwk.kty : null
  const n = typeof jwk?.n === 'string' ? jwk.n : null
  const e = typeof jwk?.e === 'string' ? jwk.e : null
  if (kty !== 'RSA' || !isLikelyRsaModulus(n) || e !== RSA_PUBLIC_EXPONENT_B64URL) {
    throw new Error('Invalid private JWK')
  }

  // Compact public key format: only the unique modulus n.
  return n
}

export async function importRsaPublicKeyJwk(jwkJson: string) {
  const jwk = parsePublicKeyInputToRsaJwk(jwkJson)
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
  const jwk = stripJwkOps(parsePublicKeyInputToRsaJwk(jwkJson))
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
  objectPadMinChars: number
  objectPadMaxChars: number
}) {
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const encodedText = await encodeEnvelopeMessageText(String(params.plaintext?.text ?? ''))

  const compactPayload: CompactEnvelopePayload = {
    t: encodedText.t,
    z: encodedText.z,
    ct: String(params.plaintext?.atIso ?? ''),
    a: typeof params.plaintext?.replyToId === 'string' ? params.plaintext.replyToId : null,
    p: makeEnvelopeObjectPadding(params.objectPadMinChars, params.objectPadMaxChars),
  }

  if (!compactPayload.ct) throw new Error('Unsupported message format')

  if (typeof params.plaintext?.modifiedAtIso === 'string' && params.plaintext.modifiedAtIso) {
    compactPayload.mt = params.plaintext.modifiedAtIso
  }

  const pt = JSON.stringify(compactPayload)
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
  objectPadMinChars: number
  objectPadMaxChars: number
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

  const parsed = JSON.parse(decUtf8(pt)) as Partial<CompactEnvelopePayload> | null
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Unsupported message format')

  const encodedText = typeof parsed.t === 'string' ? parsed.t : null
  const compressionMode = parsed.z === 0 || parsed.z === 1 ? parsed.z : null
  const atIso = typeof parsed.ct === 'string' && parsed.ct ? parsed.ct : null
  if (encodedText === null || compressionMode === null || atIso === null) throw new Error('Unsupported message format')

  if (!(parsed.a === null || typeof parsed.a === 'string' || typeof parsed.a === 'undefined')) {
    throw new Error('Unsupported message format')
  }

  const modifiedAtIso =
    typeof parsed.mt === 'undefined' ? null : typeof parsed.mt === 'string' && parsed.mt ? parsed.mt : null
  if (typeof parsed.mt !== 'undefined' && modifiedAtIso === null) throw new Error('Unsupported message format')

  assertEnvelopeObjectPadding(parsed.p, params.objectPadMinChars, params.objectPadMaxChars)
  const text = await decodeEnvelopeMessageText(encodedText, compressionMode)

  return {
    text,
    atIso,
    replyToId: typeof parsed.a === 'string' ? parsed.a : null,
    modifiedAtIso,
  }
}
