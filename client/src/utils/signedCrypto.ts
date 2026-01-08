type StoredEncryptedBlobV1 = {
  v: 1
  kdf: 'PBKDF2-SHA256'
  iterations: number
  saltB64: string
  ivB64: string
  ctB64: string
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

function concatU8(parts: Uint8Array[]) {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

async function sha256U8(data: Uint8Array) {
  const dig = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource)
  return new Uint8Array(dig)
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

export async function encryptPrivateKeyJwk(params: { privateJwk: string; password: string; extraEntropy?: Uint8Array }) {
  return encryptStringWithPassword({ plaintext: params.privateJwk, password: params.password, extraEntropy: params.extraEntropy })
}

export async function decryptPrivateKeyJwk({ encrypted, password }: { encrypted: string; password: string }) {
  return decryptStringWithPassword({ encrypted, password })
}

export async function encryptStringWithPassword(params: { plaintext: string; password: string; extraEntropy?: Uint8Array }) {
  const iterations = 250_000

  let salt = crypto.getRandomValues(new Uint8Array(16))
  let iv = crypto.getRandomValues(new Uint8Array(12))

  // Mix in optional user entropy (does not replace WebCrypto RNG; it only influences
  // how we encrypt stored secrets at rest).
  if (params.extraEntropy && params.extraEntropy.length) {
    const rnd = crypto.getRandomValues(new Uint8Array(32))
    const label = encUtf8('lrcom:extra-entropy:v1')
    const mixed = await sha256U8(concatU8([label, rnd, params.extraEntropy]))
    salt = mixed.slice(0, 16)
    iv = mixed.slice(16, 28)
  }

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

export async function encryptSignedMessage(params: {
  plaintext: {
    text: string
    atIso: string
    fromUsername: string
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
    fromUsername: unknown
    replyToId?: unknown
    modifiedAtIso?: unknown
  }

  return {
    text: typeof parsed?.text === 'string' ? parsed.text : '',
    atIso: typeof parsed?.atIso === 'string' ? parsed.atIso : new Date().toISOString(),
    fromUsername: typeof parsed?.fromUsername === 'string' ? parsed.fromUsername : '',
    replyToId: typeof parsed?.replyToId === 'string' ? parsed.replyToId : null,
    modifiedAtIso: typeof parsed?.modifiedAtIso === 'string' ? parsed.modifiedAtIso : null,
  }
}
