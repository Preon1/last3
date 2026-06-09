import { Evaluation, Oprf, VOPRFClient } from '@cloudflare/voprf-ts'
import { CryptoNoble } from '@cloudflare/voprf-ts/crypto-noble'

type VoprfConfig = {
  mode: 'VOPRF'
  suite: 'P256_SHA256'
  publicKeyB64u: string
}

let cachedConfig: VoprfConfig | null = null

// Force a browser-compatible crypto backend.
Oprf.Crypto = CryptoNoble

function b64uToU8(b64u: string): Uint8Array {
  const s = String(b64u ?? '')
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .trim()

  // Add base64 padding if missing.
  const padLen = (4 - (s.length % 4)) % 4
  const padded = s + '='.repeat(padLen)

  const bin = atob(padded)
  const u8 = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
  return u8
}

function u8ToB64u(u8: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]!)
  const b64 = btoa(bin)
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function encUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function canonicalizeNameInput(input: string): string {
  // Canonicalization must be stable across all clients.
  // NOTE: Server stores only the token; it does not re-canonicalize.
  return String(input ?? '')
    .normalize('NFKC')
    .trim()
    .toLowerCase()
}

export async function getVoprfConfig(): Promise<VoprfConfig> {
  if (cachedConfig) return cachedConfig

  const r = await fetch('/api/config', { method: 'GET' })
  const j = (await r.json()) as { voprf?: unknown }

  const v = j?.voprf as Partial<VoprfConfig> | undefined
  if (!v || v.mode !== 'VOPRF' || v.suite !== 'P256_SHA256' || typeof v.publicKeyB64u !== 'string' || !v.publicKeyB64u) {
    throw new Error('VOPRF config missing')
  }

  cachedConfig = { mode: 'VOPRF', suite: 'P256_SHA256', publicKeyB64u: v.publicKeyB64u }
  return cachedConfig
}

export async function voprfNameToken(params: { kind: 'user' | 'chat'; input: string }): Promise<string> {
  const inputCanon = canonicalizeNameInput(params.input)
  if (!inputCanon) throw new Error('Name is required')

  // Domain separation to avoid cross-namespace token reuse.
  const prefixed = `${params.kind === 'chat' ? 'c' : 'u'}:${inputCanon}`

  const cfg = await getVoprfConfig()
  const suite = Oprf.Suite.P256_SHA256
  const serverPub = b64uToU8(cfg.publicKeyB64u)

  const client = new VOPRFClient(suite, serverPub)

  const [finData, evalReq] = await client.blind([encUtf8(prefixed)])
  const evalReqB64u = u8ToB64u(evalReq.serialize())

  const r = await fetch('/api/voprf/eval', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ evalReqB64u }),
  })

  const j = (await r.json()) as { success?: unknown; evaluationB64u?: unknown; error?: unknown }
  const evaluationB64u = typeof j?.evaluationB64u === 'string' ? j.evaluationB64u : ''
  if (!r.ok || !evaluationB64u) {
    const err = typeof j?.error === 'string' ? j.error : 'VOPRF eval failed'
    throw new Error(err)
  }

  const evaluation = Evaluation.deserialize(suite, b64uToU8(evaluationB64u))
  const out = await client.finalize(finData, evaluation)

  const tokenBytes = out?.[0]
  if (!(tokenBytes instanceof Uint8Array) || !tokenBytes.length) throw new Error('VOPRF finalize failed')

  return u8ToB64u(tokenBytes)
}
