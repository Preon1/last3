// Minimal browser-safe shim for Node's `crypto` module.
//
// Some dependencies include a guarded `require('crypto')` branch for Node.
// Vite will still attempt to resolve it during bundling and warns when it
// externalizes Node built-ins for browser.
//
// This shim avoids the warning without pulling in a heavy polyfill.

export function randomBytes(size: number): Uint8Array {
  const n = Math.max(0, Number(size) || 0)
  const out = new Uint8Array(n)

  const c = (globalThis as any)?.crypto
  if (c?.getRandomValues) {
    c.getRandomValues(out)
    return out
  }

  // Extremely defensive fallback (should never happen in modern browsers).
  for (let i = 0; i < out.length; i++) out[i] = Math.floor(Math.random() * 256)
  return out
}

export default {
  randomBytes,
}
