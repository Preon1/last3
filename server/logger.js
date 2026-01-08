const raw = process.env.DEBUG ?? process.env.LRCOM_DEBUG ?? '';

export const DEBUG_ENABLED = /^(1|true|yes|on)$/i.test(String(raw).trim());

export function debugLog(...args) {
  if (!DEBUG_ENABLED) return;
  console.log(...args);
}

export function debugWarn(...args) {
  if (!DEBUG_ENABLED) return;
  console.warn(...args);
}

export function debugError(...args) {
  if (!DEBUG_ENABLED) return;
  console.error(...args);
}
