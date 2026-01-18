import { createI18n } from 'vue-i18n'
import { LocalEntity, localData } from './utils/localData'

import en from './i18n/en'
import nl from './i18n/nl'
import fr from './i18n/fr'
import de from './i18n/de'
import ru from './i18n/ru'

export const supportedLocales = ['en', 'nl', 'fr', 'de', 'ru'] as const
export type SupportedLocale = (typeof supportedLocales)[number]

function normalizeLocale(raw: string | null | undefined): SupportedLocale | null {
  const s = (raw ?? '').trim().toLowerCase()
  if (!s) return null

  // Accept exact match
  if ((supportedLocales as readonly string[]).includes(s)) return s as SupportedLocale

  // Accept prefixes like "de-DE" / "ru_RU"
  const base = s.split(/[-_]/)[0] ?? ''
  if ((supportedLocales as readonly string[]).includes(base)) return base as SupportedLocale

  return null
}

function detectInitialLocale(): SupportedLocale {
  const saved = normalizeLocale(localData.getString(LocalEntity.Locale))
  if (saved) return saved

  const nav =
    normalizeLocale(navigator.language) ??
    normalizeLocale(Array.isArray(navigator.languages) ? navigator.languages[0] : null) ??
    null

  return nav ?? 'en'
}

const baseMessages = { en, nl, fr, de, ru } as const

type AnyRecord = any

function isPlainObject(v: unknown): v is AnyRecord {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v)
}

function mergeDeep(base: AnyRecord, override: AnyRecord): AnyRecord {
  const out: AnyRecord = { ...(base ?? {}) }
  for (const [k, v] of Object.entries(override ?? {})) {
    if (isPlainObject(v) && isPlainObject(base?.[k])) out[k] = mergeDeep(base[k], v)
    else out[k] = v
  }
  return out
}

// Ensure every locale has the full key spectrum.
// Any missing key falls back to English (without needing to duplicate text).
export const messages: Record<SupportedLocale, any> = {
  en: baseMessages.en,
  nl: mergeDeep(baseMessages.en, baseMessages.nl),
  fr: mergeDeep(baseMessages.en, baseMessages.fr),
  de: mergeDeep(baseMessages.en, baseMessages.de),
  ru: mergeDeep(baseMessages.en, baseMessages.ru),
}

export const i18n: any = createI18n({
  legacy: false,
  locale: detectInitialLocale(),
  fallbackLocale: 'en',
  warnHtmlMessage: false,
  messages,
} as any)

export function getLocale(): SupportedLocale {
  return normalizeLocale(String(i18n.global.locale.value)) ?? 'en'
}

export function setLocale(next: SupportedLocale) {
  i18n.global.locale.value = next
  localData.setString(LocalEntity.Locale, next)
}

export function cycleLocale(): SupportedLocale {
  const cur = getLocale()
  const idx = supportedLocales.indexOf(cur)
  const next = supportedLocales[((idx >= 0 ? idx : -1) + 1) % supportedLocales.length] ?? 'en'
  setLocale(next)
  return next
}
