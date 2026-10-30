import { DEFAULT_BRAND } from './brand'

export const rtlLocales = new Set(['ar', 'he', 'fa', 'ur'])
export function getDirFromLocale(locale?: string): 'ltr' | 'rtl' {
  const code = (locale ?? defaultLocale).split('-')[0]
  return rtlLocales.has(code) ? 'rtl' : 'ltr'
}
/**
 * Locales a user can select (language switcher) and the proxy can detect.
 * Only locales with a catalog below: a locale without one would show English
 * text, and an RTL one (ar) would also flip the layout. Add a locale here once
 * its dictionary ships; RTL ones only once the layout has been checked RTL.
 */
export const supportedLocales = ['en', 'vi'] as const
export type SupportedLocale = (typeof supportedLocales)[number]
export const defaultLocale: SupportedLocale = 'en'

export function isSupportedLocale(value: unknown): value is SupportedLocale {
  return typeof value === 'string' && (supportedLocales as readonly string[]).includes(value)
}

// ============================================================
// Translation layer (lightweight, dependency-free)
// ============================================================

export type Dictionary = Record<string, string>
export type TranslateVars = Record<string, string | number>

// Catalogs are loaded on demand, one locale per page: each locale's catalog
// is its own chunk (./i18n/dictionaries/en.ts, vi.ts), so a page downloads
// only the language it renders instead of every catalog (about 400 KB
// gzipped each). The locale is fixed for the life of a page (switching
// reloads, see language-switcher.tsx), so one catalog is enough.
// I18nProvider waits for it before rendering; plain helpers read what is
// loaded through getDictionary().
const loaders: Record<SupportedLocale, () => Promise<Dictionary>> = {
  en: () => import('./i18n/dictionaries/en').then((m) => m.en),
  vi: () => import('./i18n/dictionaries/vi').then((m) => m.vi),
}
const loaded: Partial<Record<SupportedLocale, Dictionary>> = {}
const pending = new Map<SupportedLocale, Promise<Dictionary>>()
const EMPTY: Dictionary = Object.freeze({}) as Dictionary

/** The supported locale for a tag ("vi-VN" -> "vi"), English when unknown. */
export function catalogLocale(locale?: string): SupportedLocale {
  const code = (locale ?? defaultLocale).split('-')[0]
  return isSupportedLocale(code) ? code : defaultLocale
}

/**
 * Loads a locale's catalog once (same promise for every caller, so React's
 * `use()` can wait on it). A failed chunk load is forgotten so the next call
 * retries.
 */
export function loadDictionary(locale?: string): Promise<Dictionary> {
  const code = catalogLocale(locale)
  let p = pending.get(code)
  if (!p) {
    p = loaders[code]().then((dict) => {
      loaded[code] = dict
      return dict
    })
    p.catch(() => pending.delete(code))
    pending.set(code, p)
  }
  return p
}

/** Makes a catalog available synchronously (tests, and callers that already hold one). */
export function registerDictionary(locale: string, dict: Dictionary): void {
  const code = catalogLocale(locale)
  loaded[code] = dict
  pending.set(code, Promise.resolve(dict))
}

/** The catalog for a locale if it is loaded, else null. */
export function loadedDictionary(locale?: string): Dictionary | null {
  return loaded[catalogLocale(locale)] ?? null
}

/**
 * Returns the message catalog for a locale: the locale's own when loaded,
 * else English, else whichever catalog the page loaded, else an empty one
 * (keys then resolve to their fallback text).
 */
export function getDictionary(locale?: string): Dictionary {
  return loaded[catalogLocale(locale)] ?? loaded[defaultLocale] ?? Object.values(loaded)[0] ?? EMPTY
}

/**
 * Resolves a message key against a catalog with `{var}` interpolation.
 * Resolution order: catalog[key] → English catalog[key] (when loaded) →
 * `fallback` → `key`. en and vi hold the same keys (dictionaries.test.ts), so a
 * page that loaded only vi still finds every key. The English fallback means a key missing only from a non-English catalog
 * still renders sensible text, so translation can be filled in incrementally.
 */
export function translate(
  dict: Dictionary,
  key: string,
  fallback?: string,
  vars?: TranslateVars
): string {
  let str = dict[key] ?? loaded.en?.[key] ?? fallback ?? key
  // The brand variables default to the OpenCTEM brand; I18nProvider passes
  // the instance brand (src/context/i18n-provider.tsx).
  const all = { product: DEFAULT_BRAND.name, productShort: DEFAULT_BRAND.shortName, ...vars }
  str = applyPlurals(str, all)
  for (const [name, value] of Object.entries(all)) {
    str = str.split(`{${name}}`).join(String(value))
  }
  return str
}

// ICU plural blocks: `{n, plural, one {# finding} other {# findings}}`.
// Branches are `=N` or a CLDR category (zero one two few many other); `#` is
// the number. Branch text holds no braces. Vietnamese has only `other`, so one
// rule set (English) selects correctly for both shipped catalogs.
const PLURAL_BLOCK = /\{(\w+),\s*plural,((?:\s*(?:=\d+|\w+)\s*\{[^{}]*\})+)\s*\}/g
const PLURAL_BRANCH = /(=\d+|\w+)\s*\{([^{}]*)\}/g
const pluralRules = new Intl.PluralRules('en')

function applyPlurals(str: string, vars: TranslateVars): string {
  if (!str.includes('plural,')) return str
  return str.replace(PLURAL_BLOCK, (whole, name: string, branches: string) => {
    const raw = vars[name]
    const n = Number(raw)
    if (raw === undefined || Number.isNaN(n)) return whole
    const byKey = new Map<string, string>()
    for (const m of branches.matchAll(PLURAL_BRANCH)) byKey.set(m[1], m[2])
    const text = byKey.get(`=${n}`) ?? byKey.get(pluralRules.select(n)) ?? byKey.get('other') ?? ''
    return text.split('#').join(n.toLocaleString('en-US'))
  })
}
