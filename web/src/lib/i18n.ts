import { en, vi } from './i18n/dictionaries'
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

// Static catalogs. `ar` intentionally falls back to English until translated —
// its RTL direction is already handled by getDirFromLocale.
const enDict: Dictionary = en
const dictionaries: Record<string, Dictionary> = { en: enDict, vi }

/** Returns the message catalog for a locale, falling back to English. */
export function getDictionary(locale?: string): Dictionary {
  const code = (locale ?? defaultLocale).split('-')[0]
  return dictionaries[code] ?? dictionaries[defaultLocale] ?? enDict
}

/**
 * Resolves a message key against a catalog with `{var}` interpolation.
 * Resolution order: catalog[key] → English catalog[key] → `fallback` → `key`.
 * The English fallback means a key missing only from a non-English catalog
 * still renders sensible text, so translation can be filled in incrementally.
 */
export function translate(
  dict: Dictionary,
  key: string,
  fallback?: string,
  vars?: TranslateVars
): string {
  let str = dict[key] ?? enDict[key] ?? fallback ?? key
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
