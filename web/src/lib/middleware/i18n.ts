/**
 * Locale detection for the proxy (src/proxy.ts).
 *
 * Order: the user's explicit choice (the `locale` cookie the language switcher
 * writes), then the browser's Accept-Language as a default, then English.
 * Only locales the app ships a catalog for are ever selected (see
 * supportedLocales in src/lib/i18n.ts), so a browser setting cannot switch the
 * page to an untranslated locale or to right-to-left.
 */

import { NextRequest } from 'next/server'
import { defaultLocale, isSupportedLocale, type SupportedLocale } from '@/lib/i18n'

export const LOCALE_COOKIE = 'locale'

/** Longest Accept-Language header we parse; anything longer is not a browser. */
const MAX_ACCEPT_LANGUAGE = 512

/**
 * The best supported locale in an Accept-Language header, by q-value (ties
 * keep header order), matched on the primary subtag (`vi-VN` is `vi`).
 */
export function localeFromAcceptLanguage(
  header: string | null | undefined
): SupportedLocale | undefined {
  if (!header || header.length > MAX_ACCEPT_LANGUAGE) return undefined
  const ranked = header
    .split(',')
    .map((part, index) => {
      const [tag, ...params] = part.trim().split(';')
      const qParam = params.map((p) => p.trim()).find((p) => p.startsWith('q='))
      const q = qParam ? Number(qParam.slice(2)) : 1
      return { lang: tag.trim().split('-')[0].toLowerCase(), q: Number.isFinite(q) ? q : 0, index }
    })
    .filter((entry) => entry.q > 0)
    .sort((a, b) => b.q - a.q || a.index - b.index)
  return ranked.map((entry) => entry.lang).find(isSupportedLocale)
}

/** Cookie first, then Accept-Language, then the default. */
export function negotiateLocale(
  cookieLocale: string | undefined,
  acceptLanguage: string | null | undefined
): SupportedLocale {
  if (isSupportedLocale(cookieLocale)) return cookieLocale
  return localeFromAcceptLanguage(acceptLanguage) ?? defaultLocale
}

export function detectLocale(req: NextRequest): SupportedLocale {
  return negotiateLocale(req.cookies.get(LOCALE_COOKIE)?.value, req.headers.get('accept-language'))
}
