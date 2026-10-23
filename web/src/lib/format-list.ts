'use client'

import { useCallback } from 'react'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Join short facts into one plain-text string in the reader's language
 * (research/248): "a, b, c" in English and Vietnamese, through Intl.ListFormat
 * with type 'unit' and style 'short', so no separator glyph is hard-coded.
 *
 * For plain-text places only (a title attribute, a toast, a CSV cell, a
 * notification body). Rendered rows use <MetaLine items={[...]}/>.
 *
 * Empty parts are dropped. Falls back to ", " if the locale is unknown to Intl.
 */
export function formatList(
  parts: ReadonlyArray<string | null | undefined | false>,
  locale: string
): string {
  const items = parts.filter((p): p is string => typeof p === 'string' && p.trim() !== '')
  if (items.length === 0) return ''
  try {
    return new Intl.ListFormat(locale, { type: 'unit', style: 'short' }).format(items)
  } catch {
    return items.join(', ')
  }
}

/** formatList bound to the active locale from the i18n provider. */
export function useFormatList(): (
  parts: ReadonlyArray<string | null | undefined | false>
) => string {
  const { locale } = useTranslation()
  return useCallback((parts) => formatList(parts, locale), [locale])
}
