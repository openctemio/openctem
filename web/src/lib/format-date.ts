import { format, formatDistanceToNow } from 'date-fns'
import { enUS, vi } from 'date-fns/locale'

const DATE_FNS_LOCALES = { en: enUS, vi } as const

function dateFnsLocale(locale?: string) {
  const base = (locale ?? 'en').toLowerCase().split('-')[0] as keyof typeof DATE_FNS_LOCALES
  return DATE_FNS_LOCALES[base] ?? enUS
}

/**
 * Safe date helpers.
 *
 * date-fns `format` / `formatDistanceToNow` THROW `RangeError: Invalid time
 * value` when given an Invalid Date (e.g. `new Date(undefined)` from a missing
 * API timestamp). A bare `formatDistanceToNow(new Date(maybeMissing))` therefore
 * crashes the whole subtree. These wrappers coerce the input and return a
 * fallback string instead of throwing.
 */

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null
  const d = value instanceof Date ? value : new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

/**
 * Relative time ("3 days ago"), safe against missing/invalid input. Pass the
 * app locale (`useTranslation().locale`) to localize it; English by default.
 */
export function formatRelative(
  value: string | number | Date | null | undefined,
  fallback = '—',
  locale?: string
): string {
  const d = toDate(value)
  if (!d) return fallback
  try {
    return formatDistanceToNow(d, { addSuffix: true, locale: dateFnsLocale(locale) })
  } catch {
    return fallback
  }
}

/**
 * A date (or, with `time`, a date and time) in the console language, safe
 * against missing/invalid input. `locale` is the i18n locale from
 * `useTranslation()`; the browser's own language is not used.
 */
export function formatLocalized(
  value: string | number | Date | null | undefined,
  locale: string,
  opts: { time?: boolean; fallback?: string } = {}
): string {
  const d = toDate(value)
  if (!d) return opts.fallback ?? '—'
  try {
    return d.toLocaleString(locale, {
      dateStyle: 'medium',
      ...(opts.time ? { timeStyle: 'short' } : {}),
    })
  } catch {
    return d.toISOString()
  }
}

/** Absolute date format, safe against missing/invalid input. Default: "PP". */
export function formatDateSafe(
  value: string | number | Date | null | undefined,
  fmt = 'PP',
  fallback = '—'
): string {
  const d = toDate(value)
  if (!d) return fallback
  try {
    return format(d, fmt)
  } catch {
    return fallback
  }
}
