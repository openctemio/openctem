import { format, formatDistanceToNow } from 'date-fns'

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

/** Relative time ("3 days ago"), safe against missing/invalid input. */
export function formatRelative(
  value: string | number | Date | null | undefined,
  fallback = '—'
): string {
  const d = toDate(value)
  if (!d) return fallback
  try {
    return formatDistanceToNow(d, { addSuffix: true })
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
