/**
 * The reader's language for code that formats outside a React component, and
 * the one place raw Intl/toLocale* formatting lives.
 *
 * I18nProvider sets the locale while it renders (the locale is fixed for the
 * life of a page), so `formatNumber(n)` writes "12,840" for an English reader
 * and "12.840" for a Vietnamese one, and dates read "Nov 18, 2026" or
 * "18 thg 11, 2026", never in the browser's or the server's own language.
 * `__tests__/locale-format-guard.test.ts` fails on a raw `toLocaleString()`,
 * `toLocaleDateString()` or `toLocaleTimeString()` outside the format helpers.
 */

let current = 'en'

/** Called by I18nProvider with the page's locale. */
export function setAppLocale(locale: string): void {
  current = locale || 'en'
}

/** The page's locale ("en" until the provider renders). */
export function appLocale(): string {
  return current
}

type DateInput = string | number | Date | null | undefined

function toDate(value: DateInput): Date | null {
  if (value === null || value === undefined || value === '') return null
  const d = value instanceof Date ? value : new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

function numberFormat(locale: string, opts?: Intl.NumberFormatOptions): Intl.NumberFormat {
  try {
    return new Intl.NumberFormat(locale, opts)
  } catch {
    return new Intl.NumberFormat('en', opts)
  }
}

function dateFormat(locale: string, opts?: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  try {
    return new Intl.DateTimeFormat(locale, opts)
  } catch {
    return new Intl.DateTimeFormat('en', opts)
  }
}

/** A number in the reader's locale, grouped ("12,840" / "12.840"). */
export function formatNumber(
  value: number | bigint | null | undefined,
  opts?: Intl.NumberFormatOptions,
  locale: string = current
): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'number' && !Number.isFinite(value)) return String(value)
  return numberFormat(locale, opts).format(value)
}

/** A calendar date ("Nov 18, 2026" / "18 thg 11, 2026"), or `fallback` when missing. */
export function formatDate(
  value: DateInput,
  opts: Intl.DateTimeFormatOptions = { dateStyle: 'medium' },
  locale: string = current,
  fallback = '—'
): string {
  const d = toDate(value)
  return d ? dateFormat(locale, opts).format(d) : fallback
}

/** A date and time ("Nov 18, 2026, 9:05 AM" / "09:05 18 thg 11, 2026"). */
export function formatDateTime(
  value: DateInput,
  opts: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' },
  locale: string = current,
  fallback = '—'
): string {
  const d = toDate(value)
  return d ? dateFormat(locale, opts).format(d) : fallback
}

/** A time of day ("9:05 AM" / "09:05"). */
export function formatTime(
  value: DateInput,
  opts: Intl.DateTimeFormatOptions = { timeStyle: 'short' },
  locale: string = current,
  fallback = '—'
): string {
  const d = toDate(value)
  return d ? dateFormat(locale, opts).format(d) : fallback
}
