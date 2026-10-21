/**
 * Number, percentage, duration and time formatting for dashboard figures.
 * Everything is locale-aware (Intl), so "1,234" in English is "1.234" in
 * Vietnamese, and units are written by the platform's own catalogs.
 *
 * - counts: grouped; compact notation from 10 000 up ("12K");
 * - percentages: whole numbers, one decimal below 10 % ("7.5%", "86%");
 * - durations: the largest sensible unit ("45 min", "17 h", "5.5 d");
 * - times: relative ("5 minutes ago"), with the absolute time for hover.
 */

/** Values from this size up are written in compact notation. */
export const COMPACT_FROM = 10_000

function nf(locale: string, opts: Intl.NumberFormatOptions): Intl.NumberFormat {
  try {
    return new Intl.NumberFormat(locale, opts)
  } catch {
    return new Intl.NumberFormat('en', opts)
  }
}

/** A count or plain number. Null and non-finite values are "—". */
export function formatCount(value: number | null | undefined, locale = 'en'): string {
  if (value == null || !Number.isFinite(value)) return '—'
  if (Math.abs(value) >= COMPACT_FROM) {
    return nf(locale, { notation: 'compact', maximumFractionDigits: 1 }).format(value)
  }
  const fraction = Number.isInteger(value) ? 0 : 1
  return nf(locale, { maximumFractionDigits: fraction }).format(value)
}

/** A percentage given as 0-100. One decimal below 10 %, whole numbers above. */
export function formatPercent(pct: number | null | undefined, locale = 'en'): string {
  if (pct == null || !Number.isFinite(pct)) return '—'
  const digits = Math.abs(pct) < 10 && pct !== 0 ? 1 : 0
  return nf(locale, {
    style: 'percent',
    minimumFractionDigits: 0,
    maximumFractionDigits: digits,
  }).format(pct / 100)
}

export type DurationUnit = 'minute' | 'hour' | 'day'

/** The unit a duration in hours is best written in. */
export function durationUnit(hours: number): DurationUnit {
  const h = Math.abs(hours)
  if (h < 1) return 'minute'
  if (h < 48) return 'hour'
  return 'day'
}

/** A duration given in hours, in its largest sensible unit. */
export function formatDuration(hours: number | null | undefined, locale = 'en'): string {
  if (hours == null || !Number.isFinite(hours)) return '—'
  const unit = durationUnit(hours)
  const value = unit === 'minute' ? hours * 60 : unit === 'day' ? hours / 24 : hours
  const digits = unit === 'minute' ? 0 : Math.abs(value) < 10 ? 1 : 0
  return nf(locale, {
    style: 'unit',
    unit,
    unitDisplay: 'short',
    maximumFractionDigits: digits,
  }).format(value)
}

export type MetricUnit = 'count' | 'percent' | 'hours'

/** Formats a value by its unit. */
export function formatMetric(
  value: number | null | undefined,
  unit: MetricUnit,
  locale = 'en'
): string {
  if (unit === 'percent') return formatPercent(value, locale)
  if (unit === 'hours') return formatDuration(value, locale)
  return formatCount(value, locale)
}

/**
 * A change between two values, always signed and in the value's unit
 * ("+12", "−3 pts", "−1.2 d"). Percent deltas are in percentage points.
 */
export function formatDelta(delta: number, unit: MetricUnit, locale = 'en'): string {
  if (!Number.isFinite(delta)) return '—'
  const abs = Math.abs(delta)
  let body: string
  if (unit === 'percent') {
    body = nf(locale, { maximumFractionDigits: abs < 10 && abs !== 0 ? 1 : 0 }).format(abs)
  } else if (unit === 'hours') {
    body = formatDuration(abs, locale)
  } else {
    body = formatCount(abs, locale)
  }
  if (delta === 0) return body
  return (delta > 0 ? '+' : '−') + body
}

const RELATIVE_STEPS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['second', 60],
  ['minute', 60],
  ['hour', 24],
  ['day', 30],
  ['month', 12],
  ['year', Number.POSITIVE_INFINITY],
]

/** "5 minutes ago" / "in 2 hours", in the locale. Invalid dates are "—". */
export function formatRelativeTime(
  date: string | Date | null | undefined,
  locale = 'en',
  now: Date = new Date()
): string {
  const d = date == null ? null : typeof date === 'string' ? new Date(date) : date
  if (!d || Number.isNaN(d.getTime())) return '—'
  let value = (d.getTime() - now.getTime()) / 1000
  let rtf: Intl.RelativeTimeFormat
  try {
    rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  } catch {
    rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  }
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(value) < size) return rtf.format(Math.round(value), unit)
    value /= size
  }
  return rtf.format(Math.round(value), 'year')
}

/** The absolute date and time, for hover text next to a relative time. */
export function formatAbsoluteTime(date: string | Date | null | undefined, locale = 'en'): string {
  const d = date == null ? null : typeof date === 'string' ? new Date(date) : date
  if (!d || Number.isNaN(d.getTime())) return ''
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(d)
  } catch {
    return d.toISOString()
  }
}

/** Age in milliseconds of an "as of" time; null when unknown. */
export function ageMs(
  asOf: string | Date | null | undefined,
  now: Date = new Date()
): number | null {
  const d = asOf == null ? null : typeof asOf === 'string' ? new Date(asOf) : asOf
  if (!d || Number.isNaN(d.getTime())) return null
  return now.getTime() - d.getTime()
}

/** A bucket start (ISO date) as a short label: "Oct 5" for days and weeks, "Oct 2026" for months. */
export function formatBucket(
  value: string,
  bucket: 'day' | 'week' | 'month',
  locale = 'en'
): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  const opts: Intl.DateTimeFormatOptions =
    bucket === 'month'
      ? { month: 'short', year: 'numeric', timeZone: 'UTC' }
      : { month: 'short', day: 'numeric', timeZone: 'UTC' }
  try {
    return new Intl.DateTimeFormat(locale, opts).format(d)
  } catch {
    return new Intl.DateTimeFormat('en', opts).format(d)
  }
}
