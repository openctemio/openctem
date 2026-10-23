// A calendar date with no time of day ("2026-10-01") is the same day everywhere.
// `new Date("2026-10-01")` reads it as UTC midnight, which renders as the day
// before in timezones west of UTC. The API also returns DATE columns as
// midnight-UTC timestamps ("2026-10-01T00:00:00Z"), which mean the same thing.
const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})(?:T00:00:00(?:\.0+)?Z)?$/

/** Parse a date-only value as a local calendar date; anything else as `new Date(s)`. */
export function parseDateOnly(value: string): Date {
  const m = DATE_ONLY.exec(value)
  if (!m) return new Date(value)
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
}

/** Locale date of a date-only value ('' when missing or unparseable). */
export function formatDateOnly(value: string | null | undefined, locale?: string): string {
  if (!value) return ''
  const d = parseDateOnly(value)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(locale)
}
