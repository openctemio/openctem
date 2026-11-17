/**
 * The decide-by moment of a queue item: the latest time a pending request can
 * still be decided. Past it, the request is overdue (the server expires it on
 * its own schedule; the list only says so).
 */
export type DecideByState = 'none' | 'due' | 'overdue'

export function decideByState(
  decideBy: string | Date | null | undefined,
  now: Date = new Date()
): DecideByState {
  if (decideBy == null || decideBy === '') return 'none'
  const d = typeof decideBy === 'string' ? new Date(decideBy) : decideBy
  if (Number.isNaN(d.getTime())) return 'none'
  return d.getTime() < now.getTime() ? 'overdue' : 'due'
}

/** "12 Nov" / "12 thg 11"; with the year when it is not the current one. */
export function formatDecideByDate(
  value: string | Date,
  locale = 'en',
  now: Date = new Date()
): string {
  const d = typeof value === 'string' ? new Date(value) : value
  if (Number.isNaN(d.getTime())) return '-'
  const options: Intl.DateTimeFormatOptions =
    d.getFullYear() === now.getFullYear()
      ? { day: 'numeric', month: 'short' }
      : { day: 'numeric', month: 'short', year: 'numeric' }
  try {
    return new Intl.DateTimeFormat(locale, options).format(d)
  } catch {
    return new Intl.DateTimeFormat('en', options).format(d)
  }
}
