const DAY = /^\d{4}-\d{2}-\d{2}$/

/**
 * A yyyy-mm-dd date input as an RFC 3339 bound in the viewer's time zone:
 * the start of that day, or (end) the start of the next day, so "to" includes
 * the whole day. Anything else is no bound.
 */
export function dayBound(day: string, end: boolean): string | undefined {
  if (!DAY.test(day)) return undefined
  const d = new Date(`${day}T00:00:00`)
  if (Number.isNaN(d.getTime())) return undefined
  if (end) d.setDate(d.getDate() + 1)
  return d.toISOString()
}
