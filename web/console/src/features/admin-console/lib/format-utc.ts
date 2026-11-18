/**
 * A record's own time to the second in UTC: "2026-11-18 03:54:09 UTC". A fixed
 * shape (not the viewer's locale or zone), so it reads the same everywhere and
 * can be pasted into a ticket. Empty for a missing or invalid time.
 */
export function formatUtcTime(value: string | Date | null | undefined): string {
  const d = value == null ? null : typeof value === 'string' ? new Date(value) : value
  if (!d || Number.isNaN(d.getTime())) return ''
  return `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`
}
