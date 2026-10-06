/**
 * Freeze window schedules: how they read, and the wall-clock conversion the
 * form needs for one-off windows (entered in the window's time zone, sent as
 * instants). Whether a window is active is decided by the server only.
 */
import type { FreezeWindow } from '../types'

/** ISO weekdays, 1 Monday ... 7 Sunday. */
export const WEEKDAYS: { iso: number; short: string; long: string }[] = [
  { iso: 1, short: 'Mon', long: 'Monday' },
  { iso: 2, short: 'Tue', long: 'Tuesday' },
  { iso: 3, short: 'Wed', long: 'Wednesday' },
  { iso: 4, short: 'Thu', long: 'Thursday' },
  { iso: 5, short: 'Fri', long: 'Friday' },
  { iso: 6, short: 'Sat', long: 'Saturday' },
  { iso: 7, short: 'Sun', long: 'Sunday' },
]

/** The browser's IANA time zone, or UTC. */
export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

/** IANA time zones the browser knows, with the given ones first if missing. */
export function timeZoneOptions(...ensure: string[]): string[] {
  let zones: string[] = []
  try {
    const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] }
    zones = intl.supportedValuesOf?.('timeZone') ?? []
  } catch {
    zones = []
  }
  const out = new Set<string>(['UTC', ...zones])
  for (const z of ensure) if (z) out.add(z)
  return [...out]
}

/** Is the "HH:MM" end not after the start (the window ends the next day)? */
export function endsNextDay(start: string, end: string): boolean {
  return end <= start
}

/** "Mon, Wed, Fri" or "Every day" / "Weekdays" / "Weekends". */
export function describeDays(days: number[] | undefined): string {
  const set = [...new Set(days ?? [])].sort((a, b) => a - b)
  if (set.length === 7) return 'Every day'
  if (set.join(',') === '1,2,3,4,5') return 'Weekdays'
  if (set.join(',') === '6,7') return 'Weekends'
  return set.map((d) => WEEKDAYS[d - 1]?.short ?? String(d)).join(', ')
}

function partsIn(date: Date, timeZone: string) {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
  const p: Record<string, string> = {}
  for (const part of fmt.formatToParts(date)) p[part.type] = part.value
  return {
    year: Number(p.year),
    month: Number(p.month),
    day: Number(p.day),
    hour: Number(p.hour),
    minute: Number(p.minute),
    second: Number(p.second),
  }
}

/** The offset of timeZone from UTC at the instant, in milliseconds. */
function offsetAt(ms: number, timeZone: string): number {
  const p = partsIn(new Date(ms), timeZone)
  const asUTC = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second)
  return asUTC - Math.floor(ms / 1000) * 1000
}

/**
 * The instant at which the wall clock in timeZone reads local
 * ("YYYY-MM-DDTHH:MM"). A time skipped by a DST change resolves to the
 * instant after the jump. Returns null for malformed input.
 */
export function zonedLocalToUtc(local: string, timeZone: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(local)
  if (!m) return null
  const wall = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]))
  // The offsets in force a little before and after: the same except on the
  // day of a DST change. A candidate is right when the wall clock at it
  // reads local again.
  const day = 14 * 60 * 60 * 1000
  const candidates = [
    wall - offsetAt(wall - day, timeZone),
    wall - offsetAt(wall + day, timeZone),
  ].sort((a, b) => a - b)
  const exact = candidates.filter(
    (c) => utcToZonedLocal(new Date(c).toISOString(), timeZone) === local
  )
  // A repeated time (clocks go back) takes its first pass; a skipped time
  // (clocks go forward) the instant after the jump.
  return new Date(exact.length > 0 ? exact[0] : candidates[candidates.length - 1])
}

/** The wall clock in timeZone at the instant, as "YYYY-MM-DDTHH:MM". */
export function utcToZonedLocal(iso: string, timeZone: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const p = partsIn(d, timeZone)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${p.year}-${pad(p.month)}-${pad(p.day)}T${pad(p.hour)}:${pad(p.minute)}`
}

/** An instant shown in a time zone: "Oct 5, 2026, 22:00". */
export function formatInZone(iso: string | undefined, timeZone = 'UTC'): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(d)
  } catch {
    return d.toISOString()
  }
}

/** One line for a window's schedule, in its own time zone. */
export function describeSchedule(w: FreezeWindow): string {
  if (w.recurrence === 'weekly') {
    const start = w.start_time ?? ''
    const end = w.end_time ?? ''
    const next = start && end && endsNextDay(start, end) ? ' (next day)' : ''
    return `${describeDays(w.days)} ${start}–${end}${next} ${w.timezone}`
  }
  return `${formatInZone(w.starts_at, w.timezone)} – ${formatInZone(w.ends_at, w.timezone)} ${w.timezone}`
}

/** The windows of a list that are active now. */
export function activeWindows(ws: FreezeWindow[] | undefined): FreezeWindow[] {
  return (ws ?? []).filter((w) => w.active)
}
