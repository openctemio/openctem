/**
 * Wall-clock time in an IANA timezone <-> an instant, for the one-off run of
 * a scan ("Mon 12 Oct, 22:00 in Asia/Ho_Chi_Minh"). Only Intl: the browser's
 * own zone database, no second copy of the rules.
 */

/** The viewer's IANA timezone, or UTC when the browser does not say. */
export function viewerTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

interface WallTime {
  /** YYYY-MM-DD */
  date: string
  /** HH:MM (24h) */
  time: string
}

function partsIn(instant: Date, timeZone: string) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(instant)
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? 0)
  return {
    year: get('year'),
    month: get('month'),
    day: get('day'),
    hour: get('hour') % 24,
    minute: get('minute'),
    second: get('second'),
  }
}

/** Offset of timeZone from UTC at instant, in milliseconds. */
function offsetAt(instant: Date, timeZone: string): number {
  const p = partsIn(instant, timeZone)
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second)
  return asUtc - Math.floor(instant.getTime() / 1000) * 1000
}

/**
 * The instant at which the wall clock in timeZone reads date + time, or null
 * when the input is not a valid date/time or zone. A time skipped by a DST
 * change resolves to the instant just after the gap.
 */
export function zonedWallTimeToInstant({ date, time }: WallTime, timeZone: string): Date | null {
  const d = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date)
  const t = /^(\d{2}):(\d{2})$/.exec(time)
  if (!d || !t) return null
  const wall = Date.UTC(+d[1], +d[2] - 1, +d[3], +t[1], +t[2])
  if (Number.isNaN(wall)) return null
  try {
    // Two passes settle the offset around a DST change.
    let guess = wall - offsetAt(new Date(wall), timeZone)
    guess = wall - offsetAt(new Date(guess), timeZone)
    return new Date(guess)
  } catch {
    return null
  }
}

/** The wall-clock date and time of instant (ISO string) in timeZone. */
export function instantToZonedWallTime(iso: string, timeZone: string): WallTime | null {
  const instant = new Date(iso)
  if (Number.isNaN(instant.getTime())) return null
  try {
    const p = partsIn(instant, timeZone)
    const pad = (n: number) => n.toString().padStart(2, '0')
    return {
      date: `${p.year}-${pad(p.month)}-${pad(p.day)}`,
      time: `${pad(p.hour)}:${pad(p.minute)}`,
    }
  } catch {
    return null
  }
}

/** IANA zones the browser knows, with `current` included; UTC first. */
export function timeZoneOptions(current?: string): string[] {
  let zones: string[] = []
  try {
    const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
    zones = intl.supportedValuesOf?.('timeZone') ?? []
  } catch {
    zones = []
  }
  const set = new Set(['UTC', ...zones])
  if (current) set.add(current)
  return [...set]
}
