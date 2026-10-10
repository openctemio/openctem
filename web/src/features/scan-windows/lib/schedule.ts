/**
 * Scan window schedules: how they read, and the wall-clock conversion the
 * form needs for dated windows (entered in the policy's time zone, sent as
 * instants). Whether a window is open is decided by the server only.
 */
import type { ScanWindowOneOff, ScanWindowPolicy, ScanWindowSlot } from '../types'

/** The `t()` of useTranslation; English fallbacks when omitted. */
export type Translate = (
  key: string,
  fallback?: string,
  vars?: Record<string, string | number>
) => string

/** English passthrough for code outside React (and tests). */
export const englishT: Translate = (_key, fallback = '', vars) => {
  let s = fallback
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v))
  return s
}

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

export function dayShort(iso: number, t: Translate = englishT): string {
  const d = WEEKDAYS[iso - 1]
  return d ? t(`scanWindows.day.short.${iso}`, d.short) : String(iso)
}

export function dayLong(iso: number, t: Translate = englishT): string {
  const d = WEEKDAYS[iso - 1]
  return d ? t(`scanWindows.day.long.${iso}`, d.long) : String(iso)
}

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

export const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/

/** Is the "HH:MM" end not after the start (the window ends the next day)? */
export function endsNextDay(start: string, end: string): boolean {
  return end <= start
}

/** "Mon, Wed, Fri" or "Every day" / "Weekdays" / "Weekends". */
export function describeDays(days: number[] | undefined, t: Translate = englishT): string {
  const set = [...new Set(days ?? [])].sort((a, b) => a - b)
  if (set.length === 7) return t('scanWindows.days.every', 'Every day')
  if (set.join(',') === '1,2,3,4,5') return t('scanWindows.days.weekdays', 'Weekdays')
  if (set.join(',') === '6,7') return t('scanWindows.days.weekends', 'Weekends')
  return set.map((d) => dayShort(d, t)).join(', ')
}

/** "Weekdays 22:00–06:00 (next day)"; equal times are 24 hours. */
export function describeSlot(s: ScanWindowSlot, t: Translate = englishT): string {
  const start = s.start ?? ''
  const end = s.end ?? ''
  const days = describeDays(s.days, t)
  if (start && start === end)
    return t('scanWindows.slot.allDay', '{days}, 24 hours from {start}', { days, start })
  const next =
    start && end && endsNextDay(start, end) ? ` ${t('scanWindows.slot.nextDay', '(next day)')}` : ''
  return `${days} ${start}–${end}${next}`
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
  const day = 14 * 60 * 60 * 1000
  let candidates: number[]
  try {
    candidates = [
      wall - offsetAt(wall - day, timeZone),
      wall - offsetAt(wall + day, timeZone),
    ].sort((a, b) => a - b)
  } catch {
    return null
  }
  // A repeated time (clocks go back) takes its first pass; a skipped time
  // (clocks go forward) the instant after the jump.
  const exact = candidates.filter(
    (c) => utcToZonedLocal(new Date(c).toISOString(), timeZone) === local
  )
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

/** An instant in a time zone ("Oct 5, 2026, 22:00"); the viewer's zone by default. */
export function formatInZone(iso: string | undefined, timeZone?: string, locale = 'en-US'): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  try {
    return new Intl.DateTimeFormat(locale, {
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

/** A dated window in the policy's zone. */
export function describeOneOff(o: ScanWindowOneOff, timeZone: string): string {
  return `${formatInZone(o.starts_at, timeZone)} – ${formatInZone(o.ends_at, timeZone)}`
}

/** One line per weekly slot and dated window, in the policy's own zone. */
export function describeSchedule(
  p: Pick<ScanWindowPolicy, 'slots' | 'one_offs' | 'timezone'>,
  t: Translate = englishT
): string[] {
  const tz = p.timezone || 'UTC'
  const lines = (p.slots ?? []).map((s) => describeSlot(s, t))
  for (const o of p.one_offs ?? []) lines.push(describeOneOff(o, tz))
  if (lines.length === 0) return [t('scanWindows.schedule.none', 'No windows')]
  return lines
}

/**
 * The policy's state now, from the server's open_now / next_change_at:
 * an allow window is open or opens at; a blackout blocks now or starts at.
 */
export function policyState(
  p: Pick<ScanWindowPolicy, 'kind' | 'open_now' | 'next_change_at' | 'enabled'>,
  t: Translate = englishT
): { tone: 'open' | 'blocked' | 'idle'; label: string } {
  if (!p.enabled) return { tone: 'idle', label: t('scanWindows.state.disabled', 'Disabled') }
  const at = formatInZone(p.next_change_at)
  if (p.kind === 'blackout') {
    // open_now false: the blackout is active.
    if (!p.open_now) {
      return {
        tone: 'blocked',
        label: at
          ? t('scanWindows.state.blocksUntil', 'Blocks now, until {at}', { at })
          : t('scanWindows.state.blocksNow', 'Blocks now'),
      }
    }
    return {
      tone: 'idle',
      label: at
        ? t('scanWindows.state.blackoutStarts', 'Starts {at}', { at })
        : t('scanWindows.state.blackoutNever', 'Not active'),
    }
  }
  if (p.open_now) {
    return {
      tone: 'open',
      label: at
        ? t('scanWindows.state.openUntil', 'Open now, until {at}', { at })
        : t('scanWindows.state.openNow', 'Open now'),
    }
  }
  return {
    tone: 'blocked',
    label: at
      ? t('scanWindows.state.opensAt', 'Closed, opens {at}', { at })
      : t('scanWindows.state.neverOpens', 'Closed, never opens'),
  }
}

/** The tier a policy governs, in words. */
export function tierLabel(tier: number | undefined, t: Translate = englishT): string {
  switch (tier) {
    case 0:
      return t('scanWindows.tier.0', 'Every tool')
    case 2:
      return t('scanWindows.tier.2', 'Intrusive tools only')
    default:
      return t('scanWindows.tier.1', 'Active and intrusive tools')
  }
}
