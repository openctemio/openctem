/**
 * The policy form: its state, its validation (the API's own limits, so most
 * mistakes show before saving; the API checks everything again) and the
 * request it sends. Dated windows are edited as wall-clock times in the
 * policy's time zone and sent as instants.
 */
import type {
  ScanWindowKind,
  ScanWindowPolicy,
  ScanWindowPolicyRequest,
  ScanWindowSelector,
  ScanWindowTier,
} from '../types'
import { cleanSelector } from './selector'
import { englishT, HHMM, utcToZonedLocal, zonedLocalToUtc, type Translate } from './schedule'

export const MAX_NAME_LENGTH = 100
export const MAX_DESCRIPTION_LENGTH = 1000
export const MAX_SLOTS = 14
export const MAX_ONE_OFFS = 20
export const MAX_GRACE_MINUTES = 240
export const DEFAULT_GRACE_MINUTES = 15
export const MAX_RATE_LIMIT_RPS = 100000
export const MAX_CONCURRENT = 1000
const MAX_ONE_OFF_MS = 31 * 24 * 60 * 60 * 1000

export interface SlotDraft {
  days: number[]
  start: string
  end: string
}

/** A dated window as wall-clock "YYYY-MM-DDTHH:MM" in the policy's zone. */
export interface OneOffDraft {
  startsLocal: string
  endsLocal: string
}

export interface PolicyFormState {
  name: string
  description: string
  enabled: boolean
  kind: ScanWindowKind
  minTier: ScanWindowTier
  timezone: string
  slots: SlotDraft[]
  oneOffs: OneOffDraft[]
  selector: ScanWindowSelector
  /** Kept as text so an empty field means "none". */
  graceMinutes: string
  rateLimitRps: string
  maxConcurrent: string
}

export function emptyPolicyForm(timezone: string): PolicyFormState {
  return {
    name: '',
    description: '',
    enabled: true,
    kind: 'allow',
    minTier: 1,
    timezone,
    slots: [{ days: [1, 2, 3, 4, 5], start: '09:00', end: '17:00' }],
    oneOffs: [],
    selector: {},
    graceMinutes: String(DEFAULT_GRACE_MINUTES),
    rateLimitRps: '',
    maxConcurrent: '',
  }
}

export function policyToForm(p: ScanWindowPolicy): PolicyFormState {
  const tz = p.timezone || 'UTC'
  return {
    name: p.name ?? '',
    description: p.description ?? '',
    enabled: p.enabled ?? true,
    kind: p.kind === 'blackout' ? 'blackout' : 'allow',
    minTier: (p.min_tier === 0 || p.min_tier === 2 ? p.min_tier : 1) as ScanWindowTier,
    timezone: tz,
    slots: (p.slots ?? []).map((s) => ({
      days: [...(s.days ?? [])],
      start: s.start ?? '',
      end: s.end ?? '',
    })),
    oneOffs: (p.one_offs ?? []).map((o) => ({
      startsLocal: o.starts_at ? utcToZonedLocal(o.starts_at, tz) : '',
      endsLocal: o.ends_at ? utcToZonedLocal(o.ends_at, tz) : '',
    })),
    selector: { ...(p.selector ?? {}) },
    graceMinutes: String(p.grace_minutes ?? DEFAULT_GRACE_MINUTES),
    rateLimitRps: p.rate_limit_rps ? String(p.rate_limit_rps) : '',
    maxConcurrent: p.max_concurrent ? String(p.max_concurrent) : '',
  }
}

function intIn(v: string, min: number, max: number): boolean {
  if (!/^\d+$/.test(v.trim())) return false
  const n = Number(v)
  return n >= min && n <= max
}

/** A dated window that has already ended (kept, but it never opens again). */
export function oneOffEnded(o: OneOffDraft, timezone: string, now: Date = new Date()): boolean {
  const end = zonedLocalToUtc(o.endsLocal, timezone)
  return !!end && end.getTime() <= now.getTime()
}

/** The form's errors, keyed by field ("name", "slots.0", "oneOffs.1", ...). */
export function policyFormErrors(
  f: PolicyFormState,
  t: Translate = englishT
): Record<string, string> {
  const e: Record<string, string> = {}
  const name = f.name.trim()
  if (!name) e.name = t('scanWindows.form.err.nameRequired', 'Name is required.')
  else if (name.length > MAX_NAME_LENGTH)
    e.name = t('scanWindows.form.err.nameLong', 'Name must be at most {n} characters.', {
      n: MAX_NAME_LENGTH,
    })
  if (f.description.length > MAX_DESCRIPTION_LENGTH)
    e.description = t(
      'scanWindows.form.err.descriptionLong',
      'Description must be at most {n} characters.',
      {
        n: MAX_DESCRIPTION_LENGTH,
      }
    )
  if (!f.timezone) e.timezone = t('scanWindows.form.err.timezone', 'Pick a time zone.')
  if (f.slots.length + f.oneOffs.length === 0)
    e.windows = t(
      'scanWindows.form.err.noWindows',
      'Add at least one weekly window or one dated window.'
    )
  if (f.slots.length > MAX_SLOTS)
    e.windows = t('scanWindows.form.err.tooManySlots', 'At most {n} weekly windows.', {
      n: MAX_SLOTS,
    })
  if (f.oneOffs.length > MAX_ONE_OFFS)
    e.windows = t('scanWindows.form.err.tooManyOneOffs', 'At most {n} dated windows.', {
      n: MAX_ONE_OFFS,
    })
  f.slots.forEach((s, i) => {
    if (s.days.length === 0)
      e[`slots.${i}`] = t('scanWindows.form.err.days', 'Pick at least one day.')
    else if (!HHMM.test(s.start) || !HHMM.test(s.end))
      e[`slots.${i}`] = t('scanWindows.form.err.times', 'Enter a start and an end time.')
  })
  f.oneOffs.forEach((o, i) => {
    const start = zonedLocalToUtc(o.startsLocal, f.timezone)
    const end = zonedLocalToUtc(o.endsLocal, f.timezone)
    if (!start || !end)
      e[`oneOffs.${i}`] = t('scanWindows.form.err.dates', 'Enter when the window starts and ends.')
    else if (end.getTime() <= start.getTime())
      e[`oneOffs.${i}`] = t(
        'scanWindows.form.err.endAfterStart',
        'The end must be after the start.'
      )
    else if (end.getTime() - start.getTime() > MAX_ONE_OFF_MS)
      e[`oneOffs.${i}`] = t(
        'scanWindows.form.err.oneOffLong',
        'A dated window lasts at most 31 days.'
      )
  })
  if (!intIn(f.graceMinutes, 0, MAX_GRACE_MINUTES))
    e.graceMinutes = t('scanWindows.form.err.grace', 'Grace is 0 to {n} minutes.', {
      n: MAX_GRACE_MINUTES,
    })
  if (f.kind === 'allow') {
    if (f.rateLimitRps.trim() && !intIn(f.rateLimitRps, 1, MAX_RATE_LIMIT_RPS))
      e.rateLimitRps = t(
        'scanWindows.form.err.rate',
        'Rate limit is 1 to {n} requests per second, or empty.',
        {
          n: MAX_RATE_LIMIT_RPS,
        }
      )
    if (f.maxConcurrent.trim() && !intIn(f.maxConcurrent, 1, MAX_CONCURRENT))
      e.maxConcurrent = t('scanWindows.form.err.concurrent', 'Concurrency is 1 to {n}, or empty.', {
        n: MAX_CONCURRENT,
      })
  }
  return e
}

/**
 * The request for the form. Every field is sent (a PATCH replaces the
 * schedule and selector as a whole). Caps are 0 for a blackout, which has
 * none. Dated windows that do not parse are dropped (the form refuses to
 * save while one is invalid).
 */
export function formToRequest(f: PolicyFormState): ScanWindowPolicyRequest {
  const allow = f.kind === 'allow'
  const oneOffs = f.oneOffs.flatMap((o) => {
    const s = zonedLocalToUtc(o.startsLocal, f.timezone)
    const e = zonedLocalToUtc(o.endsLocal, f.timezone)
    return s && e ? [{ starts_at: s.toISOString(), ends_at: e.toISOString() }] : []
  })
  return {
    name: f.name.trim(),
    description: f.description,
    enabled: f.enabled,
    kind: f.kind,
    min_tier: f.minTier,
    timezone: f.timezone,
    slots: f.slots.map((s) => ({
      days: [...new Set(s.days)].sort((a, b) => a - b),
      start: s.start,
      end: s.end,
    })),
    one_offs: oneOffs,
    selector: cleanSelector(f.selector),
    grace_minutes: Number(f.graceMinutes) || 0,
    rate_limit_rps: allow && f.rateLimitRps.trim() ? Number(f.rateLimitRps) : 0,
    max_concurrent: allow && f.maxConcurrent.trim() ? Number(f.maxConcurrent) : 0,
  }
}
