/**
 * Display helpers shared by the cycle pages and the scoping overview: the date
 * range and the "Day N of M" timeline, in the console locale. Dates are
 * calendar days (no time of day), so they are parsed as local dates.
 */
import type { useTranslation } from '@/context/i18n-provider'
import { formatDateOnly, parseDateOnly } from '@/lib/date-only'

type Translate = ReturnType<typeof useTranslation>['t']

const DAY = 86_400_000

export interface CycleDates {
  status: string
  start_date?: string | null
  end_date?: string | null
}

/** "1/10/2026 to 31/12/2026", or '' when either end is missing. */
export function cycleDateRange(c: CycleDates, t: Translate, locale: string): string {
  if (!c.start_date || !c.end_date) return ''
  return t('scoping.cycle.dateRange', '{start} to {end}', {
    start: formatDateOnly(c.start_date, locale),
    end: formatDateOnly(c.end_date, locale),
  })
}

/** "Day 23 of 90" while running, the date range otherwise, "No dates" without dates. */
export function cycleTimeline(
  c: CycleDates,
  t: Translate,
  locale: string,
  now: number = Date.now()
): { value: string; hint?: string } {
  const range = cycleDateRange(c, t, locale)
  if (!range) return { value: t('scoping.cycle.noDates', 'No dates') }
  if (c.status !== 'active') return { value: range }
  const start = parseDateOnly(c.start_date!).getTime()
  const end = parseDateOnly(c.end_date!).getTime()
  const total = Math.max(1, Math.round((end - start) / DAY))
  const day = Math.min(total, Math.max(0, Math.round((now - start) / DAY)))
  return { value: t('scoping.cycle.dayOf', 'Day {day} of {total}', { day, total }), hint: range }
}
