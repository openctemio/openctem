import { describe, expect, it } from 'vitest'
import {
  durationUnit,
  formatBucket,
  formatCalendarDate,
  formatCount,
  formatDelta,
  formatDuration,
  formatPercent,
  formatRelativeTime,
} from './format-metric'

describe('format-metric', () => {
  it('groups counts and switches to compact notation from 10 000', () => {
    expect(formatCount(1748, 'en')).toBe('1,748')
    expect(formatCount(1748, 'vi')).toBe('1.748')
    expect(formatCount(12_400, 'en')).toBe('12.4K')
    expect(formatCount(null)).toBe('—')
    expect(formatCount(Number.NaN)).toBe('—')
  })

  it('writes percentages with one decimal below 10 % and whole numbers above', () => {
    expect(formatPercent(86.4, 'en')).toBe('86%')
    expect(formatPercent(7.46, 'en')).toBe('7.5%')
    expect(formatPercent(0, 'en')).toBe('0%')
    expect(formatPercent(null)).toBe('—')
  })

  it('writes durations in the largest sensible unit', () => {
    expect(durationUnit(0.5)).toBe('minute')
    expect(durationUnit(17)).toBe('hour')
    expect(durationUnit(132)).toBe('day')
    expect(formatDuration(0.5, 'en')).toBe('30 min')
    expect(formatDuration(17, 'en')).toBe('17 hr')
    expect(formatDuration(132, 'en')).toBe('5.5 days')
    expect(formatDuration(null)).toBe('—')
  })

  it('signs deltas and keeps the unit', () => {
    expect(formatDelta(12, 'count', 'en')).toBe('+12')
    expect(formatDelta(-3, 'percent', 'en')).toBe('−3')
    expect(formatDelta(0, 'count', 'en')).toBe('0')
    expect(formatDelta(-28.8, 'hours', 'en')).toBe('−29 hr')
    expect(formatDelta(-72, 'hours', 'en')).toBe('−3 days')
  })

  it('writes relative times in the locale', () => {
    const now = new Date('2026-10-21T10:00:00Z')
    expect(formatRelativeTime('2026-10-21T09:55:00Z', 'en', now)).toBe('5 minutes ago')
    expect(formatRelativeTime('2026-10-21T08:00:00Z', 'en', now)).toBe('2 hours ago')
    expect(formatRelativeTime('not a date', 'en', now)).toBe('—')
  })

  it('labels buckets in UTC', () => {
    expect(formatBucket('2026-10-05', 'day', 'en')).toBe('Oct 5')
    expect(formatBucket('2026-10-01', 'month', 'en')).toBe('Oct 2026')
  })
})

describe('formatCalendarDate', () => {
  it('formats a date in the locale, not the browser default', () => {
    const iso = '2026-10-23T10:00:00Z'
    expect(formatCalendarDate(iso, 'en')).toMatch(/Oct/)
    expect(formatCalendarDate(iso, 'vi')).not.toMatch(/Oct/)
    expect(formatCalendarDate(iso, 'vi')).toMatch(/2026/)
  })

  it('shows a dash for a missing or invalid date', () => {
    expect(formatCalendarDate(undefined)).toBe('—')
    expect(formatCalendarDate('not a date')).toBe('—')
  })
})
