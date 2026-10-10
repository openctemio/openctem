import { describe, expect, it } from 'vitest'

import {
  formatOccurrence,
  formatRelativeFuture,
  schedulePreviewKey,
  schedulePreviewRequestFromConfig,
  schedulePreviewRequestFromForm,
} from '../schedule-preview'
import { DEFAULT_NEW_SCAN } from '../../types'

describe('schedulePreviewRequestFromConfig', () => {
  it('has no preview for a scan that runs only on demand', () => {
    expect(
      schedulePreviewRequestFromConfig({ schedule_type: 'manual', schedule_timezone: 'UTC' })
    ).toBeNull()
  })

  it('sends the stored schedule in its own timezone', () => {
    expect(
      schedulePreviewRequestFromConfig({
        schedule_type: 'weekly',
        schedule_day: 0,
        schedule_time: '02:30:00',
        schedule_timezone: 'Asia/Tokyo',
      })
    ).toEqual({
      schedule_type: 'weekly',
      schedule_day: 0, // Sunday is 0, not "no day"
      schedule_time: '02:30',
      timezone: 'Asia/Tokyo',
      count: 5,
    })
  })

  it('carries an RRULE verbatim and defaults the timezone to UTC', () => {
    expect(
      schedulePreviewRequestFromConfig(
        {
          schedule_type: 'rrule',
          schedule_rrule: 'FREQ=WEEKLY;BYDAY=MO;BYHOUR=9',
          schedule_timezone: '',
        },
        3
      )
    ).toEqual({
      schedule_type: 'rrule',
      schedule_rrule: 'FREQ=WEEKLY;BYDAY=MO;BYHOUR=9',
      timezone: 'UTC',
      count: 3,
    })
  })
})

describe('schedulePreviewKey', () => {
  it('ignores field order and differs when the schedule differs', () => {
    const a = schedulePreviewKey({
      schedule_type: 'daily',
      schedule_time: '02:00',
      timezone: 'UTC',
    })
    const b = schedulePreviewKey({
      timezone: 'UTC',
      schedule_time: '02:00',
      schedule_type: 'daily',
    })
    const c = schedulePreviewKey({
      schedule_type: 'daily',
      schedule_time: '03:00',
      timezone: 'UTC',
    })
    expect(a).toBe(b)
    expect(a).not.toBe(c)
  })
})

describe('formatOccurrence', () => {
  it('shows the instant in the scan timezone, not the viewer one', () => {
    const iso = '2026-10-12T09:00:00-04:00'
    expect(formatOccurrence(iso, 'America/New_York')).toContain('09:00')
    expect(formatOccurrence(iso, 'Asia/Tokyo')).toContain('22:00')
    expect(formatOccurrence(iso, 'UTC')).toContain('13:00')
  })

  it('falls back to UTC for an unknown zone and keeps a bad value as text', () => {
    expect(formatOccurrence('2026-10-12T13:00:00Z', 'Mars/Olympus')).toContain('13:00')
    expect(formatOccurrence('not a date', 'UTC')).toBe('not a date')
  })
})

describe('formatRelativeFuture', () => {
  const now = new Date('2026-10-04T00:00:00Z')
  it('picks a unit that reads naturally', () => {
    expect(formatRelativeFuture('2026-10-04T00:12:00Z', now)).toBe('in 12 minutes')
    expect(formatRelativeFuture('2026-10-04T05:00:00Z', now)).toBe('in 5 hours')
    expect(formatRelativeFuture('2026-10-07T00:00:00Z', now)).toBe('in 3 days')
  })
})

describe('schedulePreviewRequestFromForm', () => {
  it('previews exactly the schedule Create would save', () => {
    const form = {
      ...DEFAULT_NEW_SCAN,
      name: 'x',
      schedule: {
        runImmediately: false,
        frequency: 'weekly' as const,
        dayOfWeek: 3,
        time: '04:00',
      },
    }
    expect(schedulePreviewRequestFromForm(form)).toEqual({
      schedule_type: 'weekly',
      schedule_day: 3,
      schedule_time: '04:00',
      timezone: 'UTC',
      count: 5,
    })
    // Monthly runs on the first of the month, as formDataToCreateRequest sends.
    expect(
      schedulePreviewRequestFromForm({
        ...form,
        schedule: { ...form.schedule, frequency: 'monthly' },
      })
    ).toMatchObject({ schedule_type: 'monthly', schedule_day: 1 })
  })

  it('has no preview when the scan runs now', () => {
    expect(schedulePreviewRequestFromForm(DEFAULT_NEW_SCAN)).toBeNull()
  })

  it('previews a once schedule by its run', () => {
    const req = schedulePreviewRequestFromForm({
      ...DEFAULT_NEW_SCAN,
      schedule: {
        runImmediately: false,
        frequency: 'once',
        runAtDate: '2030-01-02',
        runAtTime: '09:00',
        timezone: 'UTC',
      },
    })
    expect(req).toMatchObject({
      schedule_type: 'once',
      run_at: '2030-01-02T09:00:00Z',
      timezone: 'UTC',
    })
  })
})
