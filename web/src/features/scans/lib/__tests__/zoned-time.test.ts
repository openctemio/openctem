import { describe, expect, it } from 'vitest'
import { instantToZonedWallTime, timeZoneOptions, zonedWallTimeToInstant } from '../zoned-time'

describe('zoned wall time', () => {
  it('converts a wall time in a zone to the instant and back', () => {
    const at = zonedWallTimeToInstant({ date: '2030-03-04', time: '22:30' }, 'Asia/Ho_Chi_Minh')
    expect(at?.toISOString()).toBe('2030-03-04T15:30:00.000Z')
    expect(instantToZonedWallTime('2030-03-04T15:30:00Z', 'Asia/Ho_Chi_Minh')).toEqual({
      date: '2030-03-04',
      time: '22:30',
    })
  })

  it('follows daylight saving time', () => {
    // New York: UTC-5 in winter, UTC-4 in summer.
    expect(
      zonedWallTimeToInstant(
        { date: '2030-01-15', time: '09:00' },
        'America/New_York'
      )?.toISOString()
    ).toBe('2030-01-15T14:00:00.000Z')
    expect(
      zonedWallTimeToInstant(
        { date: '2030-07-15', time: '09:00' },
        'America/New_York'
      )?.toISOString()
    ).toBe('2030-07-15T13:00:00.000Z')
  })

  it('refuses incomplete input and unknown zones', () => {
    expect(zonedWallTimeToInstant({ date: '', time: '09:00' }, 'UTC')).toBeNull()
    expect(zonedWallTimeToInstant({ date: '2030-01-15', time: '9' }, 'UTC')).toBeNull()
    expect(zonedWallTimeToInstant({ date: '2030-01-15', time: '09:00' }, 'Mars/Base')).toBeNull()
    expect(instantToZonedWallTime('not a date', 'UTC')).toBeNull()
  })

  it('lists UTC first and keeps the current zone', () => {
    const zones = timeZoneOptions('Etc/GMT+5')
    expect(zones[0]).toBe('UTC')
    expect(zones).toContain('Etc/GMT+5')
  })
})
