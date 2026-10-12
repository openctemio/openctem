import { describe, expect, it } from 'vitest'

import type { SensorActivityItem } from '@/lib/api/sensor-types'

import { describeSensorActivity, type Translate } from '../activity'

const t: Translate = (_key, fallback = '', vars) =>
  Object.entries(vars ?? {}).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), fallback)

function item(details: SensorActivityItem['details']): SensorActivityItem {
  return {
    id: 'e:1',
    at: '2026-10-02T12:00:00Z',
    category: 'status',
    type: 'heartbeat_recovered',
    source: 'sensor',
    summary: 'Heartbeats back after a 1m20s gap (was late)',
    details,
  }
}

describe('describeSensorActivity: heartbeat_recovered (RFC-035)', () => {
  it('names the step the sensor had reached and the gap', () => {
    const v = describeSensorActivity(item({ was: 'stale', gap_seconds: 95 }), t, 'en')
    expect(v.title).toBe('Heartbeats back on time (was stale)')
    expect(v.details).toEqual(['No heartbeat for 1m'])
    expect(v.tone).toBe('success')
  })

  it('defaults to late and leaves the gap out when it is unknown', () => {
    const v = describeSensorActivity(item({}), t, 'en')
    expect(v.title).toBe('Heartbeats back on time (was late)')
    expect(v.details).toEqual([])
  })
})
