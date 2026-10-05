import { describe, expect, it } from 'vitest'

import type { Sensor } from '@/lib/api/sensor-types'

import { EMPTY_FLEET_FILTERS, activeFilterCount, filterSensors, sensorPolicyOf } from '../fleet'

const channel = { latest: '', min: '' }

function sensor(id: string, state?: 'enforced' | 'absent' | 'paused'): Sensor {
  return {
    id,
    name: id,
    type: 'worker',
    status: 'active',
    local_policy: state ? { state, kill_switch: state === 'paused' } : undefined,
  } as unknown as Sensor
}

describe('local policy facet', () => {
  const fleet = [sensor('a', 'enforced'), sensor('b', 'absent'), sensor('c', 'paused'), sensor('d')]

  it('reads the reported state, unknown without a report', () => {
    expect(fleet.map(sensorPolicyOf)).toEqual(['enforced', 'absent', 'paused', 'unknown'])
  })

  it('filters "no local policy" (absent or never reported)', () => {
    const f = { ...EMPTY_FLEET_FILTERS, policies: ['absent' as const, 'unknown' as const] }
    expect(activeFilterCount(f)).toBe(2)
    expect(filterSensors(fleet, f, Date.now(), undefined, channel).map((s) => s.id)).toEqual([
      'b',
      'd',
    ])
  })

  it('no policy facet keeps every sensor', () => {
    expect(filterSensors(fleet, EMPTY_FLEET_FILTERS, Date.now(), undefined, channel)).toHaveLength(
      4
    )
  })
})
