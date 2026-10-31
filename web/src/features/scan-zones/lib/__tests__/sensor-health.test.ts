import { describe, expect, it } from 'vitest'

import { isSensorHealthy, sensorStateLabel, sensorStateTone } from '../sensor-health'

// A translator that returns the key, so the test checks which state word is picked.
const tr = (key: string) => key

describe('scan zone sensor health', () => {
  it('routes to online and late sensors, as the API does (api RFC-035)', () => {
    expect(isSensorHealthy({ status: 'active', health: 'online' })).toBe(true)
    expect(isSensorHealthy({ status: 'active', health: 'late' })).toBe(true)
    expect(isSensorHealthy({ status: 'active', health: 'stale' })).toBe(false)
    expect(isSensorHealthy({ status: 'active', health: 'offline' })).toBe(false)
    expect(isSensorHealthy({ status: 'disabled', health: 'online' })).toBe(false)
  })

  it('prefers the API state over the stored health', () => {
    const s = { status: 'active', health: 'online', state: 'late' } as const
    expect(sensorStateLabel(s, tr)).toBe('sensors.state.late.label')
    expect(sensorStateTone(s)).toBe('warning')
    const degraded = { status: 'active', health: 'error', state: 'degraded' } as const
    expect(sensorStateLabel(degraded, tr)).toBe('sensors.state.degraded.label')
  })

  it('names a never-connected sensor as the Sensors tab does, not Offline', () => {
    const s = { status: 'active', health: 'unknown', last_seen_at: undefined } as const
    expect(sensorStateLabel(s, tr)).toBe('sensors.state.never_connected.label')
    expect(sensorStateTone(s)).toBe('muted')
  })

  it('names disabled and revoked sensors by status', () => {
    expect(sensorStateLabel({ status: 'revoked', health: 'online' }, tr)).toBe(
      'sensors.state.revoked.label'
    )
    expect(sensorStateLabel({ status: 'disabled', health: 'online' }, tr)).toBe(
      'sensors.state.disabled.label'
    )
  })
})
