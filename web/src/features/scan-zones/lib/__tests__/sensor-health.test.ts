import { describe, expect, it } from 'vitest'

import { isSensorHealthy, sensorHealthLabel } from '../sensor-health'

describe('scan zone sensor health', () => {
  it('routes to online and late sensors, as the API does (api RFC-035)', () => {
    expect(isSensorHealthy({ status: 'active', health: 'online' })).toBe(true)
    expect(isSensorHealthy({ status: 'active', health: 'late' })).toBe(true)
    expect(isSensorHealthy({ status: 'active', health: 'stale' })).toBe(false)
    expect(isSensorHealthy({ status: 'active', health: 'offline' })).toBe(false)
    expect(isSensorHealthy({ status: 'disabled', health: 'online' })).toBe(false)
  })

  it('labels every stored health', () => {
    expect(sensorHealthLabel({ status: 'active', health: 'late' })).toBe('Late')
    expect(sensorHealthLabel({ status: 'active', health: 'stale' })).toBe('Stale')
    expect(sensorHealthLabel({ status: 'active', health: 'unknown' })).toBe('Offline')
    expect(sensorHealthLabel({ status: 'revoked', health: 'online' })).toBe('Revoked')
  })
})
