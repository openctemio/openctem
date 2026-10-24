import { describe, expect, it } from 'vitest'
import { INTEGRATION_HEALTH, INTEGRATION_STATUSES, integrationHealth } from '../integration-health'
import en from '@/lib/i18n/dictionaries/en/integrationsHub.json'
import vi from '@/lib/i18n/dictionaries/vi/integrationsHub.json'

describe('integration health map', () => {
  it('maps every status to the 247 state', () => {
    expect(
      Object.fromEntries(INTEGRATION_STATUSES.map((s) => [s, INTEGRATION_HEALTH[s].state]))
    ).toEqual({
      connected: 'ok',
      pending: 'queued',
      error: 'down',
      expired: 'down',
      disabled: 'off',
      disconnected: 'unknown',
    })
  })
  it('has an en and vi label for every status', () => {
    for (const s of INTEGRATION_STATUSES) {
      const key = INTEGRATION_HEALTH[s].labelKey
      expect((en as Record<string, string>)[key]).toBeTruthy()
      expect((vi as Record<string, string>)[key]).toBeTruthy()
    }
  })
  it('reads an unknown status as not connected', () => {
    expect(integrationHealth('weird').state).toBe('unknown')
    expect(integrationHealth(undefined).state).toBe('unknown')
  })
})
