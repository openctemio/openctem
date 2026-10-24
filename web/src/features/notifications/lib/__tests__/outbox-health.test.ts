import { describe, expect, it } from 'vitest'
import { OUTBOX_HEALTH } from '../outbox-health'
import en from '@/lib/i18n/dictionaries/en/notificationChannels.json'
import vi from '@/lib/i18n/dictionaries/vi/notificationChannels.json'

describe('outbox health map', () => {
  it('maps every status to the 247 state', () => {
    expect(Object.fromEntries(Object.entries(OUTBOX_HEALTH).map(([k, v]) => [k, v.state]))).toEqual(
      {
        pending: 'queued',
        processing: 'run',
        completed: 'ok',
        failed: 'down',
        dead: 'down',
      }
    )
  })
  it('has en and vi labels for every status', () => {
    for (const v of Object.values(OUTBOX_HEALTH)) {
      expect((en as Record<string, string>)[v.labelKey]).toBeTruthy()
      expect((vi as Record<string, string>)[v.labelKey]).toBeTruthy()
    }
  })
})
